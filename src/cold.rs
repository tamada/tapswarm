//! Cold層（PostgreSQL）— 仕様書 §4.3, §6.3
//!
//! APIレスポンスをブロックしないよう非同期で書き込む。
//!
//! **データロスを許容する設計である。** キューが溢れた場合およびプロセス再起動時に
//! 打刻ログを失うが、Cold層は統計分析用であり `count` の正確性には影響しない。
//! ドロップ件数はメトリクスとして必ず記録する（§4.3）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::mpsc;

/// 1回の INSERT でまとめる最大件数
const BATCH_SIZE: usize = 100;
/// 端数を書き出すまでの待ち時間
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct CheckinRecord {
    pub app_id: String,
    pub location_id: String,
    pub client_hash: Vec<u8>,
    /// 生のIPではなくハッシュ値（§9.3）。
    /// 列は NULL 許容だが、打刻時には必ずIPが決まるため常に値が入る。
    pub ip_hash: Vec<u8>,
    pub is_new_client: bool,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct ColdMetrics {
    /// キュー溢れで捨てた件数
    pub dropped: AtomicU64,
    /// 書き込みに成功した件数
    pub written: AtomicU64,
    /// INSERT 失敗で失った件数
    pub failed: AtomicU64,
}

#[derive(Clone)]
pub struct ColdWriter {
    tx: mpsc::Sender<CheckinRecord>,
    pub metrics: Arc<ColdMetrics>,
}

impl ColdWriter {
    /// キューへ積む。**満杯なら捨てる**（呼び出し側をブロックしない）。
    pub fn enqueue(&self, record: CheckinRecord) {
        if self.tx.try_send(record).is_err() {
            let n = self.metrics.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // 溢れている間ログが洪水になるため、間引いて出す
            if n == 1 || n % 1000 == 0 {
                tracing::warn!(dropped_total = n, "cold layer queue is full; dropping checkin");
            }
        }
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.metrics.written.load(Ordering::Relaxed),
            self.metrics.dropped.load(Ordering::Relaxed),
            self.metrics.failed.load(Ordering::Relaxed),
        )
    }
}

/// バウンデッドキューとバックグラウンドの書き込みタスクを起動する。
pub fn spawn(pool: PgPool, capacity: usize) -> ColdWriter {
    let (tx, rx) = mpsc::channel(capacity);
    let metrics = Arc::new(ColdMetrics::default());
    tokio::spawn(writer_loop(pool, rx, Arc::clone(&metrics)));
    ColdWriter { tx, metrics }
}

async fn writer_loop(
    pool: PgPool,
    mut rx: mpsc::Receiver<CheckinRecord>,
    metrics: Arc<ColdMetrics>,
) {
    let mut batch: Vec<CheckinRecord> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // 1件目はブロッキングで待つ（アイドル時に空回りしない）
        let first = match rx.recv().await {
            Some(r) => r,
            None => break, // 送信側が全て drop された
        };
        batch.push(first);

        // BATCH_SIZE 件たまるか FLUSH_INTERVAL 経過するまで集める
        let deadline = tokio::time::Instant::now() + FLUSH_INTERVAL;
        while batch.len() < BATCH_SIZE {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(r)) => batch.push(r),
                Ok(None) => break,
                Err(_) => break, // タイムアウト
            }
        }

        flush(&pool, &batch, &metrics).await;
        batch.clear();
    }

    if !batch.is_empty() {
        flush(&pool, &batch, &metrics).await;
    }
    tracing::info!("cold layer writer stopped");
}

async fn flush(pool: &PgPool, batch: &[CheckinRecord], metrics: &ColdMetrics) {
    if batch.is_empty() {
        return;
    }

    let n = batch.len();
    let mut app_ids = Vec::with_capacity(n);
    let mut location_ids = Vec::with_capacity(n);
    let mut client_hashes = Vec::with_capacity(n);
    let mut ip_hashes = Vec::with_capacity(n);
    let mut is_new = Vec::with_capacity(n);
    let mut occurred = Vec::with_capacity(n);

    for r in batch {
        app_ids.push(r.app_id.clone());
        location_ids.push(r.location_id.clone());
        client_hashes.push(r.client_hash.clone());
        ip_hashes.push(r.ip_hash.clone());
        is_new.push(r.is_new_client);
        occurred.push(r.occurred_at);
    }

    let result = sqlx::query(
        r#"
        INSERT INTO checkins (app_id, location_id, client_hash, ip_hash, is_new_client, occurred_at)
        SELECT * FROM UNNEST(
            $1::text[], $2::text[], $3::bytea[], $4::bytea[], $5::bool[], $6::timestamptz[]
        )
        "#,
    )
    .bind(app_ids)
    .bind(location_ids)
    .bind(client_hashes)
    .bind(ip_hashes)
    .bind(is_new)
    .bind(occurred)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            metrics.written.fetch_add(n as u64, Ordering::Relaxed);
        }
        Err(e) => {
            metrics.failed.fetch_add(n as u64, Ordering::Relaxed);
            tracing::error!(error = %e, batch = n, "cold layer insert failed; batch discarded");
        }
    }
}

/// 自身のデータを削除する（§7.5, §9.4）。削除件数を返す。
pub async fn forget_client(
    pool: &PgPool,
    app_id: &str,
    client_hash: &[u8],
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query("DELETE FROM checkins WHERE app_id = $1 AND client_hash = $2")
        .bind(app_id)
        .bind(client_hash)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// 保持期間を過ぎたログを削除する（§9.1）。
///
/// **PoC 上の逸脱:** 仕様では月次パーティションの `DROP` としているが、本 PoC は
/// DEFAULT パーティションのみを作成しており月次パーティションを払い出していないため、
/// `DELETE` で代用している。本番投入前にパーティション運用へ切り替えること。
pub fn spawn_retention_task(pool: PgPool, retention_days: u32) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(6 * 3600));
        loop {
            ticker.tick().await;
            let sql = format!(
                "DELETE FROM checkins WHERE occurred_at < now() - interval '{retention_days} days'"
            );
            match sqlx::query(&sql).execute(&pool).await {
                Ok(r) if r.rows_affected() > 0 => {
                    tracing::info!(deleted = r.rows_affected(), "retention sweep completed");
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "retention sweep failed"),
            }
        }
    });
}
