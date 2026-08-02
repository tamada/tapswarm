//! Hot層（Redis）— 仕様書 §4.2, §6.1
//!
//! すべて通常の Redis コマンドで実装している（Lua スクリプトは使わない）。
//! 型検査もユニットテストも効かない Lua を持ち込むより、往復が1回増えても
//! Rust 側に置いたほうが保守できるという判断による。
//!
//! ## 時刻源（§4.4）
//!
//! APIサーバーは複数台構成になるためシステムクロックは使わず、`TIME` コマンドで
//! Redis から取得した値を「打刻の時刻」および「集計の基準時刻」として使う。
//! これによりインスタンス間のクロックスキューが `count` に影響しない。
//!
//! 例外はレート制限のウィンドウ計算で、ここだけシステムクロックを使う。
//! 数秒のズレが 60秒 / 3600秒 のウィンドウ境界に与える影響は無視できるうえ、
//! 集計値には一切関与しないため。
//!
//! ## キー設計
//!
//! `prefix = "<app_id>:<location_id>"` として以下を使う（§6.1）。
//!
//! | キー | 型 | 内容 |
//! |---|---|---|
//! | `ck:<prefix>` | ZSET | member=client_hash, score=UNIX秒 |
//! | `cd:<prefix>:<client_hash>` | STRING | クールダウンフラグ |
//! | `ip:<prefix>:<bucket>` | HLL | ip_hash |
//! | `na:<prefix>:<bucket>` | STRING | バケット内の打刻総数 |
//! | `nn:<prefix>:<bucket>` | STRING | うち新規クライアントの打刻数 |
//! | `tot:<prefix>` | STRING | Cold層への永続化判定用の累計 |
//! | `locs:<app_id>` | SET | 地点数の上限チェック用 |
//!
//! `location_id` は `:` を含みうるが、`bucket` と `client_hash` は必ず
//! コロンを含まない文字列なので、最後のコロンでの分解は一意に定まる。
//! したがってキーの衝突は起きない。

use std::time::{SystemTime, UNIX_EPOCH};

use redis::aio::ConnectionManager;

use crate::config::Config;
use crate::error::AppError;

/// シグナル集計のバケット粒度（秒）。
///
/// `window` の上限が24時間のため分単位のバケットではキー数が過大になる。
/// 5分粒度とすることで最大288バケットに抑える。**この粒度により `signals` には
/// 最大 ±5分の誤差が含まれる**（§6.1）。`count` 自体は ZSET から秒精度で
/// 求めるため影響を受けない。
const BUCKET_SEC: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckinOutcome {
    Accepted { total: i64 },
    Cooldown,
    LocationLimit,
}

#[derive(Debug, Clone, Copy)]
pub struct CheckinResult {
    pub outcome: CheckinOutcome,
    /// Redis から得た打刻時刻（UNIX秒）
    pub now: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct LocationStats {
    pub count: i64,
    pub unique_ip_count: i64,
    pub checkins: i64,
    pub new_checkins: i64,
}

impl LocationStats {
    /// ウィンドウ内の打刻のうち、発行から24時間以内のトークンによるものの割合（§5.5）
    pub fn new_client_ratio(&self) -> f64 {
        if self.checkins <= 0 {
            return 0.0;
        }
        let r = self.new_checkins as f64 / self.checkins as f64;
        (r * 1000.0).round() / 1000.0
    }
}

#[derive(Clone)]
pub struct Hot {
    conn: ConnectionManager,
}

impl Hot {
    pub async fn connect(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    pub async fn ping(&self) -> Result<(), redis::RedisError> {
        let mut c = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut c).await?;
        Ok(())
    }

    /// Redis を単一の時刻源として現在時刻を取る（§4.4）
    async fn redis_now(&self) -> Result<i64, AppError> {
        let mut c = self.conn.clone();
        let parts: Vec<i64> = redis::cmd("TIME").query_async(&mut c).await?;
        parts
            .first()
            .copied()
            .ok_or_else(|| AppError::internal("TIME returned no value"))
    }

    /// 打刻を記録する。
    ///
    /// 2往復で構成する。1往復目で「時刻」と「打刻してよいか」をまとめて取り、
    /// 2往復目で実際の書き込みを行う。1往復目で得た時刻を `ZADD` の score に
    /// 使うため、往復を分けても時刻源は Redis に統一されたままになる。
    pub async fn checkin(
        &self,
        cfg: &Config,
        app_id: &str,
        location_id: &str,
        client_hash_hex: &str,
        ip_hash_hex: &str,
        is_new: bool,
    ) -> Result<CheckinResult, AppError> {
        let prefix = format!("{app_id}:{location_id}");
        let locs_key = format!("locs:{app_id}");
        let cd_key = format!("cd:{prefix}:{client_hash_hex}");
        let ttl = cfg.key_ttl_sec();
        let mut c = self.conn.clone();

        // --- 1往復目: 時刻 + クールダウン判定 + 地点数の確認 ---
        //
        // SET NX 自体がアトミックなので、同時打刻でどちらか一方だけが通る
        // という判定は正しく行われる。
        let (time_parts, cooldown_acquired, loc_count, already_known): (
            Vec<i64>,
            Option<String>,
            i64,
            i64,
        ) = redis::pipe()
            .cmd("TIME")
            .cmd("SET")
            .arg(&cd_key)
            .arg(1)
            .arg("EX")
            .arg(cfg.cooldown_sec)
            .arg("NX")
            .cmd("SCARD")
            .arg(&locs_key)
            .cmd("SISMEMBER")
            .arg(&locs_key)
            .arg(location_id)
            .query_async(&mut c)
            .await?;

        let now = time_parts
            .first()
            .copied()
            .ok_or_else(|| AppError::internal("TIME returned no value"))?;

        // 60秒以内の再打刻は破棄する（§5.4.1）。
        // これが冪等性も担保するため Idempotency-Key は不要。
        if cooldown_acquired.is_none() {
            return Ok(CheckinResult {
                outcome: CheckinOutcome::Cooldown,
                now,
            });
        }

        // app_id あたりの地点数上限（§5.2）。
        // 確認と登録が別往復になるため同時打刻で数件超過しうるが、
        // これはスパム防止用の緩い上限であり実害はない。
        if already_known == 0 && loc_count >= cfg.max_locations_per_app as i64 {
            return Ok(CheckinResult {
                outcome: CheckinOutcome::LocationLimit,
                now,
            });
        }

        // --- 2往復目: 書き込み ---
        let bucket = (now / BUCKET_SEC) * BUCKET_SEC;
        let ck = format!("ck:{prefix}");
        let ipk = format!("ip:{prefix}:{bucket}");
        let nak = format!("na:{prefix}:{bucket}");
        let nnk = format!("nn:{prefix}:{bucket}");
        let totk = format!("tot:{prefix}");

        let mut pipe = redis::pipe();
        pipe.cmd("SADD").arg(&locs_key).arg(location_id).ignore();
        pipe.cmd("EXPIRE").arg(&locs_key).arg(ttl).ignore();

        // score の上書きは「滞在の延長」であり正しい挙動（§5.4.2）
        pipe.cmd("ZADD").arg(&ck).arg(now).arg(client_hash_hex).ignore();
        // ウィンドウ上限より古いメンバを削除し ZSET の肥大化を防ぐ
        pipe.cmd("ZREMRANGEBYSCORE")
            .arg(&ck)
            .arg("-inf")
            .arg(now - cfg.window_max_sec() as i64)
            .ignore();
        pipe.cmd("EXPIRE").arg(&ck).arg(ttl).ignore();

        // シグナル用カウンタ（§5.5）
        pipe.cmd("PFADD").arg(&ipk).arg(ip_hash_hex).ignore();
        pipe.cmd("EXPIRE").arg(&ipk).arg(ttl).ignore();
        pipe.cmd("INCR").arg(&nak).ignore();
        pipe.cmd("EXPIRE").arg(&nak).arg(ttl).ignore();
        if is_new {
            pipe.cmd("INCR").arg(&nnk).ignore();
            pipe.cmd("EXPIRE").arg(&nnk).arg(ttl).ignore();
        }

        // Cold層への永続化判定用の累計（§5.2）。これだけ値が要る。
        pipe.cmd("INCR").arg(&totk);
        pipe.cmd("EXPIRE").arg(&totk).arg(ttl).ignore();

        let out: Vec<i64> = pipe.query_async(&mut c).await?;
        let total = out.first().copied().unwrap_or(0);

        Ok(CheckinResult {
            outcome: CheckinOutcome::Accepted { total },
            now,
        })
    }

    /// 複数地点の混雑度をまとめて取得する（§7.3, §7.4）。
    ///
    /// 戻り値は `(as_of, 地点ごとの集計)`。集計は `location_ids` の指定順と一致する。
    ///
    /// 地点ごとに 4 コマンド（`ZCOUNT` / `PFCOUNT` / `MGET` ×2）を1本のパイプラインで
    /// 送る。バケット数は `window` に比例するため、`window=1440` かつ100地点の
    /// 一括取得ではキー名の転送量が大きくなる。実用域（`window` 5〜60分）では
    /// 1地点あたり最大13キー程度に収まる。
    pub async fn crowd_levels(
        &self,
        app_id: &str,
        location_ids: &[&str],
        window_min: u32,
    ) -> Result<(i64, Vec<LocationStats>), AppError> {
        let now = self.redis_now().await?;
        let from = now - window_min as i64 * 60;

        let first_bucket = (from / BUCKET_SEC) * BUCKET_SEC;
        let last_bucket = (now / BUCKET_SEC) * BUCKET_SEC;
        let buckets: Vec<i64> = (first_bucket..=last_bucket)
            .step_by(BUCKET_SEC as usize)
            .collect();

        let mut pipe = redis::pipe();
        for loc in location_ids {
            let prefix = format!("{app_id}:{loc}");

            // count はウィンドウ境界を秒精度で評価する
            pipe.cmd("ZCOUNT")
                .arg(format!("ck:{prefix}"))
                .arg(from)
                .arg("+inf");

            pipe.cmd("PFCOUNT");
            for b in &buckets {
                pipe.arg(format!("ip:{prefix}:{b}"));
            }
            pipe.cmd("MGET");
            for b in &buckets {
                pipe.arg(format!("na:{prefix}:{b}"));
            }
            pipe.cmd("MGET");
            for b in &buckets {
                pipe.arg(format!("nn:{prefix}:{b}"));
            }
        }

        let mut c = self.conn.clone();
        let raw: Vec<redis::Value> = pipe.query_async(&mut c).await?;

        let expected = location_ids.len() * 4;
        if raw.len() != expected {
            return Err(AppError::internal(format!(
                "pipeline returned {} values, expected {expected}",
                raw.len()
            )));
        }

        let mut stats = Vec::with_capacity(location_ids.len());
        for i in 0..location_ids.len() {
            let base = i * 4;
            let count: i64 = conv(&raw[base])?;
            let unique_ip_count: i64 = conv(&raw[base + 1])?;
            let na: Vec<Option<i64>> = conv(&raw[base + 2])?;
            let nn: Vec<Option<i64>> = conv(&raw[base + 3])?;

            stats.push(LocationStats {
                count,
                unique_ip_count,
                checkins: na.into_iter().flatten().sum(),
                new_checkins: nn.into_iter().flatten().sum(),
            });
        }

        Ok((now, stats))
    }

    /// 固定ウィンドウ方式のレート制限（§5.3.2, §5.4.3）。
    ///
    /// ウィンドウ開始時刻をキーに埋め込むことで、`INCR` + `EXPIRE` の
    /// 2コマンドだけで済み、読み取り後に書き戻す競合が生じない。
    ///
    /// 境界をまたぐと短時間に最大2倍通るという固定ウィンドウ方式の弱点はあるが、
    /// 目的が「偽装のコストを上げる」ことであって厳密な上限の強制ではないため
    /// 許容する（§5.1）。
    pub async fn consume_quota(
        &self,
        kind: &str,
        subject: &str,
        limit: i64,
        window_sec: i64,
    ) -> Result<(), AppError> {
        let now = system_now();
        let window_start = (now / window_sec) * window_sec;
        let key = format!("rl:{kind}:{subject}:{window_start}");

        let mut c = self.conn.clone();
        let out: Vec<i64> = redis::pipe()
            .cmd("INCR")
            .arg(&key)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(window_sec + 60)
            .ignore()
            .query_async(&mut c)
            .await?;

        let used = out.first().copied().unwrap_or(0);
        if used > limit {
            let retry_after = (window_start + window_sec - now).max(1) as u64;
            return Err(AppError::rate_limited(retry_after));
        }
        Ok(())
    }

    /// 自身のデータを削除する（§7.5）。削除した地点数を返す。
    pub async fn forget_client(
        &self,
        app_id: &str,
        client_hash_hex: &str,
    ) -> Result<usize, AppError> {
        let mut c = self.conn.clone();

        let locations: Vec<String> = redis::cmd("SMEMBERS")
            .arg(format!("locs:{app_id}"))
            .query_async(&mut c)
            .await?;

        if locations.is_empty() {
            return Ok(0);
        }

        // 1アプリあたり最大10,000地点になりうるため、逐次実行すると削除に
        // 数十秒かかる。パイプラインで1往復にまとめる。
        let mut pipe = redis::pipe();
        for loc in &locations {
            pipe.cmd("ZREM")
                .arg(format!("ck:{app_id}:{loc}"))
                .arg(client_hash_hex);
            pipe.cmd("DEL")
                .arg(format!("cd:{app_id}:{loc}:{client_hash_hex}"))
                .ignore();
        }

        let removed: Vec<i64> = pipe.query_async(&mut c).await?;
        Ok(removed.iter().filter(|n| **n > 0).count())
    }
}

fn conv<T: redis::FromRedisValue>(v: &redis::Value) -> Result<T, AppError> {
    redis::from_redis_value(v).map_err(AppError::from)
}

/// レート制限のウィンドウ計算にのみ使う壁時計。集計には関与しない。
fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_ratio_is_rounded_and_safe_at_zero() {
        let s = LocationStats {
            count: 5,
            unique_ip_count: 2,
            checkins: 10,
            new_checkins: 1,
        };
        assert_eq!(s.new_client_ratio(), 0.1);

        let empty = LocationStats {
            count: 0,
            unique_ip_count: 0,
            checkins: 0,
            new_checkins: 0,
        };
        assert_eq!(empty.new_client_ratio(), 0.0);
    }

    #[test]
    fn buckets_cover_the_whole_window() {
        // window=15分 なら 5分バケットが 4 本（境界を跨ぐため n+1 本になる）
        let now = 1_800_000_123i64;
        let from = now - 15 * 60;
        let first = (from / BUCKET_SEC) * BUCKET_SEC;
        let last = (now / BUCKET_SEC) * BUCKET_SEC;
        let buckets: Vec<i64> = (first..=last).step_by(BUCKET_SEC as usize).collect();

        assert_eq!(buckets.len(), 4);
        assert!(*buckets.first().unwrap() <= from);
        assert!(*buckets.last().unwrap() <= now);
    }

    #[test]
    fn a_one_minute_window_still_yields_at_least_one_bucket() {
        let now = 1_800_000_000i64; // ちょうどバケット境界
        let from = now - 60;
        let first = (from / BUCKET_SEC) * BUCKET_SEC;
        let last = (now / BUCKET_SEC) * BUCKET_SEC;
        let buckets: Vec<i64> = (first..=last).step_by(BUCKET_SEC as usize).collect();
        assert!(!buckets.is_empty());
    }
}
