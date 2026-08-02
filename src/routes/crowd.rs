//! 混雑度の取得 — 仕様書 §7.3, §7.4

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::error::AppError;
use crate::hot::LocationStats;
use crate::state::AppState;
use crate::token::AppId;
use crate::validate;

#[derive(Debug, Serialize)]
pub struct Signals {
    /// ウィンドウ内に打刻したユニークな IP 数（HyperLogLog による近似、5分粒度）
    pub unique_ip_count: i64,
    /// 発行から24時間以内のトークンによる打刻の割合
    pub new_client_ratio: f64,
}

/// 地点1件ぶんの集計結果。
///
/// サーバーは混雑の判定も真偽の判定も行わない。`signals` は判断材料であり、
/// 意味付けはドメイン知識を持つクライアントが行う（§2.2, §2.3）。
#[derive(Debug, Serialize)]
pub struct CrowdLevel {
    pub location_id: String,
    pub count: Option<i64>,
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signals: Option<Signals>,
}

impl CrowdLevel {
    /// k-匿名性を適用して整形する（§5.6）。
    ///
    /// `count < k` の場合、その場所に特定個人がいることが露見しうるため、
    /// `count` と `signals` の双方を伏せる。`signals` を残すと `unique_ip_count`
    /// から人数が推定できてしまうため、両方を伏せる必要がある。
    pub fn shape(location_id: &str, stats: LocationStats, k: u64) -> Self {
        if (stats.count as u64) < k {
            return Self {
                location_id: location_id.to_string(),
                count: None,
                suppressed: true,
                signals: None,
            };
        }
        Self {
            location_id: location_id.to_string(),
            count: Some(stats.count),
            suppressed: false,
            signals: Some(Signals {
                unique_ip_count: stats.unique_ip_count,
                new_client_ratio: stats.new_client_ratio(),
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct SingleResponse {
    location_id: String,
    count: Option<i64>,
    window: u32,
    as_of: String,
    suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signals: Option<Signals>,
}

#[derive(Debug, Serialize)]
struct BulkResponse {
    window: u32,
    as_of: String,
    results: Vec<CrowdLevel>,
}

/// 集計の基準時刻。クライアントがキャッシュした値の鮮度を判断できるようにする。
pub fn as_of(unix_secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix_secs, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn require<'a>(
    q: &'a HashMap<String, String>,
    key: &'static str,
) -> Result<&'a str, AppError> {
    q.get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::invalid_request(format!("missing required parameter: {key}")))
}

/// 多数のクライアントからのポーリングを前提とするため短期キャッシュを許す（§7.3）
fn with_cache_headers(body: impl IntoResponse) -> Response {
    ([(header::CACHE_CONTROL, "max-age=10")], body).into_response()
}

/// `GET /api/v1/crowd_level`
pub async fn get_one(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let app_id = AppId::parse(require(&q, "app_id")?)?;
    let location_id = validate::location_id(require(&q, "location_id")?)?;
    let window = validate::window(require(&q, "window")?, st.cfg.max_window_min)?;

    let (now, stats) = st
        .hot
        .crowd_levels(&app_id.to_string(), &[location_id], window)
        .await?;

    let shaped = CrowdLevel::shape(location_id, stats[0], st.cfg.k_anonymity);

    Ok(with_cache_headers(Json(SingleResponse {
        location_id: shaped.location_id,
        count: shaped.count,
        window,
        as_of: as_of(now),
        suppressed: shaped.suppressed,
        signals: shaped.signals,
    })))
}

/// `GET /api/v1/crowd_levels`
///
/// 地図上に複数地点を表示する用途で、地点ごとにリクエストを発行させないためのもの。
pub async fn get_many(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let app_id = AppId::parse(require(&q, "app_id")?)?;
    let location_ids = validate::location_ids(require(&q, "location_ids")?)?;
    let window = validate::window(require(&q, "window")?, st.cfg.max_window_min)?;

    let (now, stats) = st
        .hot
        .crowd_levels(&app_id.to_string(), &location_ids, window)
        .await?;

    // 結果の順序は location_ids の指定順と一致させる（§7.4）
    let results = location_ids
        .iter()
        .zip(stats)
        .map(|(loc, s)| CrowdLevel::shape(loc, s, st.cfg.k_anonymity))
        .collect();

    Ok(with_cache_headers(Json(BulkResponse {
        window,
        as_of: as_of(now),
        results,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(count: i64) -> LocationStats {
        LocationStats {
            count,
            unique_ip_count: 2,
            checkins: 10,
            new_checkins: 1,
        }
    }

    #[test]
    fn small_counts_are_suppressed_entirely() {
        // §5.6: count と signals の双方を伏せる。
        // signals だけ残すと unique_ip_count から人数が推定できてしまう。
        for n in 0..3 {
            let c = CrowdLevel::shape("shop-001", stats(n), 3);
            assert!(c.suppressed);
            assert!(c.count.is_none());
            assert!(c.signals.is_none(), "signals must be hidden for count={n}");
        }
    }

    #[test]
    fn counts_at_or_above_k_are_disclosed() {
        let c = CrowdLevel::shape("shop-001", stats(3), 3);
        assert!(!c.suppressed);
        assert_eq!(c.count, Some(3));
        assert_eq!(c.signals.unwrap().unique_ip_count, 2);
    }

    #[test]
    fn new_client_ratio_is_rounded() {
        assert_eq!(stats(5).new_client_ratio(), 0.1);
        let zero = LocationStats {
            count: 0,
            unique_ip_count: 0,
            checkins: 0,
            new_checkins: 0,
        };
        assert_eq!(zero.new_client_ratio(), 0.0);
    }

    #[test]
    fn as_of_is_rfc3339_utc() {
        assert_eq!(as_of(1_800_000_000), "2027-01-15T08:00:00Z");
    }
}
