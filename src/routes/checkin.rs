//! 打刻（チェックイン）— 仕様書 §7.2

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cold::CheckinRecord;
use crate::error::AppError;
use crate::hot::CheckinOutcome;
use crate::routes::{json_body, unix_now};
use crate::state::{client_ip, AppState};
use crate::token::{hex, ip_hash, AppId};
use crate::validate;

use super::crowd::{as_of, CrowdLevel, Signals};

#[derive(Debug, Deserialize)]
pub struct CheckinRequest {
    app_id: String,
    location_id: String,
    /// §5.3 でサーバー発行のトークンに置き換わった。v0.1 の自称 `client_id` は受け付けない。
    client_token: String,
}

#[derive(Debug, Serialize)]
struct CheckinResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crowd_level: Option<InlineCrowdLevel>,
}

/// `?with_count=1` 指定時に同梱する集計結果（往復を1回節約するためのオプション）
#[derive(Debug, Serialize)]
struct InlineCrowdLevel {
    location_id: String,
    count: Option<i64>,
    window: u32,
    as_of: String,
    suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signals: Option<Signals>,
}

/// `POST /api/v1/checkin`
pub async fn post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    body: Result<Json<CheckinRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    let Json(req) = json_body(body)?;

    let app_id = AppId::parse(&req.app_id)?;
    let location_id = validate::location_id(&req.location_id)?.to_string();

    // 生のIPは保存しない（§9.3）。レート制限のキーにもハッシュを使う。
    let ip = client_ip(&headers, peer, st.cfg.trusted_proxy_hops);
    let ip_h = ip_hash(&st.cfg.hash_key, &ip);
    let ip_hex = hex(&ip_h);

    // IP単位のレート制限。これは水増し対策ではなく DoS 対策であり、
    // 共有Wi-Fi / CGNAT を壊さないよう緩く設定する（§5.4.3）。
    st.hot
        .consume_quota("ci", &ip_hex, st.cfg.checkin_rate_limit_per_min, 60)
        .await?;

    // 署名検証。自称 client_id はここで確実に弾かれる（§5.3.3）。
    let now = unix_now();
    let client = st.issuer.verify(&req.client_token, &app_id, now)?;
    let client_h = client.client_hash(&st.cfg.hash_key);
    let client_hex = hex(&client_h);
    let is_new = client.is_new(now);

    // client_hash はストレージに保存する値そのもの（生トークンではない）なので、
    // 診断目的で出力してよい。§9.2 が禁じているのは生の client_token。
    tracing::debug!(
        location_id = %location_id,
        client_hash = %client_hex,
        "checkin"
    );

    let app_id_str = app_id.to_string();
    let result = st
        .hot
        .checkin(
            &st.cfg,
            &app_id_str,
            &location_id,
            &client_hex,
            &ip_hex,
            is_new,
        )
        .await?;

    let (accepted, reason) = match result.outcome {
        CheckinOutcome::Accepted { total } => {
            // 試行錯誤で作られたゴミを永続化しないため、一定回数を超えた
            // location のみ Cold層へ送る（§5.2）
            if total > st.cfg.cold_persist_min_checkins {
                st.cold.enqueue(CheckinRecord {
                    app_id: app_id_str.clone(),
                    location_id: location_id.clone(),
                    client_hash: client_h,
                    ip_hash: ip_h,
                    is_new_client: is_new,
                    occurred_at: DateTime::<Utc>::from_timestamp(result.now, 0)
                        .unwrap_or_else(Utc::now),
                });
            }
            (true, None)
        }
        // 60秒以内の再打刻。リトライさせる意味がないため 202 で返す（§7.2）。
        CheckinOutcome::Cooldown => (false, Some("cooldown")),
        // 地点数上限は開発者が対処すべき異常なので 429 で明示する（§8.2）。
        CheckinOutcome::LocationLimit => {
            return Err(AppError::location_limit_exceeded(
                st.cfg.max_locations_per_app,
            ))
        }
    };

    let crowd_level = match with_count(&q, st.cfg.max_window_min)? {
        Some(window) => {
            let (as_of_ts, stats) = st
                .hot
                .crowd_levels(&app_id_str, &[location_id.as_str()], window)
                .await?;
            let shaped = CrowdLevel::shape(&location_id, stats[0], st.cfg.k_anonymity);
            Some(InlineCrowdLevel {
                location_id: shaped.location_id,
                count: shaped.count,
                window,
                as_of: as_of(as_of_ts),
                suppressed: shaped.suppressed,
                signals: shaped.signals,
            })
        }
        None => None,
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(CheckinResponse {
            accepted,
            reason,
            crowd_level,
        }),
    )
        .into_response())
}

/// `?with_count=1&window=15` が指定されていれば `window` を返す。
fn with_count(q: &HashMap<String, String>, max_window_min: u32) -> Result<Option<u32>, AppError> {
    let requested = matches!(
        q.get("with_count").map(String::as_str),
        Some("1") | Some("true")
    );
    if !requested {
        return Ok(None);
    }
    let raw = q.get("window").map(String::as_str).ok_or_else(|| {
        AppError::invalid_window("window is required when with_count is set")
    })?;
    Ok(Some(validate::window(raw, max_window_min)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn with_count_is_opt_in() {
        assert_eq!(with_count(&q(&[]), 1440).unwrap(), None);
        assert_eq!(with_count(&q(&[("with_count", "0")]), 1440).unwrap(), None);
    }

    #[test]
    fn with_count_requires_a_valid_window() {
        assert!(with_count(&q(&[("with_count", "1")]), 1440).is_err());
        assert!(with_count(&q(&[("with_count", "1"), ("window", "0")]), 1440).is_err());
        assert_eq!(
            with_count(&q(&[("with_count", "1"), ("window", "15")]), 1440).unwrap(),
            Some(15)
        );
    }
}
