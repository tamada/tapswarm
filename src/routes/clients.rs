//! クライアントトークンの発行と削除 — 仕様書 §7.1, §7.5

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::cold;
use crate::error::AppError;
use crate::routes::{json_body, unix_now};
use crate::state::{client_ip, AppState};
use crate::token::{hex, ip_hash, AppId};

use super::crowd::as_of;

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    app_id: String,
}

#[derive(Debug, Serialize)]
struct IssueResponse {
    client_token: String,
    expires_at: String,
}

/// `POST /api/v1/clients`
///
/// 水増しコストをここに集約する（§5.3.2）。打刻そのものに厳しいIP制限をかけると
/// 共有Wi-Fi や CGNAT 配下の正規ユーザーを巻き添えにするが、トークン取得は
/// 端末の生涯でほぼ1回であるため、クォータを消費するのは新規端末だけで済む。
pub async fn issue(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<IssueRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    let Json(req) = json_body(body)?;
    let app_id = AppId::parse(&req.app_id)?;

    let ip = client_ip(&headers, peer, st.cfg.trusted_proxy_hops);
    let ip_hex = hex(&ip_hash(&st.cfg.hash_key, &ip));

    // per-IP クォータ: 既定 60個/時
    st.hot
        .consume_quota("cl", &ip_hex, st.cfg.client_issue_quota_per_hour, 3600)
        .await?;

    let (token, expires_at) = st.issuer.issue(&app_id, unix_now());

    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            client_token: token,
            expires_at: as_of(expires_at as i64),
        }),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct ForgetRequest {
    app_id: String,
    client_token: String,
}

/// `DELETE /api/v1/clients/me`
///
/// 認証がないため、**トークンの提示そのものが本人性を示す唯一の手段**である
/// （§9.4）。トークンを持つ者だけが自分のデータを消せる。
pub async fn forget(
    State(st): State<AppState>,
    body: Result<Json<ForgetRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    let Json(req) = json_body(body)?;
    let app_id = AppId::parse(&req.app_id)?;

    let client = st
        .issuer
        .verify(&req.client_token, &app_id, unix_now())?;
    let client_h = client.client_hash(&st.cfg.hash_key);
    let client_hex = hex(&client_h);
    let app_id_str = app_id.to_string();

    let hot_removed = st.hot.forget_client(&app_id_str, &client_hex).await?;

    // Cold層の削除は同期で行う。非同期にすると「消えた」と応答した直後に
    // 残っている状態が生じ、削除要求への回答として成立しない。
    let cold_removed = cold::forget_client(&st.pool, &app_id_str, &client_h)
        .await
        .map_err(|e| AppError::internal(format!("cold delete failed: {e}")))?;

    tracing::info!(
        app_id = %app_id_str,
        client_hash = %client_hex,
        hot_locations = hot_removed,
        cold_rows = cold_removed,
        "client data erased"
    );

    Ok(StatusCode::NO_CONTENT.into_response())
}
