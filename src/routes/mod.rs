//! ルーティング — 仕様書 §7

pub mod checkin;
pub mod clients;
pub mod crowd;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

use crate::error::AppError;
use crate::state::AppState;

/// リクエストボディの上限（§8.3）
const MAX_BODY_BYTES: usize = 4 * 1024;

pub fn router(state: AppState) -> Router {
    // Web サイトからの直接呼び出しを想定するため CORS を有効にする（§8.4）。
    // 資格情報は一切使わないため allow_credentials は付けない。
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/api/v1/clients", post(clients::issue))
        .route("/api/v1/clients/me", delete(clients::forget))
        .route("/api/v1/checkin", post(checkin::post))
        .route("/api/v1/crowd_level", get(crowd::get_one))
        .route("/api/v1/crowd_levels", get(crowd::get_many))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
        .fallback(not_found)
        .layer(cors)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// JSON ボディの拒否を仕様書 §8.1 の形式に変換する。
///
/// axum の既定の拒否応答はプレーンテキストなので、そのまま返すと
/// エラー形式が統一されない。
pub fn json_body<T>(r: Result<Json<T>, JsonRejection>) -> Result<Json<T>, AppError> {
    r.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AppError::payload_too_large(MAX_BODY_BYTES)
        } else {
            AppError::invalid_request(e.body_text())
        }
    })
}

/// 壁時計。
///
/// トークンの発行・検証にのみ使う。TTL が30日なので秒単位のクロックスキューは
/// 問題にならない。**集計の時刻源は Redis の `TIME` に統一されている**（§4.4）ため、
/// インスタンス間のズレが `count` に影響することはない。
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ヘルスチェック — §7.6
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Status {
    status: &'static str,
}

/// Liveness: プロセスが生きていれば 200。外部依存を確認しない。
async fn healthz() -> Response {
    Json(Status { status: "ok" }).into_response()
}

/// Readiness: Redis への疎通を確認する。Redis が落ちていれば打刻も取得も
/// できないため（§4.5）、ロードバランサから外すべき状態にあたる。
async fn readyz(State(st): State<AppState>) -> Result<Response, AppError> {
    st.hot.ping().await.map_err(|e| {
        tracing::warn!(error = %e, "readiness check failed");
        AppError::unavailable()
    })?;
    Ok(Json(Status { status: "ready" }).into_response())
}

#[derive(Serialize)]
struct Version {
    name: &'static str,
    version: &'static str,
    spec: &'static str,
}

async fn version() -> Response {
    Json(Version {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        spec: "0.2",
    })
    .into_response()
}

async fn not_found() -> AppError {
    AppError::not_found()
}
