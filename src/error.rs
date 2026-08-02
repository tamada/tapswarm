//! エラー仕様 — 仕様書 §8
//!
//! 全てのエラーは統一形式で返す。`message` は開発者向けの英語とし、
//! エンドユーザーへの表示を想定しない。

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Debug, Clone)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub field: Option<&'static str>,
    /// 429 のときに `Retry-After` ヘッダへ載せる秒数
    pub retry_after: Option<u64>,
}

impl AppError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            field: None,
            retry_after: None,
        }
    }

    fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    // --- 400 ---

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn invalid_app_id() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_app_id",
            "app_id must match ^[A-Z2-7]{26}$",
        )
        .with_field("app_id")
    }

    pub fn invalid_location_id(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_location_id", message).with_field("location_id")
    }

    pub fn invalid_window(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_window", message).with_field("window")
    }

    pub fn too_many_locations(max: usize) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "too_many_locations",
            format!("location_ids must contain between 1 and {max} entries"),
        )
        .with_field("location_ids")
    }

    // --- 401 ---

    pub fn invalid_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "client_token is malformed or its signature does not verify",
        )
        .with_field("client_token")
    }

    pub fn expired_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "expired_token",
            "client_token has expired; obtain a new one from POST /api/v1/clients",
        )
        .with_field("client_token")
    }

    // --- 404 / 413 ---

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
    }

    pub fn payload_too_large(max_bytes: usize) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body must be at most {max_bytes} bytes"),
        )
    }

    // --- 429 ---

    pub fn rate_limited(retry_after: u64) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        );
        e.retry_after = Some(retry_after);
        e
    }

    pub fn location_limit_exceeded(max: u64) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "location_limit_exceeded",
            format!("this app_id has reached the limit of {max} locations"),
        )
    }

    // --- 5xx ---

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            message,
        )
    }

    /// Redis 停止時（§4.5）
    pub fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "a required backing store is unavailable",
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 500 は内部の詳細をクライアントに漏らさない。詳細はログにのみ残す。
        let (message, log_detail) = if self.status == StatusCode::INTERNAL_SERVER_ERROR {
            ("internal server error".to_string(), Some(self.message.clone()))
        } else {
            (self.message.clone(), None)
        };

        if let Some(detail) = log_detail {
            tracing::error!(code = self.code, detail = %detail, "internal error");
        }

        let body = Json(ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: &message,
                field: self.field,
            },
        });

        match self.retry_after {
            Some(secs) => (
                self.status,
                [(header::RETRY_AFTER, secs.to_string())],
                body,
            )
                .into_response(),
            None => (self.status, body).into_response(),
        }
    }
}

impl From<redis::RedisError> for AppError {
    fn from(e: redis::RedisError) -> Self {
        tracing::error!(error = %e, "redis error");
        AppError::unavailable()
    }
}
