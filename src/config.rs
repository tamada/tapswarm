//! 設定 — 仕様書 §11
//!
//! すべて環境変数で与える。設定ファイルは必須にしない。

use std::env;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub redis_url: String,
    pub database_url: String,

    /// トークン署名鍵（§5.3.1）。アプリ開発者には見せない。
    pub signing_key: Vec<u8>,
    /// client_hash / ip_hash 用の鍵（§5.3.4, §9.3）
    pub hash_key: Vec<u8>,

    pub k_anonymity: u64,
    pub token_ttl_days: u32,
    pub cooldown_sec: u64,
    pub max_window_min: u32,
    pub max_locations_per_app: u64,

    /// トークン発行の上限（1時間の固定ウィンドウあたり、IP単位）
    pub client_issue_quota_per_hour: i64,
    /// 打刻の上限（1分の固定ウィンドウあたり、IP単位）
    pub checkin_rate_limit_per_min: i64,

    pub cold_retention_days: u32,
    pub cold_queue_capacity: usize,
    /// この件数を超えて打刻された location のみ Cold層へ永続化する（§5.2）
    pub cold_persist_min_checkins: i64,

    /// 信頼できるプロキシの段数。0 なら TCP ソースアドレスを使う。
    pub trusted_proxy_hops: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("環境変数 {0} が設定されていません")]
    Missing(&'static str),
    #[error("環境変数 {0} の値が不正です: {1}")]
    Invalid(&'static str, String),
    #[error("環境変数 {0} は {1} バイト以上である必要があります")]
    TooShort(&'static str, usize),
}

fn required(key: &'static str) -> Result<String, ConfigError> {
    env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing(key))
}

fn optional<T>(key: &'static str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse::<T>()
            .map_err(|e| ConfigError::Invalid(key, e.to_string())),
        _ => Ok(default),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let signing_key = required("SIGNING_KEY")?.into_bytes();
        if signing_key.len() < 32 {
            return Err(ConfigError::TooShort("SIGNING_KEY", 32));
        }
        let hash_key = required("HASH_KEY")?.into_bytes();
        if hash_key.len() < 32 {
            return Err(ConfigError::TooShort("HASH_KEY", 32));
        }

        let max_window_min: u32 = optional("MAX_WINDOW_MIN", 1440)?;
        if max_window_min == 0 || max_window_min > 1440 {
            return Err(ConfigError::Invalid(
                "MAX_WINDOW_MIN",
                "1〜1440 の範囲で指定してください".into(),
            ));
        }

        Ok(Self {
            bind_addr: optional("BIND_ADDR", "0.0.0.0:8080".to_string())?,
            redis_url: required("REDIS_URL")?,
            database_url: required("DATABASE_URL")?,
            signing_key,
            hash_key,
            k_anonymity: optional("K_ANONYMITY", 3)?,
            token_ttl_days: optional("TOKEN_TTL_DAYS", 30)?,
            cooldown_sec: optional("COOLDOWN_SEC", 60)?,
            max_window_min,
            max_locations_per_app: optional("MAX_LOCATIONS_PER_APP", 10_000)?,
            client_issue_quota_per_hour: optional("CLIENT_ISSUE_QUOTA_PER_HOUR", 60)?,
            checkin_rate_limit_per_min: optional("CHECKIN_RATE_LIMIT_PER_MIN", 300)?,
            cold_retention_days: optional("COLD_RETENTION_DAYS", 90)?,
            cold_queue_capacity: optional("COLD_QUEUE_CAPACITY", 10_000)?,
            cold_persist_min_checkins: optional("COLD_PERSIST_MIN_CHECKINS", 10)?,
            trusted_proxy_hops: optional("TRUSTED_PROXY_HOPS", 0)?,
        })
    }

    /// Redis キーの TTL（秒）。`window` の最大値 + マージン1時間（§6.1）
    pub fn key_ttl_sec(&self) -> u64 {
        self.max_window_min as u64 * 60 + 3600
    }

    /// ZSET から古いメンバを削除する基準（秒）。`window` の最大値そのもの。
    pub fn window_max_sec(&self) -> u64 {
        self.max_window_min as u64 * 60
    }

    pub fn token_ttl_sec(&self) -> u64 {
        self.token_ttl_days as u64 * 86_400
    }
}
