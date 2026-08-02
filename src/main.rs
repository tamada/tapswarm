//! tapswarm — 汎用混雑度測定サービス
//!
//! 仕様書: `.github/assets/spec.md` (v0.2)

mod cold;
mod config;
mod error;
mod hot;
mod routes;
mod state;
mod token;
mod validate;

use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::hot::Hot;
use crate::state::AppState;
use crate::token::{AppId, TokenIssuer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `tapswarm gen-app-id` — 開発用に app_id を1つ払い出す（§5.2）。
    // 本来は SDK が初回起動時に生成するもので、サーバーへの登録は不要。
    if std::env::args().nth(1).as_deref() == Some("gen-app-id") {
        println!("{}", AppId::generate());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("tapswarm=info,warn")),
        )
        .init();

    let cfg = Arc::new(Config::from_env()?);

    let hot = Hot::connect(&cfg.redis_url).await?;
    hot.ping().await?;
    tracing::info!("connected to redis");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("connected to postgres and applied migrations");

    let cold = cold::spawn(pool.clone(), cfg.cold_queue_capacity);
    cold::spawn_retention_task(pool.clone(), cfg.cold_retention_days);

    let issuer = Arc::new(TokenIssuer::new(
        cfg.signing_key.clone(),
        cfg.token_ttl_sec(),
    ));

    let state = AppState {
        cfg: Arc::clone(&cfg),
        hot,
        cold: cold.clone(),
        pool,
        issuer,
    };

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        k_anonymity = cfg.k_anonymity,
        max_window_min = cfg.max_window_min,
        trusted_proxy_hops = cfg.trusted_proxy_hops,
        "tapswarm listening"
    );

    axum::serve(
        listener,
        routes::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    let (written, dropped, failed) = cold.snapshot();
    tracing::info!(written, dropped, failed, "shutting down; cold layer totals");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
