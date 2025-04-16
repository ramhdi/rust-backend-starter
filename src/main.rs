use std::time::Duration;

use sea_orm::{ConnectOptions, Database};
use tokio::net::TcpListener;
use tokio::signal;

mod auth;
mod config;
mod entity;
mod error;
mod middleware;
mod repository;
mod routes;
mod services;

#[tokio::main]
async fn main() {
    // Logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Config
    let config = config::Config::from_env().expect("Failed loading environment variable");
    tracing::info!("Configuration loaded:");
    tracing::info!("  Database URL: {}", config.database_url);
    tracing::info!(
        "  Database Connection timeout: {} seconds",
        config.db_connect_timeout
    );
    tracing::info!("  Server Address: {}", config.server_addr);
    tracing::info!("  JWT Expiration: {} minutes", config.jwt_expiration);

    // Connect to db
    tracing::info!(
        "Connecting to database with timeout {}s...",
        config.db_connect_timeout
    );

    let mut opt = ConnectOptions::new(config.database_url.clone());
    opt.connect_timeout(Duration::from_secs(config.db_connect_timeout));
    opt.max_connections(100);
    opt.min_connections(5);
    opt.sqlx_logging(false);

    let db = Database::connect(opt)
        .await
        .expect("Failed to connect to database");

    tracing::info!("Database connection established");

    // Configure router
    let app = routes::create_router(config.clone(), db.clone());
    let listener = TcpListener::bind(&config.server_addr)
        .await
        .expect("Failed to bind server");

    tracing::info!("Server listening on {}", config.server_addr);

    let shutdown_signal = async {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to setup SIGTERM handler");
            tokio::select! {
                _ = signal::ctrl_c() => {
                    tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                },
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM, initiating graceful shutdown...");
                },
            }
        }

        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
            tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
        }
    };

    // Serve
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .expect("Server error");

    // Resource cleanup
    tracing::info!("Closing database connection...");
    db.close()
        .await
        .expect("Failed to close database connection");

    tracing::info!("Database connection closed. Exiting...");
}
