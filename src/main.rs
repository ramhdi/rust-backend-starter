use sea_orm::Database;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::info;

mod auth;
mod config;
mod entity;
mod error;
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
    info!("Configuration loaded:");
    info!("  Database URL: {}", config.database_url);
    info!("  Server Address: {}", config.server_addr);
    info!("  JWT Expiration: {} hours", config.jwt_expiration);

    // Connect to db
    info!("Connecting to database...");
    let db = Database::connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    info!("Database connection established");

    // Configure router
    let app = routes::create_router(config.clone(), db.clone());
    let listener = TcpListener::bind(&config.server_addr)
        .await
        .expect("Failed to bind server");

    info!("Server listening on {}", config.server_addr);

    let shutdown_signal = async {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to setup SIGTERM handler");
            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                },
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                },
            }
        }

        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
        }
    };

    // Serve
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .expect("Server error");

    // Resource cleanup
    info!("Closing database connection...");
    db.close()
        .await
        .expect("Failed to close database connection");

    info!("Database connection closed. Exiting...");
}
