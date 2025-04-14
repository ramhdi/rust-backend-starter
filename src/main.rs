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
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Load configuration
    let config = config::Config::from_env();
    info!("Configuration loaded:");
    info!("  Database URL: {}", config.database_url);
    info!("  Server Address: {}", config.server_addr);
    info!("  JWT Expiration: {} hours", config.jwt_expiration);

    // Connect to database
    info!("Connecting to database...");
    let db = Database::connect(&config.database_url)
        .await
        .expect("Failed to connect to database");
    info!("Database connection established");

    // Create router with config and db
    let app = routes::create_router(config.clone(), db.clone());

    // Start server
    let listener = TcpListener::bind(&config.server_addr)
        .await
        .expect("Failed to bind server");

    info!("Server listening on {}", config.server_addr);

    // Spawn a task to listen for shutdown signals
    let shutdown_signal = async {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
            },
            // _ = signal::unix::signal(signal::unix::SignalKind::terminate()) => {
            //     info!("Received SIGTERM, initiating graceful shutdown...");
            // },
        }
    };

    // Serve the app with graceful shutdown
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal);

    if let Err(err) = server.await {
        eprintln!("Server error: {}", err);
    }

    // Close the database connection after shutdown
    info!("Closing database connection...");
    db.close()
        .await
        .expect("Failed to close database connection");
    info!("Database connection closed. Exiting...");
}
