use axum::{
    middleware,
    routing::{get, post},
    Extension, Router,
};
use sea_orm::DatabaseConnection;

use crate::auth::{authorize, sign_in, sign_up};
use crate::config::Config;
use crate::services::user_service;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Config,
}

pub fn create_router(config: Config, db: DatabaseConnection) -> Router {
    // Create application state
    let app_state = AppState {
        db: db.clone(),
        config: config.clone(),
    };

    // Public routes that don't require authentication
    let public_routes = Router::new()
        .route("/auth/signin", post(sign_in))
        .route("/auth/signup", post(sign_up));

    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/users/me", get(user_service::get_current_user))
        .route("/users/profile", get(user_service::get_user_profile))
        .layer(middleware::from_fn(authorize));

    // Health check route outside the /api prefix
    let health_route = Router::new().route("/healthz", get(health_check));

    // Combine all routes
    Router::new()
        .nest(
            "/api",
            Router::new().merge(public_routes).merge(protected_routes),
        )
        .merge(health_route) // Keep health check at root level
        .layer(Extension(config)) // Add extension for backward compatibility
        .layer(Extension(db)) // Add extension for backward compatibility
        .with_state(app_state) // Set the app state
}

async fn health_check() -> &'static str {
    "OK"
}
