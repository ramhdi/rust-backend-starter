use axum::{
    middleware,
    routing::{get, post},
    Extension, Router,
};
use sea_orm::DatabaseConnection;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

use crate::auth;
use crate::config::Config;
use crate::services::user;

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
    config: Config,
}

pub fn create_router(config: Config, db: DatabaseConnection) -> Router {
    let app_state = AppState {
        db: db.clone(),
        config: config.clone(),
    };

    // Public routes
    let public_routes = Router::new()
        .route("/auth/signin", post(auth::sign_in))
        .route("/auth/signup", post(auth::sign_up))
        .route("/auth/refresh", post(auth::refresh_token));

    // Protected routes
    let protected_routes = Router::new()
        .route("/users/me", get(user::get_current_user))
        .route("/users/profile", get(user::get_user_profile))
        .route("/auth/signout", post(auth::signout))
        .route("/auth/signout/all", post(auth::signout_all))
        .layer(middleware::from_fn(auth::authorize));

    // Health check
    let health_route = Router::new().route("/healthz", get(health_check));

    Router::new()
        .nest(
            "/api",
            Router::new().merge(public_routes).merge(protected_routes),
        )
        .merge(health_route)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(Extension(config))
        .layer(Extension(db))
        .with_state(app_state)
}

async fn health_check() -> &'static str {
    "OK"
}
