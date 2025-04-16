use axum::{body::Body, extract::Request, http, http::Response, middleware::Next};
use chrono::Utc;
use uuid::Uuid;

use crate::auth::{self, CurrentUser, Role};
use crate::config::Config;
use crate::error::{AppError, Result};

pub async fn authorize(mut req: Request, next: Next) -> Result<Response<Body>> {
    let config = req
        .extensions()
        .get::<Config>()
        .ok_or_else(|| AppError::Internal("Configuration not found".to_string()))?
        .clone();

    let token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| AppError::Auth("Missing authorization header".to_string()))?
        .to_str()
        .map_err(|_| AppError::Auth("Invalid authorization header".to_string()))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid token format".to_string()))?;

    let claims = auth::decode_jwt(&config, token)?;

    let now = Utc::now().timestamp() as u64;
    if claims.claims.exp < now {
        return Err(AppError::Auth("Token expired".to_string()));
    }

    let user_id = Uuid::parse_str(&claims.claims.user_id)
        .map_err(|_| AppError::Auth("Invalid user ID in token".to_string()))?;

    let current_user = CurrentUser {
        user_id,
        email: claims.claims.email,
        username: claims.claims.username,
        full_name: claims.claims.full_name,
        role: claims.claims.role,
    };

    req.extensions_mut().insert(current_user);

    Ok(next.run(req).await)
}

pub async fn require_role(
    role_required: Role,
    request: Request,
    next: Next,
) -> Result<Response<Body>> {
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or_else(|| AppError::Auth("User not authenticated".to_string()))?;

    let user_role = Role::from_str(&user.role)
        .ok_or_else(|| AppError::Auth(format!("Invalid role: {}", user.role)))?;

    if user_role.is_admin() {
        return Ok(next.run(request).await);
    }

    if role_required == Role::User && user_role == Role::User {
        return Ok(next.run(request).await);
    }

    Err(AppError::Auth(format!(
        "Insufficient permissions. Required role: {}",
        role_required
    )))
}

pub async fn require_admin(request: Request, next: Next) -> Result<Response<Body>> {
    require_role(Role::Admin, request, next).await
}

pub async fn require_user(request: Request, next: Next) -> Result<Response<Body>> {
    require_role(Role::User, request, next).await
}
