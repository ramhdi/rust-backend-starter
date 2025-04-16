use crate::auth::CurrentUser;
use crate::error::{AppError, Result};
use axum::{extract::Request, middleware::Next, response::Response};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn from_str(role: &str) -> Option<Self> {
        match role.to_lowercase().as_str() {
            "user" => Some(Role::User),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Admin => "admin",
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub async fn require_role(role_required: Role, request: Request, next: Next) -> Result<Response> {
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

pub async fn require_admin(request: Request, next: Next) -> Result<Response> {
    require_role(Role::Admin, request, next).await
}

pub async fn require_user(request: Request, next: Next) -> Result<Response> {
    require_role(Role::User, request, next).await
}
