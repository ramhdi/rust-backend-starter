use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use sea_orm::DbErr;
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Database(DbErr),
    Auth(String),
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Database error: {}", e),
            Self::Auth(e) => write!(f, "Authentication error: {}", e),
            Self::NotFound(e) => write!(f, "Not found: {}", e),
            Self::BadRequest(e) => write!(f, "Bad request: {}", e),
            Self::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl From<DbErr> for AppError {
    fn from(err: DbErr) -> Self {
        Self::Database(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error occurred"),
            Self::Auth(ref err) => (StatusCode::UNAUTHORIZED, err.as_str()),
            Self::NotFound(ref err) => (StatusCode::NOT_FOUND, err.as_str()),
            Self::BadRequest(ref err) => (StatusCode::BAD_REQUEST, err.as_str()),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
