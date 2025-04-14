use axum::{Extension, Json};

use crate::auth::CurrentUser;
use crate::error::{AppError, Result};
use crate::repository::user_repository;
use sea_orm::DatabaseConnection;
use serde_json::json;

pub async fn get_current_user(
    Extension(current_user): Extension<CurrentUser>,
) -> Json<CurrentUser> {
    Json(current_user)
}

pub async fn get_user_profile(
    Extension(db): Extension<DatabaseConnection>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>> {
    let user = user_repository::find_user_by_id(&db, current_user.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "created_at": user.created_at
    })))
}
