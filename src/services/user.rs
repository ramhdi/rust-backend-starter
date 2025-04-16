use axum::extract::Path;
use axum::{Extension, Json};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::auth::{self, CurrentUser, Role, SignUpData};
use crate::error::{AppError, Result};
use crate::repository;

#[derive(Serialize)]
pub struct UserListItem {
    id: String,
    username: String,
    email: String,
    full_name: String,
    role: String,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

pub async fn get_current_user(
    Extension(current_user): Extension<CurrentUser>,
) -> Json<CurrentUser> {
    Json(current_user)
}

pub async fn get_user_profile(
    Extension(db): Extension<DatabaseConnection>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Value>> {
    let user = repository::user::find_user_by_id(&db, current_user.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "created_at": user.created_at
    })))
}

pub async fn get_all_users(
    Extension(db): Extension<DatabaseConnection>,
) -> Result<Json<Vec<UserListItem>>> {
    let users = repository::user::find_all_users(&db).await?;

    let user_list = users
        .into_iter()
        .map(|user| UserListItem {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            role: user.role,
            created_at: user.created_at.map(|dt| dt.into()),
        })
        .collect();

    Ok(Json(user_list))
}

pub async fn get_user_by_id(
    Extension(db): Extension<DatabaseConnection>,
    user_id: String,
) -> Result<Json<Value>> {
    let uuid = Uuid::parse_str(&user_id)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let user = repository::user::find_user_by_id(&db, uuid)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "created_at": user.created_at
    })))
}

pub async fn update_user_role(
    Extension(db): Extension<DatabaseConnection>,
    Path(user_id): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<Value>> {
    let role = Role::from_str(&request.role)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid role: {}", request.role)))?;

    let uuid = Uuid::parse_str(&user_id)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let updated_user = repository::user::update_user_role(&db, uuid, role.to_string()).await?;

    Ok(Json(serde_json::json!({
        "id": updated_user.id.to_string(),
        "username": updated_user.username,
        "email": updated_user.email,
        "role": updated_user.role,
        "message": format!("User role updated to {}", updated_user.role)
    })))
}

pub async fn delete_user(
    Extension(db): Extension<DatabaseConnection>,
    user_id: String,
) -> Result<Json<Value>> {
    let uuid = Uuid::parse_str(&user_id)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let user = repository::user::find_user_by_id(&db, uuid)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))?;

    repository::user::delete_user(&db, uuid).await?;

    Ok(Json(serde_json::json!({
        "message": format!("User {} successfully deleted", user.username),
        "id": user_id
    })))
}

pub async fn create_admin_user(
    Extension(db): Extension<DatabaseConnection>,
    Json(data): Json<SignUpData>,
) -> Result<Json<Value>> {
    if repository::user::find_user_by_email(&db, &data.email)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest("Email already registered".to_string()));
    }

    let password_hash = auth::hash_password(&data.password)?;

    let user = repository::user::create_user_with_role(
        &db,
        data.username,
        data.email,
        password_hash,
        data.full_name,
        Role::Admin.as_str().to_string(),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at,
        "message": "Admin user created successfully"
    })))
}
