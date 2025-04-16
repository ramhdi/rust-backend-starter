use crate::entity::{self, users};
use crate::error::{AppError, Result};
use chrono::Utc;
use entity::prelude::*;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use uuid::Uuid;

pub async fn find_user_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<Option<users::Model>> {
    Users::find()
        .filter(users::Column::Email.eq(email))
        .one(db)
        .await
        .map_err(AppError::from)
}

pub async fn find_user_by_id(db: &DatabaseConnection, id: Uuid) -> Result<Option<users::Model>> {
    Users::find_by_id(id).one(db).await.map_err(AppError::from)
}

pub async fn find_all_users(db: &DatabaseConnection) -> Result<Vec<users::Model>> {
    Users::find().all(db).await.map_err(AppError::from)
}

pub async fn create_user_with_role(
    db: &DatabaseConnection,
    username: String,
    email: String,
    password_hash: String,
    full_name: String,
    role: String,
) -> Result<users::Model> {
    let uuid = Uuid::new_v4();
    let now = Utc::now();

    let user = users::ActiveModel {
        id: sea_orm::Set(uuid),
        username: sea_orm::Set(username),
        email: sea_orm::Set(email),
        password_hash: sea_orm::Set(password_hash),
        full_name: sea_orm::Set(full_name),
        role: sea_orm::Set(role),
        created_at: sea_orm::Set(Some(now.into())),
        updated_at: sea_orm::Set(Some(now.into())),
    };

    user.insert(db).await.map_err(AppError::from)
}

pub async fn update_user_role(
    db: &DatabaseConnection,
    user_id: Uuid,
    role: String,
) -> Result<users::Model> {
    let user = Users::find_by_id(user_id)
        .one(db)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))?;

    let mut user_model: users::ActiveModel = user.into();
    user_model.role = sea_orm::Set(role);
    let updated_user = user_model.update(db).await.map_err(AppError::from)?;

    Ok(updated_user)
}

pub async fn delete_user(db: &DatabaseConnection, user_id: Uuid) -> Result<()> {
    let _ = Users::find_by_id(user_id)
        .one(db)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))?;

    Users::delete_by_id(user_id)
        .exec(db)
        .await
        .map_err(AppError::from)?;

    Ok(())
}
