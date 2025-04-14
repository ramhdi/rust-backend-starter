use crate::entity::{self, users};
use crate::error::{AppError, Result};
use chrono::Utc;
use entity::prelude::*;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
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

pub async fn create_user(
    db: &DatabaseConnection,
    username: String,
    email: String,
    password_hash: String,
    full_name: String,
) -> Result<users::Model> {
    let uuid = Uuid::new_v4();
    let now = Utc::now();

    let user = users::ActiveModel {
        id: Set(uuid),
        username: Set(username),
        email: Set(email),
        password_hash: Set(password_hash),
        full_name: Set(full_name),
        role: Set("user".to_string()),
        created_at: Set(Some(now.into())),
        updated_at: Set(Some(now.into())),
    };

    user.insert(db).await.map_err(AppError::from)
}
