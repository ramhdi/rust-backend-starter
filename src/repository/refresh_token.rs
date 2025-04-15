use crate::entity::{self, refresh_tokens};
use crate::error::{AppError, Result};
use chrono::{DateTime, Utc};
use entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub async fn find_by_token(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<refresh_tokens::Model>> {
    RefreshTokens::find()
        .filter(refresh_tokens::Column::Token.eq(token))
        .one(db)
        .await
        .map_err(AppError::from)
}

pub async fn find_by_user_id(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<refresh_tokens::Model>> {
    RefreshTokens::find()
        .filter(refresh_tokens::Column::UserId.eq(user_id))
        .all(db)
        .await
        .map_err(AppError::from)
}

pub async fn create_refresh_token(
    db: &DatabaseConnection,
    user_id: Uuid,
    token: &str,
    expires_at: DateTime<Utc>,
    device_info: Option<String>,
) -> Result<refresh_tokens::Model> {
    let expires_dt: DateTimeWithTimeZone = expires_at.into();
    let now_dt: DateTimeWithTimeZone = Utc::now().into();

    let refresh_token = refresh_tokens::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        token: Set(token.to_string()),
        expires_at: Set(expires_dt),
        created_at: Set(now_dt),
        revoked: Set(false),
        revoked_at: Set(None),
        device_info: Set(device_info),
    };

    refresh_token.insert(db).await.map_err(AppError::from)
}

pub async fn revoke_token(db: &DatabaseConnection, token: &str) -> Result<()> {
    let token_entity = RefreshTokens::find()
        .filter(refresh_tokens::Column::Token.eq(token))
        .one(db)
        .await
        .map_err(AppError::from)?;

    if let Some(token_model) = token_entity {
        let mut token_am: refresh_tokens::ActiveModel = token_model.into();
        token_am.revoked = Set(true);

        let now_dt: DateTimeWithTimeZone = Utc::now().into();
        token_am.revoked_at = Set(Some(now_dt));

        token_am.update(db).await.map_err(AppError::from)?;
    }

    Ok(())
}

pub async fn revoke_all_user_tokens(db: &DatabaseConnection, user_id: Uuid) -> Result<()> {
    let tokens = RefreshTokens::find()
        .filter(refresh_tokens::Column::UserId.eq(user_id))
        .filter(refresh_tokens::Column::Revoked.eq(false))
        .all(db)
        .await
        .map_err(AppError::from)?;

    let now_dt: DateTimeWithTimeZone = Utc::now().into();

    for token in tokens {
        let mut token_am: refresh_tokens::ActiveModel = token.into();
        token_am.revoked = Set(true);
        token_am.revoked_at = Set(Some(now_dt.clone()));

        token_am.update(db).await.map_err(AppError::from)?;
    }

    Ok(())
}

pub async fn clean_expired_tokens(db: &DatabaseConnection) -> Result<u64> {
    let now = Utc::now();
    let now_dt: sea_orm::prelude::DateTimeWithTimeZone = now.into();

    let result = RefreshTokens::delete_many()
        .filter(refresh_tokens::Column::ExpiresAt.lt(now_dt))
        .exec(db)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected)
}
