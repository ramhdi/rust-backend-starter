use crate::entity::{self, users};
use entity::prelude::*;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};

pub async fn find_user_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<Option<users::Model>, DbErr> {
    Users::find()
        .filter(users::Column::Email.eq(email))
        .one(db)
        .await
}
