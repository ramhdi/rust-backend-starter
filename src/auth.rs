use axum::{
    body::Body,
    extract::{Extension, Json, Request},
    http,
    http::Response,
    middleware::Next,
};
use bcrypt::DEFAULT_COST;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::entity;
use crate::error::{AppError, Result};
use crate::repository;
use crate::{config::Config, rbac::Role};

#[derive(Deserialize)]
pub struct SignInData {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub device_info: Option<String>,
}

#[derive(Deserialize)]
pub struct SignUpData {
    pub email: String,
    pub password: String,
    pub username: String,
    pub full_name: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: u64,
    pub iat: u64,
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub full_name: String,
    pub role: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub user_id: Uuid,
    pub email: String,
    pub username: String,
    pub full_name: String,
    pub role: String,
}

pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, DEFAULT_COST).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn generate_refresh_token() -> String {
    Uuid::new_v4().to_string()
}

pub fn encode_jwt(config: &Config, user: &entity::users::Model) -> Result<(String, DateTime<Utc>)> {
    let now = Utc::now();
    let expiry_time = now + Duration::minutes(config.jwt_expiration);
    let exp = expiry_time.timestamp() as u64;
    let iat = now.timestamp() as u64;

    let claim = Claims {
        iat,
        exp,
        email: user.email.clone(),
        username: user.username.clone(),
        user_id: user.id.to_string(),
        full_name: user.full_name.clone(),
        role: user.role.clone(),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal("Failed to encode JWT".to_string()))?;

    Ok((token, expiry_time))
}

pub fn decode_jwt(config: &Config, jwt: &str) -> Result<TokenData<Claims>> {
    jsonwebtoken::decode(
        jwt,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Auth("Invalid token".to_string()))
}

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

    let claims = decode_jwt(&config, token)?;

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

pub async fn sign_in(
    Extension(config): Extension<Config>,
    Extension(db): Extension<DatabaseConnection>,
    Json(data): Json<SignInData>,
) -> Result<Json<AuthTokens>> {
    let user = repository::user::find_user_by_email(&db, &data.email)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid email or password".to_string()))?;

    if !verify_password(&data.password, &user.password_hash)? {
        return Err(AppError::Auth("Invalid email or password".to_string()));
    }

    let (access_token, expiry) = encode_jwt(&config, &user)?;
    let expires_in = (expiry - Utc::now()).num_seconds();
    let refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    repository::refresh_token::create_refresh_token(
        &db,
        user.id,
        &refresh_token,
        refresh_expires_at,
        data.device_info,
    )
    .await?;

    Ok(Json(AuthTokens {
        access_token,
        refresh_token,
        expires_in,
        token_type: "Bearer".to_string(),
    }))
}

pub async fn sign_up(
    Extension(db): Extension<DatabaseConnection>,
    Json(data): Json<SignUpData>,
) -> Result<Json<Value>> {
    if repository::user::find_user_by_email(&db, &data.email)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest("Email already registered".to_string()));
    }

    let password_hash = hash_password(&data.password)?;

    let user = repository::user::create_user_with_role(
        &db,
        data.username,
        data.email,
        password_hash,
        data.full_name,
        Role::User.as_str().to_string(),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at
    })))
}

pub async fn refresh_token(
    Extension(config): Extension<Config>,
    Extension(db): Extension<DatabaseConnection>,
    Json(data): Json<RefreshTokenRequest>,
) -> Result<Json<AuthTokens>> {
    let stored_token = repository::refresh_token::find_by_token(&db, &data.refresh_token)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid refresh token".to_string()))?;

    let now: DateTime<Utc> = stored_token.expires_at.into();
    if now < Utc::now() || stored_token.revoked {
        repository::refresh_token::revoke_token(&db, &data.refresh_token).await?;
        return Err(AppError::Auth(
            "Refresh token expired or revoked".to_string(),
        ));
    }

    let user = repository::user::find_user_by_id(&db, stored_token.user_id)
        .await?
        .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

    let (access_token, expiry) = encode_jwt(&config, &user)?;
    let expires_in = (expiry - Utc::now()).num_seconds();
    let new_refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    repository::refresh_token::revoke_token(&db, &data.refresh_token).await?;

    repository::refresh_token::create_refresh_token(
        &db,
        user.id,
        &new_refresh_token,
        refresh_expires_at,
        stored_token.device_info,
    )
    .await?;

    Ok(Json(AuthTokens {
        access_token,
        refresh_token: new_refresh_token,
        expires_in,
        token_type: "Bearer".to_string(),
    }))
}

pub async fn signout(
    Extension(db): Extension<DatabaseConnection>,
    Json(data): Json<RefreshTokenRequest>,
) -> Result<Json<Value>> {
    repository::refresh_token::revoke_token(&db, &data.refresh_token).await?;

    Ok(Json(serde_json::json!({
        "message": "Successfully signed out"
    })))
}

pub async fn signout_all(
    Extension(db): Extension<DatabaseConnection>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Value>> {
    repository::refresh_token::revoke_all_user_tokens(&db, current_user.user_id).await?;

    Ok(Json(serde_json::json!({
        "message": "Successfully signed out from all devices"
    })))
}
