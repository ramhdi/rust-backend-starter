use axum::{
    body::Body,
    extract::{Extension, Json, Request},
    http,
    http::Response,
    middleware::Next,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::config::Config;
use crate::entity::users;
use crate::error::{AppError, Result};
use crate::repository::user_repository;

#[derive(Deserialize)]
pub struct SignInData {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SignUpData {
    pub email: String,
    pub password: String,
    pub username: String,
    pub full_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: u64,
    pub iat: u64,
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub full_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub user_id: Uuid,
    pub email: String,
    pub username: String,
    pub full_name: String,
}

pub fn hash_password(password: &str) -> Result<String> {
    hash(password, DEFAULT_COST).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    verify(password, hash).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn encode_jwt(config: &Config, user: &users::Model) -> Result<String> {
    let now = Utc::now();
    let exp = (now + Duration::hours(config.jwt_expiration)).timestamp() as u64;
    let iat = now.timestamp() as u64;

    let claim = Claims {
        iat,
        exp,
        email: user.email.clone(),
        username: user.username.clone(),
        user_id: user.id.to_string(),
        full_name: user.full_name.clone(),
    };

    encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal("Failed to encode JWT".to_string()))
}

pub fn decode_jwt(config: &Config, jwt: &str) -> Result<TokenData<Claims>> {
    decode(
        jwt,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Auth("Invalid token".to_string()))
}

pub async fn authorize(mut req: Request, next: Next) -> Result<Response<Body>> {
    // Extract the config from the request extensions
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
        .map_err(|_| AppError::Auth("Invalid authorization header".to_string()))?;

    let token = token
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid token format".to_string()))?;

    let claims = decode_jwt(&config, token)?;

    // Check if token is expired
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
    };

    req.extensions_mut().insert(current_user);

    Ok(next.run(req).await)
}

pub async fn sign_in(
    Extension(config): Extension<Config>,
    Extension(db): Extension<sea_orm::DatabaseConnection>,
    Json(data): Json<SignInData>,
) -> Result<Json<String>> {
    let user = user_repository::find_user_by_email(&db, &data.email)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid email or password".to_string()))?;

    if !verify_password(&data.password, &user.password_hash)? {
        return Err(AppError::Auth("Invalid email or password".to_string()));
    }

    let token = encode_jwt(&config, &user)?;
    Ok(Json(token))
}

pub async fn sign_up(
    Extension(db): Extension<sea_orm::DatabaseConnection>,
    Json(data): Json<SignUpData>,
) -> Result<Json<serde_json::Value>> {
    // Check if user already exists
    if user_repository::find_user_by_email(&db, &data.email)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest("Email already registered".to_string()));
    }

    let password_hash = hash_password(&data.password)?;

    let user = user_repository::create_user(
        &db,
        data.username,
        data.email,
        password_hash,
        data.full_name,
    )
    .await?;

    Ok(Json(json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at
    })))
}
