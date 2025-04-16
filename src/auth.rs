use axum::extract::{Extension, Json, State};
use bcrypt::DEFAULT_COST;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

use crate::config::Config;
use crate::entity;
use crate::error::{AppError, Result};
use crate::repository;
use crate::state::AppState;

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
    .map_err(|error| match error.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Auth("Expired token".to_string())
        }
        _ => AppError::Auth("Invalid token".to_string()),
    })
}

pub async fn sign_in(
    State(state): State<AppState>,
    Json(data): Json<SignInData>,
) -> Result<Json<AuthTokens>> {
    let user = repository::user::find_user_by_email(&state.db, &data.email)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid email or password".to_string()))?;

    if !verify_password(&data.password, &user.password_hash)? {
        return Err(AppError::Auth("Invalid email or password".to_string()));
    }

    let (access_token, expiry) = encode_jwt(&state.config, &user)?;
    let expires_in = (expiry - Utc::now()).num_seconds();
    let refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    repository::refresh_token::create_refresh_token(
        &state.db,
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
    State(state): State<AppState>,
    Json(data): Json<SignUpData>,
) -> Result<Json<Value>> {
    if repository::user::find_user_by_email(&state.db, &data.email)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest("Email already registered".to_string()));
    }

    let password_hash = hash_password(&data.password)?;

    let user = repository::user::create_user_with_role(
        &state.db,
        data.username,
        data.email,
        password_hash,
        data.full_name,
        Role::User.to_string(),
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
    State(state): State<AppState>,
    Json(data): Json<RefreshTokenRequest>,
) -> Result<Json<AuthTokens>> {
    let stored_token = repository::refresh_token::find_by_token(&state.db, &data.refresh_token)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid refresh token".to_string()))?;

    let now: DateTime<Utc> = stored_token.expires_at.into();
    if now < Utc::now() || stored_token.revoked {
        repository::refresh_token::revoke_token(&state.db, &data.refresh_token).await?;
        return Err(AppError::Auth(
            "Refresh token expired or revoked".to_string(),
        ));
    }

    let user = repository::user::find_user_by_id(&state.db, stored_token.user_id)
        .await?
        .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

    let (access_token, expiry) = encode_jwt(&state.config, &user)?;
    let expires_in = (expiry - Utc::now()).num_seconds();
    let new_refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    repository::refresh_token::revoke_token(&state.db, &data.refresh_token).await?;

    repository::refresh_token::create_refresh_token(
        &state.db,
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
    State(state): State<AppState>,
    Json(data): Json<RefreshTokenRequest>,
) -> Result<Json<Value>> {
    repository::refresh_token::revoke_token(&state.db, &data.refresh_token).await?;

    Ok(Json(serde_json::json!({
        "message": "Successfully signed out"
    })))
}

pub async fn signout_all(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Value>> {
    repository::refresh_token::revoke_all_user_tokens(&state.db, current_user.user_id).await?;

    Ok(Json(serde_json::json!({
        "message": "Successfully signed out from all devices"
    })))
}

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

    pub fn to_string(&self) -> String {
        match self {
            Role::User => "user".to_string(),
            Role::Admin => "admin".to_string(),
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
