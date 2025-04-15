use dotenvy::dotenv;
use std::env::{self};
use tracing::info;

use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration: i64, // hours
    pub server_addr: String,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        match dotenv() {
            Ok(_) => info!("Loaded environment from .env file"),
            Err(_) => info!("No .env file found, using environment variables"),
        }

        let server_addr = env::var("SERVER_ADDR").map_err(|_| {
            AppError::Environment("SERVER_ADDR not found in environment".to_string())
        })?;

        let database_url = env::var("DATABASE_URL").map_err(|_| {
            AppError::Environment("DATABASE_URL not found in environment".to_string())
        })?;

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| {
            AppError::Environment("JWT_SECRET not found in environment".to_string())
        })?;

        let jwt_expiration = env::var("JWT_EXPIRATION")
            .map_err(|_| {
                AppError::Environment("JWT_EXPIRATION not found in environment".to_string())
            })?
            .parse()
            .map_err(|_| {
                AppError::Environment("Failed parsing JWT_EXPIRATION to i64".to_string())
            })?;

        Ok(Self {
            database_url,
            jwt_secret,
            jwt_expiration,
            server_addr,
        })
    }
}
