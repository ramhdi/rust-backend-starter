use dotenvy::dotenv;
use std::env;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration: i64, // in hours
    pub server_addr: String,
}

impl Config {
    pub fn from_env() -> Self {
        // Load .env file if it exists
        match dotenv() {
            Ok(_) => info!("Loaded environment from .env file"),
            Err(_) => info!("No .env file found, using environment variables"),
        }

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:postgres@localhost:5432/myapp?currentSchema=public".to_string()
        });

        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());

        let jwt_expiration = env::var("JWT_EXPIRATION")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .unwrap_or(24);

        let server_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());

        Self {
            database_url,
            jwt_secret,
            jwt_expiration,
            server_addr,
        }
    }
}
