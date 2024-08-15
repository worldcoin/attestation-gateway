#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::utils::GlobalConfig;
use dotenvy::dotenv;
use redis::aio::ConnectionManager;
use std::env;

mod android;
mod apple;
mod keys;
mod kms_jws;
mod routes;
mod server;
mod utils;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let environment = Environment::from_env();

    tracing_subscriber::fmt()
        .with_max_level(environment.log_level())
        .json()
        .with_target(false)
        .flatten_event(true)
        .without_time()
        .init();

    tracing::info!("Starting attestation gateway...");

    let redis = environment.redis_client().await;
    tracing::info!("✅ Connection to Redis established.");

    let aws_config = environment.aws_config().await;

    server::start(redis, aws_config, GlobalConfig::from_env()).await;
}

async fn build_redis_pool(redis_url: String) -> redis::RedisResult<ConnectionManager> {
    let client: redis::Client = redis::Client::open(redis_url)?;
    ConnectionManager::new(client).await
}

#[derive(Debug, PartialEq, Eq)]
enum Environment {
    Production,
    Development,
}

impl TryFrom<&str> for Environment {
    type Error = Box<dyn std::error::Error>;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "production" => Ok(Self::Production),
            "development" => Ok(Self::Development),
            _ => Err(format!("invalid `APP_ENV` environment variable: {s}").into()),
        }
    }
}

impl Environment {
    pub fn from_env() -> Self {
        env::var("APP_ENV")
            .unwrap_or_else(|_| "production".to_string())
            .trim()
            .try_into()
            .unwrap()
    }

    pub const fn log_level(&self) -> tracing::Level {
        match self {
            Self::Development => tracing::Level::DEBUG,
            Self::Production => tracing::Level::INFO,
        }
    }

    pub async fn redis_client(&self) -> ConnectionManager {
        let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| {
            let host = env::var("REDIS_HOST").expect("REDIS_URL or REDIS_HOST is required.");
            let port =
                env::var("REDIS_PORT").expect("REDIS_PORT required if REDIS_URL is not set.");
            let username = env::var("REDIS_USERNAME")
                .expect("REDIS_USERNAME required if REDIS_URL is not set.");
            let password = env::var("REDIS_PASSWORD")
                .expect("REDIS_PASSWORD required if REDIS_URL is not set.");
            // Get the REDIS_USE_TLS environment variable and parse it as a boolean
            let use_tls = env::var("REDIS_USE_TLS")
                .map(|val| val.to_lowercase() == "true")
                .unwrap_or(false);

            format!(
                "{}://{}:{}@{}:{}",
                if use_tls { "rediss" } else { "redis" },
                username,
                password,
                host,
                port
            )
        });

        assert!(
            self != &Self::Production || redis_url.starts_with("rediss://"),
            "For security reasons, TLS is required for Redis in production. Set `REDIS_USE_TLS` = `true` or the scheme of `REDIS_URL`."
        );

        build_redis_pool(redis_url)
            .await
            .expect("Failed to connect to Redis")
    }

    pub async fn aws_config(&self) -> aws_config::SdkConfig {
        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
    }
}
