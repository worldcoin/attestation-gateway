#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use dotenvy::dotenv;
use redis::aio::ConnectionManager;
use std::env;

mod android;
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

    // Construct Redis URL

    let redis = environment.redis_client().await;

    tracing::info!("✅ Connection to Redis established.");

    let kms_client = environment.kms_client().await;

    server::start(redis, kms_client).await;
}

async fn build_redis_pool(mut redis_url: String) -> redis::RedisResult<ConnectionManager> {
    if !redis_url.starts_with("redis://") && !redis_url.starts_with("rediss://") {
        redis_url = format!("redis://{redis_url}");
    }

    let client = redis::Client::open(redis_url)?;

    ConnectionManager::new(client).await
}

enum Environment {
    Testing,
    Production,
    Development,
}

impl From<&str> for Environment {
    fn from(s: &str) -> Self {
        match s {
            "testing" => Self::Testing,
            "production" => Self::Production,
            "development" => Self::Development,
            _ => panic!("no, bad."),
        }
    }
}

impl Environment {
    pub fn from_env() -> Self {
        env::var("APP_ENV")
            .unwrap_or_else(|_| "production".to_string())
            .as_str()
            .into()
    }

    pub const fn log_level(&self) -> tracing::Level {
        match self {
            Self::Testing | Self::Development => tracing::Level::DEBUG,
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

        build_redis_pool(redis_url)
            .await
            .expect("Failed to connect to Redis")
    }

    pub async fn kms_client(&self) -> aws_sdk_kms::Client {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

        tracing::debug!("AWS Config: {:?}", aws_config);

        aws_sdk_kms::Client::new(&aws_config)
    }
}
