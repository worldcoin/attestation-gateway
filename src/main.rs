#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use crate::utils::GlobalConfig;
use aws_sdk_kinesis::Client as KinesisClient;
use dotenvy::dotenv;
use metrics_exporter_statsd::StatsdBuilder;
use redis::aio::ConnectionManager;
use regex::Regex;
use std::{env, fmt};

mod android;
mod apple;
mod keys;
mod kinesis;
mod kms_jws;
mod routes;
mod server;
mod utils;

#[tokio::main]
async fn main() {
    // initialize logging early to make sure everything is reported
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .flatten_event(true)
        .init();

    tracing::info!("Starting attestation gateway...");

    dotenv().ok();

    let environment = Environment::from_env();

    // Initialize logging
    match environment {
        Environment::Production | Environment::Staging => {
            set_up_metrics(environment)
                .map_err(|e| {
                    tracing::error!(error = ?e, "Error setting up metrics");
                })
                .unwrap();
        }
        Environment::Development => {}
    }

    tracing::info!("✅ Configuration loaded successfully...");

    let redis = environment.redis_client().await;
    tracing::info!("✅ Connection to Redis established.");

    let aws_config = environment.aws_config().await;
    tracing::info!("✅ AWS configuration setup complete.");

    let kinesis_client = environment.kinesis_client().await;
    tracing::info!("✅ Kinesis client created.");

    server::start(redis, aws_config, GlobalConfig::from_env(), kinesis_client).await;
}

fn set_up_metrics(environment: Environment) -> eyre::Result<()> {
    let recorder = StatsdBuilder::from("localhost", 8125)
        .with_queue_size(5000)
        .with_buffer_size(1024)
        .with_default_tag("env", environment.to_string())
        .build(Some("attestation_gateway."))?;

    metrics::set_global_recorder(recorder)?;

    Ok(())
}

async fn build_redis_pool(redis_url: String) -> redis::RedisResult<ConnectionManager> {
    let client: redis::Client = redis::Client::open(redis_url)?;
    ConnectionManager::new(client).await
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Environment {
    Production,
    Staging,
    Development,
}

impl TryFrom<&str> for Environment {
    type Error = Box<dyn std::error::Error>;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "production" => Ok(Self::Production),
            "staging" => Ok(Self::Staging),
            "development" => Ok(Self::Development),
            _ => Err(format!("invalid `APP_ENV` environment variable: {s}").into()),
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env_str = match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Development => "development",
        };
        write!(f, "{env_str}")
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

            // assert port is in valid range
            let port: u16 = port
                .parse()
                .expect("REDIS_PORT must be a valid port number");
            assert!(port > 1024, "REDIS_PORT must be a valid port number");

            let re = Regex::new(r"[^@%\/\\:,]+").unwrap();

            // assert valid username & password
            assert!(
                re.is_match(&username),
                "redis username must not contain invalid characters"
            );

            assert!(
                re.is_match(&password),
                "redis password must not contain invalid characters"
            );

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

    pub async fn kinesis_client(&self) -> KinesisClient {
        // Redefine the Kinesis region if needed
        let kinesis_region = env::var("KINESIS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let mut config_builder = self.aws_config().await.into_builder();
        config_builder.set_region(Some(aws_sdk_kinesis::config::Region::new(kinesis_region)));
        let config = config_builder.build();
        KinesisClient::new(&config)
    }

    pub async fn aws_config(&self) -> aws_config::SdkConfig {
        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
    }
}
