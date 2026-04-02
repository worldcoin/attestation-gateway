use std::{env, net::SocketAddr, time::Duration};

use crate::{android::AndroidAttestationService, nonces::NonceDb};
use aide::openapi::{Info, OpenApi};
use aws_sdk_kinesis::Client as KinesisClient;
use axum::Extension;
use redis::aio::ConnectionManager;
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};

use crate::{routes, utils::GlobalConfig};

#[must_use]
pub fn get_timeout_layer(timeout: Option<u64>) -> TimeoutLayer {
    let timeout = timeout.map_or(Duration::from_secs(5), Duration::from_secs);
    TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, timeout)
}

pub async fn start(
    redis: ConnectionManager,
    aws_config: aws_config::SdkConfig,
    global_config: GlobalConfig,
    kinesis_client: KinesisClient,
) {
    let mut openapi = OpenApi {
        info: Info {
            title: "Attestation Gateway".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let nonce_db = NonceDb::new(redis.clone());
    let android_attestation_service = AndroidAttestationService::from_defaults()
        .await
        .expect("failed to construct Android attestation service");

    android_attestation_service.spawn_refresh_loop();

    let app = routes::handler()
        .finish_api(&mut openapi)
        .layer(Extension(nonce_db))
        .layer(Extension(redis))
        .layer(Extension(openapi))
        .layer(Extension(aws_config))
        .layer(Extension(global_config))
        .layer(CompressionLayer::new())
        .layer(Extension(kinesis_client))
        .layer(Extension(android_attestation_service))
        .layer(
            TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().include_headers(true)),
        )
        .layer(get_timeout_layer(None));

    let address = SocketAddr::from((
        [0, 0, 0, 0],
        env::var("PORT").map_or(8000, |p| p.parse().unwrap()),
    ));
    let listener = TcpListener::bind(&address)
        .await
        .expect("Failed to bind address");

    println!("😈 Attestation gateway started on http://{address}");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("Failed to start server");
}
