use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Extension,
};
use http_body_util::BodyExt;
use serde_json::{Map, Value};
use tower::ServiceExt; // for `response.collect`

async fn get_aws_config_extension() -> Extension<aws_config::SdkConfig> {
    // Required to load default AWS Config variables
    dotenvy::from_filename(".env.example").unwrap();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    let aws_config = aws_config
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build();

    Extension(aws_config)
}

async fn get_redis_extension() -> Extension<redis::aio::ConnectionManager> {
    let client = redis::Client::open("redis://localhost").unwrap();
    // Reset Redis before each test run
    redis::cmd("FlUSHALL").execute(&mut client.clone().get_connection().unwrap());

    Extension(redis::aio::ConnectionManager::new(client).await.unwrap())
}

async fn get_api_router() -> aide::axum::ApiRouter {
    attestation_gateway::routes::handler()
        .layer(get_aws_config_extension().await)
        .layer(get_redis_extension().await)
}

#[tokio::test]
async fn test_fetching_jwks() {
    // Note we haven't created any keys yet, but when fetching the keys if none are available, a new one is created
    let response = get_api_router()
        .await
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let response = response.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&response).unwrap();

    let keys: Vec<Map<String, Value>> = response["keys"].into();

    assert!(response["keys"])
}
