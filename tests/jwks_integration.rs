use attestation_gateway::{keys::SigningKey, kms_jws::KMSKeyDefinition, utils::SIGNING_CONFIG};
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Extension,
};
use http_body_util::BodyExt;
use josekit::jwk::Jwk;
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::{Map, Value};
use serial_test::serial;
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

#[derive(Debug, Deserialize, Clone)]
struct KeyResponse {
    keys: Vec<Map<String, Value>>,
}

#[tokio::test]
#[serial]
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
    let response = serde_json::from_slice::<KeyResponse>(&response).unwrap();

    assert_eq!(response.keys.len(), 1);

    let jwk = Jwk::from_map(response.keys[0].clone()).unwrap();

    assert_eq!(&jwk.key_id().unwrap()[0..4], "key_");

    assert!(jwk.to_public_key().is_ok());
}

#[tokio::test]
#[serial]
async fn test_fetching_jwks_includes_keys_valid_for_signature() {
    let api_router = get_api_router().await;
    let mut redis = get_redis_extension().await.0;

    // create a key valid for for verification
    let verifying_key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_abcdefgh".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_abcdefgh".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp() - SIGNING_CONFIG.key_ttl_signing - 10,
    };
    redis
        .rpush::<_, _, ()>("signing-keys", serde_json::to_vec(&verifying_key).unwrap())
        .await
        .unwrap();

    // create a key that is completely expired
    let key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_123".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_123".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp() - SIGNING_CONFIG.key_ttl_verification - 10,
    };
    redis
        .rpush::<_, _, ()>("signing-keys", serde_json::to_vec(&key).unwrap())
        .await
        .unwrap();

    // Note we haven't created any keys yet, but when fetching the keys if none are available, a new one is created
    let response = api_router
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
    let response = serde_json::from_slice::<KeyResponse>(&response).unwrap();

    assert_eq!(response.keys.len(), 2); // 2 keys are valid for verification (one is automatically added because there are no valid keys)

    let jwk = Jwk::from_map(response.keys[0].clone()).unwrap();

    assert_eq!(&jwk.key_id().unwrap()[0..4], "key_");

    assert!(jwk.to_public_key().is_ok());

    // assert the expired key is never returned
    for map in &response.keys {
        for (key, value) in map {
            if key == "kid" {
                assert_ne!(value.as_str().unwrap(), "key_123".to_string());
            }
        }
    }
}
