use aws_config::Region;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Extension,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `collect`
use tracing_subscriber::FmtSubscriber;

use attestation_gateway::utils::{BundleIdentifier, TokenGenerationRequest};

static VALID_INTEGRITY_TOKEN: &str = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.cNECHTrf6KAJDjDGqkWF4O0uMey-S4rjJYV9GNuyVGZlSOJV_4VaTg.gC6osYvLIhvwroOJ.EYkQCz4FFVNdRozPflriVz23J4AkP3FXnYU-p2IzEp9I5GHsYnEQg8CHCx_bNRBP_kUiWKjUDNW7XV-f1xHp-F8lDhuda-eouMdzdzphbQPw_jCEo3ujN-i6tO8NWUqOX3L8IhYQxDilz3yQ6j5_2ESlrNfm9J2KO9UaK5xAvNvUeplDCuG9DbAjoiqyKo1F7Arezqqo7M0NeMMD3EWVf36Pqx3_Fna14wdUx6mRQeMcZ5wYtQprU7mJXGIPoCGvdNuSzwM1Hcgmey8mp7HLXTQP1EXrogzSoGkTdZomfz0wnrB8WkLT5wDg3eb1lhYbih9SwupTrakAQG9LdBAWEldO_GzX1JW6zI51tZIUlWjyNhNrWJtyYNAYSSbc9dY4qN5ffNd0vhVlMB5DWD6v-ztaPASG3776e_mfgYsCEd_1PsrW3CbuVY-m5fva2qi0ar1Hye5ZSrE267ND_2CIvjqnEjDKji3S3PepTlbPv1_VGzRrra9QpuJKVKxefeoNGwZ-U8jDeJCErfFdOFJaXJ94McnO0IWc6aoEQf3stzqTEsx_T9MIP6n8TGx-w0xG-WJIVu_P1nb5Ybva8F8oqgtZwhuTGnin3ErSlHAn8HpdJ3-2T0BMuvf8ITfBgdSvS_aMJTPfPp3M8K0O-LN-6fGDZc-brKv_i7s-VQZj6w6D-EJ9xwGbXwxOk7mkyIAseUS-SEXNxG1OcC4QT-e47ncyq2C_KzR3-5spdzCg0FdxvqDuBhj8G2rd-LeElXohmITmJ3Ee_VafaFiYGcRzJdr6wfgF-LJoGNr8GMDxcEH9tIAZwDn6f3BearErgn8EJFrNhMDcallTWQX1AoPlCEhaJBB0RB5L0grAqOqkhM5XqrqzYBUIiIP3Cs1LQSmy2Ai2z6iOaKfyOU_rNXq_jhGmvr9u9PBYjnZhnnOoSVmNp8PkGdb8pLrL_LzMuHundTFOZUsbz3tgyqKzh8dae-Yf6D5u_byCUyMscnLL9Q520NfWnXtHVYJCWZOeU9F693MFUUE4aOuEZFfSk998QTSEFf-TagC7vP2rH4Zpux0sCM2hqxjOOvZEyg3Ef8FsBvg9srRIIb_L5mpVa0jasTyqfyDVECxZO4YiqZW5CWPWLDfgT2MkYPOT8VclhZ5ZyJIKu7ZamNGriSZBhHjKQi2g0ap9A75qnyrdq-hEJZo4gqKmUou9f3fQAzT3sCPj1i3PEWVmHQvlt5vbDTqmBBxyLcgSkd0oNrpI-So2jf94syvImh_5OKexCdde5Fj91o8.5_KKK0EuQwEA5tjlpxaRzA";

async fn get_kms_client_extension() -> Extension<aws_sdk_kms::Client> {
    // Required to load default AWS Config variables
    dotenvy::from_filename(".env.example").unwrap();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    let config = aws_sdk_kms::config::Builder::from(&aws_config)
        .region(Region::new("us-east-1"))
        .endpoint_url("http://localhost:4566")
        .build();

    let kms_client = aws_sdk_kms::Client::from_conf(config);

    Extension(kms_client)
}

fn get_global_config_extension() -> Extension<attestation_gateway::utils::GlobalConfig> {
    let config = attestation_gateway::utils::GlobalConfig {
        output_token_kms_key_arn:
            "arn:aws:kms:us-east-1:000000001111:key/c7956b9c-5235-4e8e-bb35-7310fb80f4ca"
                .to_string(),
    };
    Extension(config)
}

async fn get_redis_extension() -> Extension<redis::aio::ConnectionManager> {
    let client = redis::Client::open("redis://localhost").unwrap();
    // Reset Redis before each test run
    redis::cmd("FlUSHALL").execute(&mut client.clone().get_connection().unwrap());

    Extension(redis::aio::ConnectionManager::new(client).await.unwrap())
}

async fn get_api_router() -> aide::axum::ApiRouter {
    attestation_gateway::routes::handler()
        .layer(get_kms_client_extension().await)
        .layer(get_global_config_extension())
        .layer(get_redis_extension().await)
}

#[tokio::test]
async fn test_token_generation() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: VALID_INTEGRITY_TOKEN.to_string(),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert!(body["attestation_gateway_token"].is_string());

    // TODO: Verify the token
}

#[tokio::test]
async fn test_token_generation_fails_on_invalid_bundle_identifier() {
    let api_router = get_api_router().await;

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "toolsforhumanity.com".to_string(),
        "bundle_identifier": "com.worldcoin.invalid".to_string(),
        "request_hash": "my_request_hash".to_string(),
    });

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body["schema_validation"][0]["instance_location"],
        "/bundle_identifier".to_string()
    );
}

#[tokio::test]
async fn test_token_generation_fails_on_duplicate_redis_key() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: VALID_INTEGRITY_TOKEN.to_string(),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

    // First request succeeds
    let response = api_router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Subsequent request fails
    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["code"], "duplicate_request_hash");
}
