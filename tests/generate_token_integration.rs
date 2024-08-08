use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Extension,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for response.`collect`

use attestation_gateway::utils::{BundleIdentifier, TokenGenerationRequest};
use tracing_test::traced_test;

static VALID_INTEGRITY_TOKEN: &str = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.cNECHTrf6KAJDjDGqkWF4O0uMey-S4rjJYV9GNuyVGZlSOJV_4VaTg.gC6osYvLIhvwroOJ.EYkQCz4FFVNdRozPflriVz23J4AkP3FXnYU-p2IzEp9I5GHsYnEQg8CHCx_bNRBP_kUiWKjUDNW7XV-f1xHp-F8lDhuda-eouMdzdzphbQPw_jCEo3ujN-i6tO8NWUqOX3L8IhYQxDilz3yQ6j5_2ESlrNfm9J2KO9UaK5xAvNvUeplDCuG9DbAjoiqyKo1F7Arezqqo7M0NeMMD3EWVf36Pqx3_Fna14wdUx6mRQeMcZ5wYtQprU7mJXGIPoCGvdNuSzwM1Hcgmey8mp7HLXTQP1EXrogzSoGkTdZomfz0wnrB8WkLT5wDg3eb1lhYbih9SwupTrakAQG9LdBAWEldO_GzX1JW6zI51tZIUlWjyNhNrWJtyYNAYSSbc9dY4qN5ffNd0vhVlMB5DWD6v-ztaPASG3776e_mfgYsCEd_1PsrW3CbuVY-m5fva2qi0ar1Hye5ZSrE267ND_2CIvjqnEjDKji3S3PepTlbPv1_VGzRrra9QpuJKVKxefeoNGwZ-U8jDeJCErfFdOFJaXJ94McnO0IWc6aoEQf3stzqTEsx_T9MIP6n8TGx-w0xG-WJIVu_P1nb5Ybva8F8oqgtZwhuTGnin3ErSlHAn8HpdJ3-2T0BMuvf8ITfBgdSvS_aMJTPfPp3M8K0O-LN-6fGDZc-brKv_i7s-VQZj6w6D-EJ9xwGbXwxOk7mkyIAseUS-SEXNxG1OcC4QT-e47ncyq2C_KzR3-5spdzCg0FdxvqDuBhj8G2rd-LeElXohmITmJ3Ee_VafaFiYGcRzJdr6wfgF-LJoGNr8GMDxcEH9tIAZwDn6f3BearErgn8EJFrNhMDcallTWQX1AoPlCEhaJBB0RB5L0grAqOqkhM5XqrqzYBUIiIP3Cs1LQSmy2Ai2z6iOaKfyOU_rNXq_jhGmvr9u9PBYjnZhnnOoSVmNp8PkGdb8pLrL_LzMuHundTFOZUsbz3tgyqKzh8dae-Yf6D5u_byCUyMscnLL9Q520NfWnXtHVYJCWZOeU9F693MFUUE4aOuEZFfSk998QTSEFf-TagC7vP2rH4Zpux0sCM2hqxjOOvZEyg3Ef8FsBvg9srRIIb_L5mpVa0jasTyqfyDVECxZO4YiqZW5CWPWLDfgT2MkYPOT8VclhZ5ZyJIKu7ZamNGriSZBhHjKQi2g0ap9A75qnyrdq-hEJZo4gqKmUou9f3fQAzT3sCPj1i3PEWVmHQvlt5vbDTqmBBxyLcgSkd0oNrpI-So2jf94syvImh_5OKexCdde5Fj91o8.5_KKK0EuQwEA5tjlpxaRzA";

async fn get_aws_config_extension() -> Extension<aws_config::SdkConfig> {
    // Required to load default AWS Config variables
    dotenvy::from_filename(".env.example").unwrap();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    let aws_config = aws_config
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build();

    reset_apple_keys_table(&aws_config).await;

    Extension(aws_config)
}

async fn reset_apple_keys_table(aws_config: &aws_config::SdkConfig) {
    let client = aws_sdk_dynamodb::Client::new(aws_config);

    // NOTE: We opt for manual deletion of specific records to avoid an additional table scan
    let result = client
        .delete_item()
        .table_name("attestation-gateway-apple-keys")
        .key(
            "key_id",
            aws_sdk_dynamodb::types::AttributeValue::S(
                "key#3tHEioTHHrX5wmvAiP/WTAjGRlwLNfoOiL7E7U8VmFQ=".to_string(),
            ),
        )
        .send()
        .await;

    result.unwrap();
}

fn get_global_config_extension() -> Extension<attestation_gateway::utils::GlobalConfig> {
    let config = attestation_gateway::utils::GlobalConfig {
        output_token_kms_key_arn:
            "arn:aws:kms:us-east-1:000000000000:key/c7956b9c-5235-4e8e-bb35-7310fb80f4ca"
                .to_string(),
        android_outer_jwe_private_key: "7d5b44298bf959af149a0086d79334e6".to_string(),
        apple_keys_dynamo_table_name: "attestation-gateway-apple-keys".to_string(),
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
        .layer(get_aws_config_extension().await)
        .layer(get_global_config_extension())
        .layer(get_redis_extension().await)
}

#[tokio::test]
async fn test_android_e2e_success() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(VALID_INTEGRITY_TOKEN.to_string()),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
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

    // FIXME: Verify the token
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
async fn test_android_token_generation_with_invalid_attributes() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "code": "bad_request",
            "details": "`integrity_token` is required for this bundle identifier."
        })
    );
}

#[tokio::test]
async fn test_token_generation_fails_on_duplicate_request_hash() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(VALID_INTEGRITY_TOKEN.to_string()),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
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
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["code"], "duplicate_request_hash");
    assert_eq!(body["details"], "The `request_hash` has already been used.");
}

#[traced_test]
#[tokio::test]
async fn test_server_error_is_properly_logged() {
    // Override global config to use an invalid JWE private key which will cause a server error
    fn get_local_config_extension() -> Extension<attestation_gateway::utils::GlobalConfig> {
        let config = attestation_gateway::utils::GlobalConfig {
            output_token_kms_key_arn:
                "arn:aws:kms:us-east-1:000000000000:key/c7956b9c-5235-4e8e-bb35-7310fb80f4ca"
                    .to_string(),
            // This is not a valid AES-256 key
            android_outer_jwe_private_key: "invalid".to_string(),
            apple_keys_dynamo_table_name: "attestation-gateway-apple-keys".to_string(),
        };
        Extension(config)
    }

    async fn get_local_api_router() -> aide::axum::ApiRouter {
        attestation_gateway::routes::handler()
            .layer(get_aws_config_extension().await)
            .layer(get_local_config_extension())
            .layer(get_redis_extension().await)
    }

    let api_router = get_local_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(VALID_INTEGRITY_TOKEN.to_string()),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "test_server_error_is_properly_logged_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "code": "internal_server_error",
            "details": "Internal server error. Please try again."
        })
    );

    assert!(logs_contain("Error verifying Android or Apple integrity e=Invalid key format: The key size must be 32: 7"));
}

#[tokio::test]
async fn test_apple_initial_attestation_e2e_success() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "testhash".to_string(),
        client_error: None,
        apple_initial_attestation: Some("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".to_string()),
        apple_public_key: None,
        apple_assertion: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

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

    let response = response.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&response).unwrap();

    assert!(response["attestation_gateway_token"].is_string());

    // Verify the key was saved to Dynamo (retried 3 times)
    let client = aws_sdk_dynamodb::Client::new(&aws_config.0);
    let scan_result = client
        .scan()
        .table_name("attestation-gateway-apple-keys")
        .filter_expression("key_id = :key_id")
        .expression_attribute_values(
            ":key_id",
            aws_sdk_dynamodb::types::AttributeValue::S(
                "key#3tHEioTHHrX5wmvAiP/WTAjGRlwLNfoOiL7E7U8VmFQ=".to_string(),
            ),
        )
        .send()
        .await
        .unwrap();

    let items = scan_result.items.unwrap_or_default();

    if items.is_empty() {
        panic!("Key was not saved to Dynamo");
    }

    let item = &items[0];

    assert_eq!(item.get("public_key").unwrap().as_s().unwrap(), "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHB6lDlPsxyNES6JSYM+w5rIxF5nPeN19dwNlSLYGU9LFx5kYOKeajWrsEPT3laf1UL07S0ANVG+2Hr5lCieiDw");
    assert_eq!(item.get("counter").unwrap().as_n().unwrap(), "0");
    assert_eq!(
        item.get("bundle_identifier").unwrap().as_s().unwrap(),
        "org.worldcoin.insight.staging"
    );

    // FIXME: Verify the token

    // SECTION: Test that the same public key cannot be verified as an initial attestation (we avoid another test to avoid duplicating the same calls)

    // Call this to flush Redis and avoid the duplicate request hash error which is not what we are testing here
    let _ = get_redis_extension().await;

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
    let response = response.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        response,
        json!({
            "code": "invalid_initial_attestation",
            "details": "This public key has already gone through initial attestation. Use assertion instead."
        })
    );
}

#[tokio::test]
async fn test_apple_token_generation_with_invalid_attributes_for_initial_attestation() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: Some("ou000000000000000000".to_string()),
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = response.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        response,
        json!({
            "code": "bad_request",
            "details": "For initial attestations, `apple_assertion` and `apple_public_key` attributes are not allowed."
        })
    );
}

#[tokio::test]
async fn test_apple_token_generation_with_invalid_attributes_for_assertion() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "code": "bad_request",
            "details": "`apple_assertion` and `apple_public_key` are required for this bundle identifier when `apple_initial_attestation` is not provided."
        })
    );
}
