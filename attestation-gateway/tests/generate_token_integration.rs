use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use attestation_gateway::{
    apple,
    keys::fetch_active_key,
    utils::{BundleIdentifier, DataReport, TokenGenerationRequest},
};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kinesis::types::ShardIteratorType;
use axum::{
    Extension,
    body::Body,
    http::{self, Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use josekit::{
    jwe::{A256KW, JweContext, JweHeader},
    jws::{ES256, JwsHeader},
    jwt::{self, JwtPayload},
};
use openssl::{pkey::Private, sha::Sha256};
use regex::Regex;
use serde_bytes::ByteBuf;
use serde_json::{Value, json};
use serial_test::serial;
use tokio::{sync::OnceCell, task};
use tower::ServiceExt; // for `response.collect`
use tracing::Instrument;
use tracing_test::traced_test;

static APPLE_KEYS_DYNAMO_TABLE_NAME: &str = "attestation-gateway-apple-keys";

// These keys need to be replaced if the test attestation is updated
static TEST_VALID_ATTESTATION: &str = "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";
static TEST_ATTESTATION_KEY_ID: &str = "QSMxLJmAOdfSiCfgSr0jj3dqSCrVf9MVbxbOH6y8cDI=";
static TEST_ATTESTATION_RAW_PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoEd2NgBRXwJZTRe+bIw4RmEf9MhNpOm3CAQztk+5jbMyOXL7IKok08+blp9KtwDRqjLEus9zgQzqcFvHSHvVTw==";
static TEST_VALID_ASSERTION: &str = "omlzaWduYXR1cmVYRjBEAiBX7NktwvtyY2f3Jt8IpoATgI6Zxu3jjFk2foIrAtJmkAIga3yByVSHE2jLqihyECe5PDIdrwTtcd/nuMCboSBuvD5xYXV0aGVudGljYXRvckRhdGFYJdJYCIP3FikJXRKshlK4W68Qb+I/1miZc5AejfQ5oOt1QAAAAAE=";
static TEST_REQUEST_HASH: &str = "02072cdf5e347d876a89949e6c11febb55716e3e7026e76b7d90d0bed6cf28e9";

// SECTION --- setup & config ---

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
        .table_name(APPLE_KEYS_DYNAMO_TABLE_NAME)
        .key(
            "key_id",
            aws_sdk_dynamodb::types::AttributeValue::S(format!("key#{TEST_ATTESTATION_KEY_ID}")),
        )
        .send()
        .await;

    result.unwrap();
}

fn get_global_config_extension() -> Extension<attestation_gateway::utils::GlobalConfig> {
    // Required to load default env vars
    dotenvy::from_filename(".env.example").unwrap();
    let config = attestation_gateway::utils::GlobalConfig {
        android_outer_jwe_private_key: std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY").expect("`ANDROID_OUTER_JWE_PRIVATE_KEY` must be set for tests."),
        android_inner_jws_public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+D+pCqBGmautdPLe/D8ot+e0/EScv4MgiylljSWZUPzQU0npHMNTO8Z9meOTHa3rORO3c2s14gu+Wc5eKdvoHw==".to_string(),
        apple_keys_dynamo_table_name: APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        enabled_bundle_identifiers: vec![BundleIdentifier::AndroidStageWorldApp, BundleIdentifier::AndroidDevWorldApp, BundleIdentifier::IOSStageWorldApp, BundleIdentifier::IOSProdWorldApp],
        log_client_errors: false,
        kinesis_stream_arn: Some("arn:aws:kinesis:us-west-1:000000000000:stream/attestation-gateway-data-reports".to_string()),
        developer_inner_jwks_url: std::env::var("DEVELOPER_INNER_JWKS_URL").ok(),
    };
    Extension(config)
}

async fn get_redis_extension() -> Extension<redis::aio::ConnectionManager> {
    let client = redis::Client::open("redis://localhost").unwrap();
    // Reset Redis before each test run
    redis::cmd("FlUSHALL")
        .exec(&mut client.clone().get_connection().unwrap())
        .unwrap();

    Extension(redis::aio::ConnectionManager::new(client).await.unwrap())
}

async fn get_kinesis_extension() -> Extension<aws_sdk_kinesis::Client> {
    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let aws_config = aws_config
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build();
    let kinesis_client = aws_sdk_kinesis::Client::new(&aws_config);
    Extension(kinesis_client)
}

async fn get_api_router() -> aide::axum::ApiRouter {
    attestation_gateway::routes::handler()
        .layer(get_aws_config_extension().await)
        .layer(get_global_config_extension())
        .layer(get_redis_extension().await)
        .layer(get_kinesis_extension().await)
}

/// Generates a valid Android integrity token (simulating what Play Store would generate)
/// We need to generate this dynamically because of the timestamp
fn helper_generate_valid_token() -> String {
    // This is the corresponding private key to the public key we use in tests
    let verifier_private_key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFU28VNv+wsvcC0rR
5n05rAs2xRxfmbHzDjEQdQqvRSmhRANCAAT4P6kKoEaZq6108t78Pyi357T8RJy/
gyCLKWWNJZlQ/NBTSekcw1M7xn2Z45Mdres5E7dzazXiC75Zzl4p2+gf
-----END PRIVATE KEY-----";

    let token_payload_str = r#"
    {
        "requestDetails": {
            "requestPackageName": "com.worldcoin.dev",
            "nonce": "i_am_a_sample_request_hash",
            "timestampMillis": {timestamp}
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": "com.worldcoin.dev",
            "certificateSha256Digest": [
                "6a6a1474b5cbbb2b1aa57e0bc3"
            ],
            "versionCode": "25700"
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": [
                "MEETS_DEVICE_INTEGRITY"
            ]
        },
        "accountDetails": {
            "appLicensingVerdict": "LICENSED"
        },
        "environmentDetails": {
            "appAccessRiskVerdict": {
                "appsDetected": [
                    "KNOWN_INSTALLED",
                    "UNKNOWN_INSTALLED",
                    "UNKNOWN_CAPTURING"
                ]
            }
        }
    }"#;
    let token_payload_str = token_payload_str.replace(
        "{timestamp}",
        chrono::Utc::now().timestamp_millis().to_string().as_str(),
    );

    let token_payload: Value = serde_json::from_str(token_payload_str.as_str()).unwrap();

    let json_map: serde_json::Map<String, Value> = match token_payload {
        Value::Object(map) => map.into_iter().collect(),
        _ => panic!("Unexpected value"),
    };

    let payload = JwtPayload::from_map(json_map).unwrap();
    let mut headers = JwsHeader::new();
    headers.set_algorithm("ES256");

    // Sign the inner JWS
    let signer = ES256.signer_from_pem(verifier_private_key).unwrap();
    let jws = jwt::encode_with_signer(&payload, &headers, &signer).unwrap();

    // Encrypt the JWE
    let encrypter = A256KW
        .encrypter_from_bytes(
            base64::engine::general_purpose::STANDARD
                .decode(
                    std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY")
                        .expect("`ANDROID_OUTER_JWE_PRIVATE_KEY` must be set for tests."),
                )
                .expect("Improperly encoded `ANDROID_OUTER_JWE_PRIVATE_KEY`."),
        )
        .unwrap();
    let mut headers = JweHeader::new();
    headers.set_algorithm("A256KW");
    headers.set_content_encryption("A256GCM");

    let context = JweContext::new();
    let jwe = context
        .serialize_compact(jws.as_bytes(), &headers, &encrypter)
        .unwrap();

    jwe
}

// SECTION ------------------ android tests ------------------

#[tokio::test]
#[serial]
async fn test_android_e2e_success() {
    let api_router = get_api_router().await;
    let mut redis = get_redis_extension().await.0;
    let aws_config = get_aws_config_extension().await.0;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(helper_generate_valid_token()),
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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

    let token: &str = body["attestation_gateway_token"].as_str().unwrap();

    let headers = josekit::jwt::decode_header(token).unwrap();

    assert_eq!(
        headers.claim("typ"),
        Some(&josekit::Value::String("JWT".to_string()))
    );
    assert_eq!(
        headers.claim("alg"),
        Some(&josekit::Value::String("ES256".to_string()))
    );

    let kid = headers.claim("kid").unwrap().as_str().unwrap();

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // active key should match the key used to sign the token
    assert_eq!(key.key_definition.id, kid);

    let verifier = josekit::jws::ES256.verifier_from_jwk(&key.jwk).unwrap();
    let (payload, _header) = josekit::jwt::decode_with_verifier(token, &verifier).unwrap();

    assert_eq!(payload.claim("pass"), Some(&josekit::Value::Bool(true)));
    assert_eq!(
        payload.claim("out"),
        Some(&josekit::Value::String("pass".to_string()))
    );

    assert_eq!(
        payload.claim("app_version"),
        Some(&josekit::Value::String("25700".to_string()))
    );
}

#[tokio::test]
#[serial]
async fn test_token_generation_fails_on_invalid_bundle_identifier() {
    let api_router = get_api_router().await;

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "relying-party.example.com".to_string(),
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
#[serial]
async fn test_token_generation_fails_on_disabled_bundle_identifier() {
    let api_router = get_api_router().await;

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "relying-party.example.com".to_string(),
        "bundle_identifier": "com.worldcoin".to_string(), // see get_global_config_extension where this identifier is currently disabled
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
        body["error"]["message"],
        "This bundle identifier is currently unavailable.".to_string()
    );
}

#[tokio::test]
#[serial]
async fn test_android_token_generation_with_invalid_attributes() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "code": "bad_request",
                "message": "`integrity_token` is required for this bundle identifier."
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_token_generation_fails_on_duplicate_request_hash() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(helper_generate_valid_token()),
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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

    assert_eq!(body["error"]["code"], "duplicate_request_hash");
    assert_eq!(
        body["error"]["message"],
        "The `request_hash` has already been used."
    );
}

#[tokio::test]
#[serial]
/// Asserts that there is no race condition when the same request hash is used multiple times at the same time
async fn test_request_hash_race_condition() {
    let api_router_base = get_api_router().await;

    let num_calls = 10;
    let mut handles = vec![];
    let output_mutex = Arc::new(Mutex::new(vec![]));

    for i in 0..num_calls {
        let output_mutex = Arc::clone(&output_mutex);

        let api_router = api_router_base.clone();
        let span = tracing::span!(tracing::Level::INFO, "generate_token", task_id = i);

        let token_generation_request = TokenGenerationRequest {
            integrity_token: Some(helper_generate_valid_token()),
            aud: "relying-party.example.com".to_string(),
            bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
            request_hash: "i_am_a_sample_request_hash".to_string(), // note we use the same request hash for all requests
            client_error: None,
            apple_initial_attestation: None,
            apple_public_key: None,
            apple_assertion: None,
            developer_token: None,
        };

        let handle = task::spawn(
            async move {
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
                let mut outputs = output_mutex.lock().unwrap();
                outputs.push(response.status());
            }
            .instrument(span),
        );

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let status_codes = {
        let outputs = output_mutex.lock().unwrap();
        outputs.clone()
    };

    let count_200 = status_codes
        .iter()
        .filter(|&&code| code == StatusCode::OK)
        .count();
    assert_eq!(count_200, 1);
    let count_409 = status_codes
        .iter()
        .filter(|&&code| code == StatusCode::CONFLICT)
        .count();
    assert_eq!(count_409, num_calls - 1);
}

#[tokio::test]
#[serial]
async fn test_request_hash_is_released_if_request_fails() {
    let api_router = get_api_router().await;

    let mut token_generation_request = TokenGenerationRequest {
        integrity_token: Some(helper_generate_valid_token()),
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

    // First request fails (from integrity checks)
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
    assert_eq!(body["error"]["code"], "integrity_failed");

    // Subsequent request succeeds (request hash is freed up)
    token_generation_request.bundle_identifier = BundleIdentifier::AndroidDevWorldApp;
    let body = serde_json::to_string(&token_generation_request).unwrap();
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
    assert_eq!(response.status(), StatusCode::OK);
}

#[traced_test]
#[tokio::test]
#[serial]
async fn test_server_error_is_properly_logged() {
    // Override global config to use an invalid JWE private key which will cause a server error
    fn get_local_config_extension() -> Extension<attestation_gateway::utils::GlobalConfig> {
        let config = attestation_gateway::utils::GlobalConfig {
            // This is not a valid AES-256 key
            android_outer_jwe_private_key: base64::engine::general_purpose::STANDARD
                .encode("invalid"),
            android_inner_jws_public_key: "irrelevant".to_string(),
            apple_keys_dynamo_table_name: APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
            enabled_bundle_identifiers: vec![BundleIdentifier::AndroidDevWorldApp],
            log_client_errors: false,
            kinesis_stream_arn: None,
            developer_inner_jwks_url: None,
        };
        Extension(config)
    }

    async fn get_local_api_router() -> aide::axum::ApiRouter {
        attestation_gateway::routes::handler()
            .layer(get_aws_config_extension().await)
            .layer(get_local_config_extension())
            .layer(get_redis_extension().await)
            .layer(get_kinesis_extension().await)
    }

    let api_router = get_local_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(helper_generate_valid_token()),
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "test_server_error_is_properly_logged_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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
            "allowRetry": true,
            "error": {
                "message": "Internal server error. Please try again.",
                "code": "internal_server_error"
            },
        })
    );

    assert!(logs_contain(
        "Error verifying Android or Apple integrity error=Invalid key format: The key size must be 32: 7"
    ));
}
// !SECTION ------------------ android tests ------------------

// SECTION --- apple initial attestation tests ---

#[tokio::test]
#[serial]
async fn test_apple_initial_attestation_e2e_success() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;
    let mut redis = get_redis_extension().await.0;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "02072cdf5e347d876a89949e6c11febb55716e3e7026e76b7d90d0bed6cf28e9"
            .to_string(),
        client_error: None,
        apple_initial_attestation: Some(TEST_VALID_ATTESTATION.to_string()),
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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
    let token = response["attestation_gateway_token"].as_str().unwrap();

    // Verify the key was saved to Dynamo
    let client = aws_sdk_dynamodb::Client::new(&aws_config.0);
    let get_item_result = client
        .get_item()
        .table_name(APPLE_KEYS_DYNAMO_TABLE_NAME.to_string())
        .key(
            "key_id",
            aws_sdk_dynamodb::types::AttributeValue::S(format!("key#{TEST_ATTESTATION_KEY_ID}")),
        )
        .send()
        .await
        .unwrap();

    let item = get_item_result.item.unwrap();

    assert_eq!(
        item.get("public_key").unwrap().as_s().unwrap(),
        TEST_ATTESTATION_RAW_PUBLIC_KEY
    );
    assert_eq!(item.get("key_counter").unwrap().as_n().unwrap(), "0");
    assert_eq!(
        item.get("bundle_identifier").unwrap().as_s().unwrap(),
        "org.worldcoin.insight.staging"
    );

    let headers = josekit::jwt::decode_header(token).unwrap();

    assert_eq!(
        headers.claim("typ"),
        Some(&josekit::Value::String("JWT".to_string()))
    );
    assert_eq!(
        headers.claim("alg"),
        Some(&josekit::Value::String("ES256".to_string()))
    );

    let kid = headers.claim("kid").unwrap().as_str().unwrap();

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // active key should match the key used to sign the token
    assert_eq!(key.key_definition.id, kid);

    let verifier = josekit::jws::ES256.verifier_from_jwk(&key.jwk).unwrap();
    let (payload, _header) = josekit::jwt::decode_with_verifier(token, &verifier).unwrap();

    assert_eq!(payload.claim("pass"), Some(&josekit::Value::Bool(true)));
    assert_eq!(
        payload.claim("out"),
        Some(&josekit::Value::String("pass".to_string()))
    );

    // ANCHOR: Test that the same public key cannot be verified as an initial attestation (we avoid another test to avoid duplicating the same calls)

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
            "allowRetry": false,
            "error": {
                "code": "invalid_initial_attestation",
                "message": "This public key has already gone through initial attestation. Use assertion instead."
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_invalid_attributes_for_initial_attestation() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: Some("ou000000000000000000".to_string()),
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: None,
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "For initial attestations, `apple_assertion` and `apple_public_key` attributes are not allowed.",
                "code": "bad_request"
            }
        })
    );
}
// !SECTION ------------------ apple initial attestation tests ------------------

// SECTION --- apple assertions tests ---

#[tokio::test]
#[serial]
async fn test_apple_assertion_e2e_success() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;
    let mut redis = get_redis_extension().await.0;

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        // public key can also be retrieved from the assertion
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
        developer_token: None,
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

    let token = response["attestation_gateway_token"].as_str().unwrap();

    let headers = josekit::jwt::decode_header(token).unwrap();

    assert_eq!(
        headers.claim("typ"),
        Some(&josekit::Value::String("JWT".to_string()))
    );
    assert_eq!(
        headers.claim("alg"),
        Some(&josekit::Value::String("ES256".to_string()))
    );

    let kid = headers.claim("kid").unwrap().as_str().unwrap();

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // active key should match the key used to sign the token
    assert_eq!(key.key_definition.id, kid);

    let verifier = josekit::jws::ES256.verifier_from_jwk(&key.jwk).unwrap();
    let (payload, _header) = josekit::jwt::decode_with_verifier(token, &verifier).unwrap();

    assert_eq!(payload.claim("pass"), Some(&josekit::Value::Bool(true)));
    assert_eq!(
        payload.claim("out"),
        Some(&josekit::Value::String("pass".to_string()))
    );

    // Verify the key counter was updated in Dynamo

    let key = apple::dynamo::fetch_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        TEST_ATTESTATION_KEY_ID.to_string(),
    )
    .await
    .unwrap();

    assert_eq!(key.counter, 1);
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_an_invalid_base_64_assertion_generates_a_client_error() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        // public key can also be retrieved from the assertion
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some("not_even_base64".to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "The provided token or attestation is invalid or malformed.",
                "code": "invalid_token"
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_an_invalid_assertion_generates_a_client_error() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        // public key can also be retrieved from the assertion
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        // Valid base64 but invalid CBOR message
        apple_assertion: Some("aW52YWxpZA".to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "The provided token or attestation is invalid or malformed.",
                "code": "invalid_token"
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_invalid_attributes_for_assertion() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: None,
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "code": "bad_request",
                "message": "`apple_assertion` and `apple_public_key` are required for this bundle identifier when `apple_initial_attestation` is not provided."
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_assertion_with_an_invalid_key_id() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: Some("0x00000000000000000000000000000000".to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "code": "invalid_public_key",
                "message": "Public key has not been attested."
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_assertion_with_an_invalidly_signed_assertion() {
    // This assertion can be obtained from `verify_assertion_failure_with_invalid_key`
    let invalid_assertion = "omlzaWduYXR1cmVYRzBFAiAzg4lX/q4SMY/HZLegpV+1I5eUE1fRldlC4yloghLWsQIhAMSlrYPwou6WJ0JsiVCE00G2+ZCBphnyOO3imjI68yCccWF1dGhlbnRpY2F0b3JEYXRhWEt0aGlzX2lzX25vdF9hX3ZhbGlkX2F1dGhlbnRpY2F0b3JfZGF0YV9idXRfdmVyaWZpY2F0aW9uX3dpbGxfbm90X3JlYWNoX2hlcmU";
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        // public key can also be retrieved from the assertion
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "testhash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(invalid_assertion.to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "The provided token or attestation is invalid or malformed.",
                "code": "invalid_token"
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_assertion_with_an_invalid_key_bundle_identifier_pair() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSProdWorldApp, // <-- we also change this to test explicitly the `rp_id` check in the assertion
        TEST_ATTESTATION_KEY_ID.to_string(),
        // public key can also be retrieved from the assertion
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        // Notice the bundle identifier is different
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "The provided attestation is not valid for this app. Verify the provided bundle identifier is correct for this attestation object.",
                "code": "invalid_attestation_for_app"
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_invalid_counter() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;
    let client = aws_sdk_dynamodb::Client::new(&aws_config.0);

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        // this assertion has a `counter = 1`
        TEST_ATTESTATION_RAW_PUBLIC_KEY.to_string(),
        "receipt".to_string(),
    )
    .await
    .unwrap();

    // increase the counter beyond the current assertion
    client
        .update_item()
        .table_name(APPLE_KEYS_DYNAMO_TABLE_NAME)
        .key(
            "key_id",
            AttributeValue::S(format!("key#{TEST_ATTESTATION_KEY_ID}")),
        )
        .update_expression("SET key_counter = :new_counter")
        .expression_attribute_values(":new_counter", AttributeValue::N(2.to_string()))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await
        .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "message": "The integrity token has expired. Please generate a new one.",
                "code": "expired_token"
            },
        })
    );
}

fn helper_generate_valid_assertion(
    request_hash: String,
    sk: openssl::pkey::PKey<Private>,
) -> String {
    let counter: u32 = 1;

    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let hashed_nonce = hasher.finish();

    let mut authenticator_data: ByteBuf = ByteBuf::new();

    // 0 - 32 bytes
    let mut hasher = Sha256::new();
    hasher.update(
        BundleIdentifier::IOSStageWorldApp
            .apple_app_id()
            .unwrap()
            .as_bytes(),
    );
    let rp_id: &[u8] = &hasher.finish();
    authenticator_data.extend_from_slice(rp_id);

    authenticator_data.extend_from_slice(&[0x00]); // 32 - 33 bytes

    // 33 - 37 bytes
    authenticator_data.extend_from_slice(&counter.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&authenticator_data);
    hasher.update(&hashed_nonce);
    let nonce: &[u8] = &hasher.finish();

    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &sk).unwrap();
    let signature = signer.sign_oneshot_to_vec(nonce).unwrap();

    let assertion = apple::Assertion {
        authenticator_data,
        signature: ByteBuf::from(signature),
    };

    let mut encoded_assertion: Vec<u8> = Vec::new();

    ciborium::into_writer(&assertion, &mut encoded_assertion).unwrap();

    base64::engine::general_purpose::STANDARD.encode(encoded_assertion)
}

#[tokio::test]
#[serial]
/// Asserts that there is no race condition when the same counter in an Apple assertion is used multiple times at the same time
async fn test_apple_counter_race_condition() {
    // Generate a temp key
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let sk = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();

    let mut assertions: Vec<(u32, String)> = Vec::new();

    let num_calls = 5;

    for i in 0..num_calls {
        let assertion = helper_generate_valid_assertion(format!("testhash-{i}"), sk.clone());
        assertions.push((i as u32, assertion));
    }

    let api_router_base = get_api_router().await;

    let aws_config = get_aws_config_extension().await;

    let pk = base64::engine::general_purpose::STANDARD.encode(sk.public_key_to_der().unwrap());

    // Insert key into Dynamo first
    apple::dynamo::insert_apple_public_key(
        &aws_config.0,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::IOSStageWorldApp,
        TEST_ATTESTATION_KEY_ID.to_string(),
        pk,
        "receipt".to_string(),
    )
    .await
    .unwrap();

    let mut handles = vec![];
    let output_mutex = Arc::new(Mutex::new(vec![]));

    for (i, assertion) in assertions.iter() {
        let output_mutex = Arc::clone(&output_mutex);

        let api_router = api_router_base.clone();
        let span = tracing::span!(tracing::Level::INFO, "generate_token", task_id = i);

        let token_generation_request = TokenGenerationRequest {
            integrity_token: None,
            aud: "relying-party.example.com".to_string(),
            bundle_identifier: BundleIdentifier::IOSStageWorldApp,
            request_hash: format!("testhash-{i}"),
            client_error: None,
            apple_initial_attestation: None,
            apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
            apple_assertion: Some(assertion.to_string()),
            developer_token: None,
        };

        let handle = task::spawn(
            async move {
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
                let code = response.status();

                let output = match response.status() {
                    StatusCode::OK => "ok".to_string(),
                    StatusCode::BAD_REQUEST => {
                        let response = response.into_body().collect().await.unwrap().to_bytes();
                        let response: Value = serde_json::from_slice(&response).unwrap();
                        response["error"]["code"].as_str().unwrap().to_string()
                    }
                    _ => panic!("Unexpected status code: {:?}", code),
                };

                let mut outputs = output_mutex.lock().unwrap();
                outputs.push(output);
            }
            .instrument(span),
        );

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let response_codes = {
        let outputs = output_mutex.lock().unwrap();
        outputs.clone()
    };

    // only one success
    let count_ok = response_codes.iter().filter(|&code| code == "ok").count();
    assert_eq!(count_ok, 1);

    // rest is expired_tokens
    let count_expired = response_codes
        .iter()
        .filter(|&code| code == "expired_token")
        .count();
    assert_eq!(count_expired, num_calls - 1);
}

// !SECTION ------------------ apple assertions tests ------------------

// SECTION ------------------ developer assertion tests ------------------
use mockito;

fn get_jwk(key_id: &str) -> josekit::jwk::Jwk {
    let mut jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    jwk.set_key_id(key_id);
    jwk
}

fn generate_developer_certificate(
    client_public_key: &josekit::jwk::Jwk,
    developer_jwk: &josekit::jwk::Jwk,
    issuer: String,
) -> String {
    let mut header = josekit::jws::JwsHeader::new();
    header.set_token_type("JWT");
    header.set_key_id(developer_jwk.key_id().unwrap());

    let mut payload = josekit::jwt::JwtPayload::new();
    payload.set_expires_at(&(SystemTime::now() + Duration::from_secs(60)));
    payload.set_issued_at(&SystemTime::now());
    payload.set_issuer(issuer);
    payload.set_subject("foo.bar@relying-party.example.com");
    payload
        .set_claim(
            "publicKey",
            Some(josekit::Value::String(client_public_key.to_string())),
        )
        .unwrap();

    // Signing JWT
    let signer = ES256.signer_from_jwk(&developer_jwk).unwrap();
    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    jwt.to_string()
}

fn generate_client_token(
    client_jwk: &josekit::jwk::Jwk,
    developer_certificate: String,
    request_hash: &String,
) -> String {
    let mut header = josekit::jws::JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = josekit::jwt::JwtPayload::new();
    payload.set_expires_at(&(SystemTime::now() + Duration::from_secs(60)));
    payload.set_issued_at(&SystemTime::now());
    payload.set_jwt_id(request_hash);
    payload
        .set_claim(
            "certificate",
            Some(josekit::Value::String(developer_certificate.into())),
        )
        .unwrap();

    // Signing JWT
    let signer = ES256.signer_from_jwk(&client_jwk).unwrap();
    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    jwt.to_string()
}

// Start a lightweight mock server.
async fn get_mock_server(jwk: &josekit::jwk::Jwk) -> mockito::ServerGuard {
    let mut public_key = jwk.to_public_key().unwrap();
    // to_public_key() removes the key_id, so we need to set it again
    public_key.set_key_id(jwk.key_id().unwrap());
    let body = json!({
        "keys": [public_key]
    });

    let mut server = mockito::Server::new_async().await;

    server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_body(body.to_string())
        .create();

    server
}

struct TestEnvironment {
    client_jwk: josekit::jwk::Jwk,
    developer_jwk: josekit::jwk::Jwk,
    developer_server_base_url: String,
}

// Generate JWK only once because developer_VERIFIER in developer/mod.rs is a global once cell
static DEVELOPER_JWK: OnceCell<josekit::jwk::Jwk> = OnceCell::const_new();
static JWK_SERVER: OnceCell<mockito::ServerGuard> = OnceCell::const_new();

async fn initialize_developer_test_environment() -> TestEnvironment {
    let client_jwk = get_jwk("client");
    let developer_jwk = DEVELOPER_JWK
        .get_or_init(|| async { get_jwk("developer") })
        .await;
    let server = JWK_SERVER
        .get_or_init(|| async {
            let server = get_mock_server(&developer_jwk).await;
            let url = server.url() + "/.well-known/jwks.json";
            unsafe { std::env::set_var("DEVELOPER_INNER_JWKS_URL", url) };
            server
        })
        .await;

    TestEnvironment {
        client_jwk,
        developer_jwk: developer_jwk.clone(),
        developer_server_base_url: server.url(),
    }
}

#[tokio::test]
#[serial]
async fn test_developer_token_generation_e2e_success() {
    let TestEnvironment {
        client_jwk,
        developer_jwk,
        developer_server_base_url,
    } = initialize_developer_test_environment().await;

    let mut redis = get_redis_extension().await.0;
    let aws_config = get_aws_config_extension().await.0;
    let api_router = get_api_router().await;

    let request_hash = String::from("i_am_a_sample_request_hash");

    // Generate developer certificate
    let developer_certificate = generate_developer_certificate(
        &client_jwk.to_public_key().unwrap(),
        &developer_jwk,
        developer_server_base_url,
    );

    // Generate client token
    let generated_client_token =
        generate_client_token(&client_jwk, developer_certificate, &request_hash);

    // Generate token generation request
    let token_generation_request = TokenGenerationRequest {
        integrity_token: None, // note the missing token
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash,
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: Some(generated_client_token),
    };
    let body = serde_json::to_string(&token_generation_request).unwrap();

    // Make request
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

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    let token: &str = body["attestation_gateway_token"].as_str().unwrap();

    let headers = josekit::jwt::decode_header(token).unwrap();

    assert_eq!(
        headers.claim("typ"),
        Some(&josekit::Value::String("JWT".to_string()))
    );
    assert_eq!(
        headers.claim("alg"),
        Some(&josekit::Value::String("ES256".to_string()))
    );

    let kid = headers.claim("kid").unwrap().as_str().unwrap();

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // active key should match the key used to sign the token
    assert_eq!(key.key_definition.id, kid);

    let verifier = josekit::jws::ES256.verifier_from_jwk(&key.jwk).unwrap();
    let (payload, _header) = josekit::jwt::decode_with_verifier(token, &verifier).unwrap();

    assert_eq!(payload.claim("pass"), Some(&josekit::Value::Bool(true)));
    assert_eq!(
        payload.claim("out"),
        Some(&josekit::Value::String("pass".to_string()))
    );

    assert_eq!(payload.claim("app_version"), None);
}

#[tokio::test]
#[serial]
async fn test_developer_token_generation_e2e_request_hash_mismatch() {
    let TestEnvironment {
        client_jwk,
        developer_jwk,
        developer_server_base_url,
    } = initialize_developer_test_environment().await;

    let api_router = get_api_router().await;

    let expected_request_hash = String::from("i_am_a_sample_request_hash");
    let request_hash = String::from("wrong_request_hash");

    let developer_certificate = generate_developer_certificate(
        &client_jwk.to_public_key().unwrap(),
        &developer_jwk,
        developer_server_base_url,
    );
    let generated_client_token =
        generate_client_token(&client_jwk, developer_certificate, &request_hash);

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None, // note the missing token
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash: expected_request_hash.clone(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: Some(generated_client_token),
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
            "allowRetry": false,
            "error": {
                "code": "invalid_developer_token",
                "message": "The provided developer token is invalid or malformed."
            }
        })
    );
}

#[tokio::test]
#[serial]
async fn test_developer_token_generation_e2e_missing_token() {
    let TestEnvironment {
        client_jwk: _,
        developer_jwk: _,
        developer_server_base_url: _,
    } = initialize_developer_test_environment().await;

    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None, // note the missing token
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        // note the missing developer_token
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "code": "bad_request",
                "message": "`integrity_token` is required for this bundle identifier."
            }
        })
    );
}
// !SECTION ------------------ developer assertions tests ------------------

// SECTION --- general failure cases ---

#[tokio::test]
#[serial]
async fn test_client_error_gets_logged_to_kinesis() {
    let api_router = get_api_router().await;

    let kinesis_client = get_kinesis_extension().await;
    let kinesis_stream_arn =
        "arn:aws:kinesis:us-west-1:000000000000:stream/attestation-gateway-data-reports";

    let shard_id = kinesis_client
        .describe_stream()
        .stream_arn(kinesis_stream_arn)
        .send()
        .await
        .unwrap()
        .stream_description
        .unwrap()
        .shards[0]
        .shard_id
        .clone();

    let shard_iterator = kinesis_client
        .get_shard_iterator()
        .stream_arn(kinesis_stream_arn)
        .shard_id(shard_id)
        .shard_iterator_type(ShardIteratorType::Latest)
        .send()
        .await
        .unwrap()
        .shard_iterator
        .unwrap();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None, // note the missing token
        aud: "relying-party.example.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: Some("play_integrity_api_is_down".to_string()),
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
        developer_token: None,
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
            "allowRetry": false,
            "error": {
                "code": "integrity_failed",
                "message": "Integrity checks have not passed."
            }
        })
    );

    let response = kinesis_client
        .get_records()
        .shard_iterator(shard_iterator)
        .stream_arn(kinesis_stream_arn)
        .send()
        .await
        .unwrap();

    let record = response.records[0].clone();
    assert_eq!(record.partition_key, "id");
    let record_body = String::from_utf8(record.data.into_inner()).unwrap();

    let json_body = serde_json::from_str::<Value>(&record_body).unwrap();

    let re = Regex::new(r"^report_[0-9a-f]{32}$").unwrap();
    assert!(
        re.is_match(json_body["id"].as_str().unwrap()),
        "Kinesis DataReport.id format is incorrect"
    );

    let data_report: DataReport = serde_json::from_str(&record_body).unwrap();

    assert_eq!(
        data_report.client_error,
        Some("play_integrity_api_is_down".to_string())
    );
    assert!(!data_report.pass);
    assert_eq!(
        data_report.bundle_identifier,
        BundleIdentifier::AndroidStageWorldApp
    );
    assert_eq!(
        data_report.request_hash,
        "i_am_a_sample_request_hash".to_string()
    );
}

// !SECTION ------------------ general failure cases ------------------
