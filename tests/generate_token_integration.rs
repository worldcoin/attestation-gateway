use std::sync::{Arc, Mutex};

use attestation_gateway::{
    apple,
    keys::fetch_active_key,
    utils::{BundleIdentifier, TokenGenerationRequest},
};
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Extension,
};
use base64::Engine;
use http_body_util::BodyExt;
use josekit::{
    jwe::{JweContext, JweHeader, A256KW},
    jws::{JwsHeader, ES256},
    jwt::{self, JwtPayload},
};
use openssl::{pkey::Private, sha::Sha256};
use serde_bytes::ByteBuf;
use serde_json::{json, Value};
use serial_test::serial;
use tokio::task;
use tower::ServiceExt; // for `response.collect`
use tracing::Instrument;
use tracing_test::traced_test;

static APPLE_KEYS_DYNAMO_TABLE_NAME: &str = "attestation-gateway-apple-keys";

// These keys need to be replaced if the test attestation is updated
static TEST_VALID_ATTESTATION: &str = "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";
static TEST_ATTESTATION_KEY_ID: &str = "us1sMB71A6ffTbD5UdkeevxwPIFyFEuI3vNc8R/jiBw=";
static TEST_ATTESTATION_RAW_PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu5PyE6mg2JOA19zIosBmv/18/3B5ySWGLET7mQhWijPWWtKPEjdfDME7djEYaT81tvWoXXm95qfBYZw3Q2YDmQ==";
static TEST_VALID_ASSERTION: &str = "omlzaWduYXR1cmVYSDBGAiEA0Qs8Xf23WStR6ZhWteHd6sS6YQ14VgDrC4+8vrakNFMCIQCl8CZ2iqpujjgbWxO7vadwCy3WSSB09Mi9X3tp+97ZrHFhdXRoZW50aWNhdG9yRGF0YVgl0lgIg/cWKQldEqyGUrhbrxBv4j/WaJlzkB6N9Dmg63VAAAAAAQ==";
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
        kinesis_stream_name: None,
        kinesis_stream_arn: None,
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
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
}

#[tokio::test]
#[serial]
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
#[serial]
async fn test_token_generation_fails_on_disabled_bundle_identifier() {
    let api_router = get_api_router().await;

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "toolsforhumanity.com".to_string(),
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
        body["details"],
        "This bundle identifier is currently unavailable.".to_string()
    );
}

#[tokio::test]
#[serial]
async fn test_android_token_generation_with_invalid_attributes() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
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
#[serial]
async fn test_token_generation_fails_on_duplicate_request_hash() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: Some(helper_generate_valid_token()),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
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
            aud: "toolsforhumanity.com".to_string(),
            bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
            request_hash: "i_am_a_sample_request_hash".to_string(), // note we use the same request hash for all requests
            client_error: None,
            apple_initial_attestation: None,
            apple_public_key: None,
            apple_assertion: None,
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
        apple_assertion: None,
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
    assert_eq!(body["code"], "integrity_failed");

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
            kinesis_stream_name: None,
            kinesis_stream_arn: None,
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

    assert!(logs_contain("Error verifying Android or Apple integrity error=Invalid key format: The key size must be 32: 7"));
}

// SECTION --- apple initial attestation tests ---

#[tokio::test]
#[serial]
async fn test_apple_initial_attestation_e2e_success() {
    let api_router = get_api_router().await;

    let aws_config = get_aws_config_extension().await;
    let mut redis = get_redis_extension().await.0;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "02072cdf5e347d876a89949e6c11febb55716e3e7026e76b7d90d0bed6cf28e9"
            .to_string(),
        client_error: None,
        apple_initial_attestation: Some(TEST_VALID_ATTESTATION.to_string()),
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
            "code": "invalid_initial_attestation",
            "details": "This public key has already gone through initial attestation. Use assertion instead."
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_invalid_attributes_for_initial_attestation() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some("not_even_base64".to_string()),
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
            "code": "invalid_token",
            "details": "The provided token or attestation is invalid or malformed."
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        // Valid base64 but invalid CBOR message
        apple_assertion: Some("aW52YWxpZA".to_string()),
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
            "code": "invalid_token",
            "details": "The provided token or attestation is invalid or malformed."
        })
    );
}

#[tokio::test]
#[serial]
async fn test_apple_token_generation_with_invalid_attributes_for_assertion() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
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

#[tokio::test]
#[serial]
async fn test_apple_token_generation_assertion_with_an_invalid_key_id() {
    let api_router = get_api_router().await;

    let token_generation_request = TokenGenerationRequest {
        integrity_token: None,
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: "i_am_a_sample_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some("0x00000000000000000000000000000000".to_string()),
        apple_assertion: Some("0x00000000000000000000000000000000".to_string()),
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
            "code": "invalid_public_key",
            "details": "Public key has not been attested."
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: "testhash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(invalid_assertion.to_string()),
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
            "code": "invalid_token",
            "details": "The provided token or attestation is invalid or malformed."
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
        aud: "toolsforhumanity.com".to_string(),
        // Notice the bundle identifier is different
        bundle_identifier: BundleIdentifier::IOSProdWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
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
            "code": "invalid_attestation_for_app",
            "details": "The provided attestation is not valid for this app. Verify the provided bundle identifier is correct for this attestation object."
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
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::IOSStageWorldApp,
        request_hash: TEST_REQUEST_HASH.to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
        apple_assertion: Some(TEST_VALID_ASSERTION.to_string()),
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
            "code": "expired_token",
            "details": "The integrity token has expired. Please generate a new one."
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
            aud: "toolsforhumanity.com".to_string(),
            bundle_identifier: BundleIdentifier::IOSStageWorldApp,
            request_hash: format!("testhash-{i}"),
            client_error: None,
            apple_initial_attestation: None,
            apple_public_key: Some(TEST_ATTESTATION_KEY_ID.to_string()),
            apple_assertion: Some(assertion.to_string()),
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
                        response["code"].as_str().unwrap().to_string()
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
