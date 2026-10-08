//! Integration tests for the WIP-106 `/aat` route and the Authenticator Metadata endpoint.
//! Requires the services in `tests/docker-compose.test.yml`.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use attestation_gateway::{
    aat_issuer::AatIssuer,
    apple,
    utils::{AndroidResponseKeys, BundleIdentifier, GlobalConfig},
};
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    Extension,
    body::Body,
    http::{self, Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use eddsa_babyjubjub::EdDSAPrivateKey;
use http_body_util::BodyExt;
use josekit::{
    jwe::{A256KW, JweContext, JweHeader},
    jws::{ES256, JwsHeader},
    jwt::{self, JwtPayload},
};
use openssl::{pkey::Private, sha::Sha256};
use serde_bytes::ByteBuf;
use serde_json::{Value, json};
use serial_test::serial;
use tower::ServiceExt;
use world_id_primitives::{
    FieldElement,
    authenticator_assertion::{SignedAuthenticatorAssertionToken, UserPresence},
};

static APPLE_KEYS_DYNAMO_TABLE_NAME: &str = "attestation-gateway-apple-keys";
static APPLE_KEY_ID: &str = "aat-integration-test-key";
/// `versionCode` in the generated Play Integrity token.
const ANDROID_VERSION_CODE: u32 = 25700;
const AAT_LIFETIME_SECS: u32 = 1200;

// SECTION --- setup ---

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn issuer_key() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([7u8; 32])
}

fn global_config() -> GlobalConfig {
    dotenvy::from_filename(".env.example").unwrap();
    GlobalConfig {
        android_default_keys: AndroidResponseKeys {
            outer_jwe_private_key: std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY").unwrap(),
            inner_jws_public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+D+pCqBGmautdPLe/D8ot+e0/EScv4MgiylljSWZUPzQU0npHMNTO8Z9meOTHa3rORO3c2s14gu+Wc5eKdvoHw==".to_string(),
        },
        android_world_app_keys: None,
        android_world_id_keys: None,
        apple_keys_dynamo_table_name: APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        enabled_bundle_identifiers: vec![
            BundleIdentifier::ComWorldcoinDev,
            BundleIdentifier::OrgWorldcoinInsightStaging,
        ],
        log_client_errors: false,
        kinesis_stream_arn: None,
        developer_inner_jwks_url: None,
        apple_root_ca_pem: include_bytes!("../src/apple/apple_app_attestation_root_ca.pem").to_vec(),
        aud_whitelist: vec![],
        jwt_issuer: "attestation.worldcoin.org".to_string(),
        developer_portal_base_url: None,
        aud_authorization_cache_ttl_secs: 60 * 60,
        token_exp_max_by_aud: std::collections::HashMap::new(),
    }
}

async fn aws_config() -> aws_config::SdkConfig {
    dotenvy::from_filename(".env.example").unwrap();
    aws_config::load_defaults(aws_config::BehaviorVersion::latest())
        .await
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build()
}

async fn redis() -> redis::aio::ConnectionManager {
    let client = redis::Client::open("redis://localhost").unwrap();
    redis::cmd("FLUSHALL")
        .exec(&mut client.get_connection().unwrap())
        .unwrap();
    redis::aio::ConnectionManager::new(client).await.unwrap()
}

async fn router(issuer: Option<AatIssuer>) -> aide::axum::ApiRouter {
    attestation_gateway::routes::handler()
        .layer(Extension(aws_config().await))
        .layer(Extension(global_config()))
        .layer(Extension(redis().await))
        .layer(Extension(issuer.map(Arc::new)))
}

/// An issuer whose key signs for the next day.
fn issuer() -> AatIssuer {
    let now = now();
    AatIssuer::new(
        issuer_key(),
        "test-provider".to_string(),
        now - 60,
        now + 24 * 60 * 60,
        AAT_LIFETIME_SECS,
    )
}

async fn post_aat(router: &aide::axum::ApiRouter, request: &Value) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/aat")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn commitment(n: u64) -> String {
    FieldElement::from(n).to_string()
}

/// The platform challenge, written out independently of the route:
/// `hex(SHA-256(aat_commitment || user_presence || build_version))`.
fn challenge(n: u64, user_presence: u8, build_version: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&FieldElement::from(n).to_be_bytes());
    hasher.update(&[user_presence]);
    hasher.update(&build_version.to_be_bytes());
    hex::encode(hasher.finish())
}

/// A Play Integrity token as Google would issue it for `nonce`.
fn play_integrity_token(nonce: &str) -> String {
    // Matches `inner_jws_public_key` in `global_config`.
    let verifier_private_key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFU28VNv+wsvcC0rR
5n05rAs2xRxfmbHzDjEQdQqvRSmhRANCAAT4P6kKoEaZq6108t78Pyi357T8RJy/
gyCLKWWNJZlQ/NBTSekcw1M7xn2Z45Mdres5E7dzazXiC75Zzl4p2+gf
-----END PRIVATE KEY-----";
    let payload = json!({
        "requestDetails": {
            "requestPackageName": "com.worldcoin.dev",
            "nonce": nonce,
            "timestampMillis": chrono::Utc::now().timestamp_millis().to_string(),
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": "com.worldcoin.dev",
            "certificateSha256Digest": ["6a6a1474b5cbbb2b1aa57e0bc3"],
            "versionCode": ANDROID_VERSION_CODE.to_string(),
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] },
        "accountDetails": { "appLicensingVerdict": "LICENSED" },
        "environmentDetails": { "appAccessRiskVerdict": { "appsDetected": ["KNOWN_INSTALLED"] } },
    });
    let Value::Object(map) = payload else {
        unreachable!()
    };
    let mut jws_header = JwsHeader::new();
    jws_header.set_algorithm("ES256");
    let signer = ES256.signer_from_pem(verifier_private_key).unwrap();
    let jws =
        jwt::encode_with_signer(&JwtPayload::from_map(map).unwrap(), &jws_header, &signer).unwrap();

    let encrypter = A256KW
        .encrypter_from_bytes(
            STANDARD
                .decode(std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY").unwrap())
                .unwrap(),
        )
        .unwrap();
    let mut jwe_header = JweHeader::new();
    jwe_header.set_algorithm("A256KW");
    jwe_header.set_content_encryption("A256GCM");
    JweContext::new()
        .serialize_compact(jws.as_bytes(), &jwe_header, &encrypter)
        .unwrap()
}

/// Registers a fresh App Attest key and returns it.
async fn register_apple_key() -> openssl::pkey::PKey<Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let sk =
        openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
    let aws_config = aws_config().await;
    aws_sdk_dynamodb::Client::new(&aws_config)
        .delete_item()
        .table_name(APPLE_KEYS_DYNAMO_TABLE_NAME)
        .key("key_id", AttributeValue::S(format!("key#{APPLE_KEY_ID}")))
        .send()
        .await
        .unwrap();
    apple::dynamo::insert_apple_public_key(
        &aws_config,
        &APPLE_KEYS_DYNAMO_TABLE_NAME.to_string(),
        BundleIdentifier::OrgWorldcoinInsightStaging,
        APPLE_KEY_ID.to_string(),
        STANDARD.encode(sk.public_key_to_der().unwrap()),
        "receipt".to_string(),
    )
    .await
    .unwrap();
    sk
}

/// An App Attest assertion over `challenge` with `counter`.
fn apple_assertion(challenge: &str, counter: u32, sk: &openssl::pkey::PKey<Private>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        BundleIdentifier::OrgWorldcoinInsightStaging
            .apple_app_id()
            .unwrap()
            .as_bytes(),
    );
    let mut authenticator_data = ByteBuf::new();
    authenticator_data.extend_from_slice(&hasher.finish());
    authenticator_data.extend_from_slice(&[0x00]);
    authenticator_data.extend_from_slice(&counter.to_be_bytes());

    let mut client_data_hash = Sha256::new();
    client_data_hash.update(challenge.as_bytes());
    let mut nonce = Sha256::new();
    nonce.update(&authenticator_data);
    nonce.update(&client_data_hash.finish());

    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), sk).unwrap();
    let signature = signer.sign_oneshot_to_vec(&nonce.finish()).unwrap();

    let mut encoded = Vec::new();
    ciborium::into_writer(
        &apple::Assertion {
            authenticator_data,
            signature: ByteBuf::from(signature),
        },
        &mut encoded,
    )
    .unwrap();
    STANDARD.encode(encoded)
}

fn android_request(n: u64, build_version: u32) -> Value {
    json!({
        "bundle_identifier": "com.worldcoin.dev",
        "aat_commitment": commitment(n),
        "build_version": build_version,
        "user_presence": 2,
        "integrity_token": play_integrity_token(&challenge(n, 2, build_version)),
    })
}

/// Decodes the AAT in a response and checks its signature against the issuer key.
fn decode_aat(body: &Value) -> SignedAuthenticatorAssertionToken {
    let cwt = URL_SAFE_NO_PAD
        .decode(body["aat"].as_str().unwrap())
        .unwrap();
    let aat = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();
    assert!(
        issuer_key()
            .public()
            .verify(*aat.token.message_hash(), &aat.signature)
    );
    aat
}

// SECTION --- tests ---

#[tokio::test]
#[serial]
async fn test_aat_android_success() {
    let router = router(Some(issuer())).await;
    let (status, body) = post_aat(&router, &android_request(1, ANDROID_VERSION_CODE)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let aat = decode_aat(&body);
    assert_eq!(aat.token.aat_commitment(), FieldElement::from(1u64));
    let flags = aat.token.sec_flags();
    assert_eq!((flags.platform(), flags.sec_level()), (4, 3));
    assert_eq!(flags.build_version(), ANDROID_VERSION_CODE);
    assert_eq!(flags.user_presence(), UserPresence::PresentVerified);
    let lifetime = u64::from(aat.token.exp()) - now();
    assert!(lifetime <= u64::from(AAT_LIFETIME_SECS) && lifetime > 0);
}

#[tokio::test]
#[serial]
async fn test_aat_apple_assertion_success() {
    let router = router(Some(issuer())).await;
    let sk = register_apple_key().await;
    let request = json!({
        "bundle_identifier": "org.worldcoin.insight.staging",
        "aat_commitment": commitment(2),
        "build_version": 41,
        "user_presence": 0,
        "apple_public_key": APPLE_KEY_ID,
        "apple_assertion": apple_assertion(&challenge(2, 0, 41), 1, &sk),
    });
    let (status, body) = post_aat(&router, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let flags = decode_aat(&body).token.sec_flags();
    assert_eq!((flags.platform(), flags.sec_level()), (2, 1));
    assert_eq!(flags.build_version(), 41);
}

#[tokio::test]
#[serial]
async fn test_aat_apple_rejects_changed_user_presence() {
    let router = router(Some(issuer())).await;
    let sk = register_apple_key().await;
    // The assertion covers `user_presence = 0`; the request claims `2`.
    let request = json!({
        "bundle_identifier": "org.worldcoin.insight.staging",
        "aat_commitment": commitment(3),
        "build_version": 41,
        "user_presence": 2,
        "apple_public_key": APPLE_KEY_ID,
        "apple_assertion": apple_assertion(&challenge(3, 0, 41), 1, &sk),
    });
    let (status, body) = post_aat(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "invalid_token");
}

#[tokio::test]
#[serial]
async fn test_aat_rejects_build_version_not_matching_play_integrity() {
    let router = router(Some(issuer())).await;
    let (status, body) = post_aat(&router, &android_request(4, ANDROID_VERSION_CODE + 1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "integrity_failed");
}

#[tokio::test]
#[serial]
async fn test_aat_commitment_is_signed_once_and_released_on_failure() {
    let router = router(Some(issuer())).await;

    // A failed request does not consume the commitment...
    let (status, _) = post_aat(&router, &android_request(5, ANDROID_VERSION_CODE + 1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = post_aat(&router, &android_request(5, ANDROID_VERSION_CODE)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // ...but a signed one does.
    let (status, body) = post_aat(&router, &android_request(5, ANDROID_VERSION_CODE)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "duplicate_request_hash");
}

#[tokio::test]
#[serial]
async fn test_aat_rejects_invalid_requests() {
    let router = router(Some(issuer())).await;

    let mut request = android_request(6, ANDROID_VERSION_CODE);
    request["aat_commitment"] = json!("0x01");
    let (status, _) = post_aat(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut request = android_request(6, ANDROID_VERSION_CODE);
    request["user_presence"] = json!(5);
    let (status, _) = post_aat(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut request = android_request(6, ANDROID_VERSION_CODE);
    request["apple_assertion"] = json!("both platforms");
    let (status, _) = post_aat(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_aat_routes_are_disabled_without_a_signing_key() {
    let router = router(None).await;
    let (status, _) = post_aat(&router, &android_request(7, ANDROID_VERSION_CODE)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/world-id-authenticator.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn test_authenticator_metadata() {
    let router = router(Some(issuer())).await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/world-id-authenticator.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(metadata["version"], 1);
    assert_eq!(metadata["provider_id"], "test-provider");
    let key = &metadata["authenticator_provider_keys"][0];
    assert_eq!(
        key["kid"],
        hex::encode(issuer_key().public().to_compressed_bytes().unwrap())
    );
    assert_eq!(key["status"], "active");
}
