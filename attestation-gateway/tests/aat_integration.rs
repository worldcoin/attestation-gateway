//! Integration tests for the WIP-106 `/aat` route and the Authenticator Metadata endpoint.
//! Requires the services in `tests/docker-compose.test.yml`.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use attestation_gateway::{
    aat_issuer::{AatIssuer, IssueError, KeySchedule},
    aat_keys::AatKeyStore,
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
use eddsa_babyjubjub::EdDSAPublicKey;
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
    authenticator_assertion::{
        Platform, SecFlags, SecLevel, SignedAuthenticatorAssertionToken, UserPresence,
    },
};

static APPLE_KEYS_DYNAMO_TABLE_NAME: &str = "attestation-gateway-apple-keys";
static APPLE_KEY_ID: &str = "aat-integration-test-key";
/// Must match `tests/aws-seed.sh`.
static AAT_KEYS_TABLE: &str = "attestation-gateway-aat-keys";
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
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

/// One-day slots; slot 0 started an hour ago. Keys sign as soon as they are created, and the next
/// one is created two hours before its slot.
fn schedule(now: u64) -> KeySchedule {
    KeySchedule::new(now - HOUR, DAY, 0, 2 * HOUR, AAT_LIFETIME_SECS)
}

/// Start of slot 1 for `schedule(now)`.
const fn slot_1_start(now: u64) -> u64 {
    now - HOUR + DAY
}

/// A fresh KMS key that encrypts the stored secrets.
async fn kms_key(aws_config: &aws_config::SdkConfig) -> String {
    aws_sdk_kms::Client::new(aws_config)
        .create_key()
        .send()
        .await
        .unwrap()
        .key_metadata
        .unwrap()
        .arn
        .unwrap()
}

/// Empties the AAT keys table.
async fn reset_aat_keys(aws_config: &aws_config::SdkConfig) {
    let client = aws_sdk_dynamodb::Client::new(aws_config);
    for slot in stored_slots(aws_config).await {
        client
            .delete_item()
            .table_name(AAT_KEYS_TABLE)
            .key("slot", AttributeValue::S(slot))
            .send()
            .await
            .unwrap();
    }
}

async fn stored_slots(aws_config: &aws_config::SdkConfig) -> Vec<String> {
    let items = aws_sdk_dynamodb::Client::new(aws_config)
        .scan()
        .table_name(AAT_KEYS_TABLE)
        .send()
        .await
        .unwrap();
    let mut slots: Vec<String> = items
        .items()
        .iter()
        .map(|item| item["slot"].as_s().unwrap().clone())
        .collect();
    slots.sort();
    slots
}

async fn issuer_with(aws_config: &aws_config::SdkConfig, kms_key: String, now: u64) -> AatIssuer {
    let store = AatKeyStore::new(aws_config, AAT_KEYS_TABLE.to_string(), kms_key);
    AatIssuer::new(store, schedule(now), "test-provider".to_string(), now)
        .await
        .unwrap()
}

/// An issuer on an empty table, as on first start.
async fn issuer() -> AatIssuer {
    let aws_config = aws_config().await;
    reset_aat_keys(&aws_config).await;
    let kms_key = kms_key(&aws_config).await;
    issuer_with(&aws_config, kms_key, now()).await
}

fn flags() -> SecFlags {
    SecFlags::new(
        Platform::Ios.into(),
        SecLevel::HardwareKey.into(),
        41,
        0,
        UserPresence::Undetermined,
    )
    .unwrap()
}

/// The `kid` of the key that signs at `at`.
async fn signing_kid(issuer: &AatIssuer, at: u64) -> [u8; 32] {
    let cwt = issuer
        .keys(at)
        .await
        .issue(FieldElement::from(1u64), flags(), at)
        .unwrap();
    SignedAuthenticatorAssertionToken::decode(&cwt)
        .unwrap()
        .kid
        .unwrap()
}

async fn statuses(issuer: &AatIssuer, at: u64) -> Vec<&'static str> {
    issuer
        .keys(at)
        .await
        .metadata("test-provider", at)
        .unwrap()
        .authenticator_provider_keys
        .iter()
        .map(|k| k.status)
        .collect()
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

/// Decodes the AAT in a response and checks its signature against the key its `kid` names.
fn decode_aat(body: &Value) -> SignedAuthenticatorAssertionToken {
    let cwt = URL_SAFE_NO_PAD
        .decode(body["aat"].as_str().unwrap())
        .unwrap();
    let aat = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();
    let key = EdDSAPublicKey::from_compressed_bytes(aat.kid.unwrap()).unwrap();
    assert!(key.verify(*aat.token.message_hash(), &aat.signature));
    aat
}

// SECTION --- tests ---

#[tokio::test]
#[serial]
async fn test_aat_android_success() {
    let router = router(Some(issuer().await)).await;
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
    let router = router(Some(issuer().await)).await;
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
    let router = router(Some(issuer().await)).await;
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
    let router = router(Some(issuer().await)).await;
    let (status, body) = post_aat(&router, &android_request(4, ANDROID_VERSION_CODE + 1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "integrity_failed");
}

#[tokio::test]
#[serial]
async fn test_aat_commitment_is_signed_once_and_released_on_failure() {
    let router = router(Some(issuer().await)).await;

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
    let router = router(Some(issuer().await)).await;

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
    let router = router(Some(issuer().await)).await;
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
    let keys = metadata["authenticator_provider_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"].as_str().unwrap().len(), 64);
    assert_eq!(keys[0]["status"], "active");
}

#[tokio::test]
#[serial]
async fn test_first_start_creates_the_current_key() {
    let issuer = issuer().await;
    assert_eq!(stored_slots(&aws_config().await).await, ["slot#0"]);
    assert_eq!(statuses(&issuer, now()).await, ["active"]);
}

#[tokio::test]
#[serial]
async fn test_next_key_is_created_ahead_and_takes_over_at_the_boundary() {
    let now = now();
    let issuer = issuer().await;
    let boundary = slot_1_start(now);

    // Within the create lead, a request creates slot 1's key; slot 0 still signs.
    let before = signing_kid(&issuer, boundary - HOUR).await;
    assert_eq!(
        stored_slots(&aws_config().await).await,
        ["slot#0", "slot#1"]
    );
    assert_eq!(
        statuses(&issuer, boundary - HOUR).await,
        ["active", "active"]
    );

    // From the boundary on, slot 1 signs and slot 0 is retired.
    let after = signing_kid(&issuer, boundary + 10 * 60).await;
    assert_ne!(before, after);
    assert_eq!(
        statuses(&issuer, boundary + 10 * 60).await,
        ["retired", "active"]
    );
}

#[tokio::test]
#[serial]
async fn test_revoked_key_stops_signing() {
    let now = now();
    let issuer = issuer().await;
    aws_sdk_dynamodb::Client::new(&aws_config().await)
        .update_item()
        .table_name(AAT_KEYS_TABLE)
        .key("slot", AttributeValue::S("slot#0".to_string()))
        .update_expression("SET #revoked = :revoked")
        .expression_attribute_names("#revoked", "revoked")
        .expression_attribute_values(":revoked", AttributeValue::Bool(true))
        .send()
        .await
        .unwrap();

    // Seen once the cache expires.
    let later = now + 10 * 60;
    let result = issuer
        .keys(later)
        .await
        .issue(FieldElement::from(1u64), flags(), later);
    assert!(matches!(result, Err(IssueError::KeyNotValid)));
    assert_eq!(statuses(&issuer, later).await, ["revoked"]);
}

#[tokio::test]
#[serial]
async fn test_instances_racing_on_first_start_create_one_key() {
    let now = now();
    let aws_config = aws_config().await;
    reset_aat_keys(&aws_config).await;
    let kms_key = kms_key(&aws_config).await;

    let (a, b) = tokio::join!(
        issuer_with(&aws_config, kms_key.clone(), now),
        issuer_with(&aws_config, kms_key, now),
    );

    assert_eq!(stored_slots(&aws_config).await, ["slot#0"]);
    assert_eq!(signing_kid(&a, now).await, signing_kid(&b, now).await);
}

/// A store over a table with slot 0's key, and the item update to apply to it.
async fn store_after(update: &str, values: Option<(&str, AttributeValue)>) -> AatKeyStore {
    let aws_config = aws_config().await;
    reset_aat_keys(&aws_config).await;
    let kms_key = kms_key(&aws_config).await;
    issuer_with(&aws_config, kms_key.clone(), now()).await;

    let mut request = aws_sdk_dynamodb::Client::new(&aws_config)
        .update_item()
        .table_name(AAT_KEYS_TABLE)
        .key("slot", AttributeValue::S("slot#0".to_string()))
        .update_expression(update);
    if let Some((name, value)) = values {
        request = request.expression_attribute_values(name, value);
    }
    request.send().await.unwrap();
    AatKeyStore::new(&aws_config, AAT_KEYS_TABLE.to_string(), kms_key)
}

#[tokio::test]
#[serial]
async fn test_key_item_with_a_changed_window_does_not_decrypt() {
    let store = store_after(
        "SET not_after = :not_after",
        Some((":not_after", AttributeValue::N(u64::MAX.to_string()))),
    )
    .await;
    assert!(store.load(0).await.is_err());
}

#[tokio::test]
#[serial]
async fn test_key_item_without_revoked_does_not_load() {
    let store = store_after("REMOVE revoked", None).await;
    assert!(store.load(0).await.is_err());
}
