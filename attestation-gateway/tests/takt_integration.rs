//! Integration tests for the WIP-106 `/takt` route and the Authenticator Metadata endpoint.
//! Requires the services in `tests/docker-compose.test.yml`.
//!
//! Android attestations come from real devices with fixed challenges, so only iOS is exercised
//! end to end; the Android path shares `/a`'s verifier.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use attestation_gateway::{
    android::{
        AllowAllAndroidRiskEvaluator, AndroidAttestationService, CertChainBuilder, RevocationList,
        analytics_service::AnalyticsService, rate_limit_service::RateLimitService,
    },
    apple,
    nonces::{NonceDb, TokenDetailsFactory},
    takt_issuer::TaktIssuer,
    utils::{AndroidResponseKeys, BundleIdentifier, GlobalConfig},
};
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
use openssl::sha::sha256;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use serial_test::serial;
use tower::ServiceExt;
use world_id_primitives::authenticator_assertion::TrustAnchorKeyToken;

const TAKT_LIFETIME_SECS: u32 = 7 * 24 * 60 * 60;
const BUNDLE: BundleIdentifier = BundleIdentifier::OrgWorldcoinInsightStaging;

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

/// An issuer whose key signs for the next 30 days.
fn issuer() -> TaktIssuer {
    let now = now();
    TaktIssuer::new(
        issuer_key(),
        "test-provider".to_string(),
        now - 60,
        now + 30 * 24 * 60 * 60,
        TAKT_LIFETIME_SECS,
    )
}

fn global_config(apple_root_ca_pem: Vec<u8>) -> GlobalConfig {
    dotenvy::from_filename(".env.example").unwrap();
    GlobalConfig {
        android_default_keys: AndroidResponseKeys {
            outer_jwe_private_key: std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY").unwrap(),
            inner_jws_public_key: std::env::var("ANDROID_INNER_JWS_PUBLIC_KEY").unwrap(),
        },
        android_world_app_keys: None,
        android_world_id_keys: None,
        apple_keys_dynamo_table_name: "attestation-gateway-apple-keys".to_string(),
        enabled_bundle_identifiers: vec![BUNDLE, BundleIdentifier::ComWorldcoinDev],
        log_client_errors: false,
        kinesis_stream_arn: None,
        developer_inner_jwks_url: None,
        apple_root_ca_pem,
        aud_whitelist: vec![],
        jwt_issuer: "attestation.worldcoin.org".to_string(),
        developer_portal_base_url: None,
        aud_authorization_cache_ttl_secs: 60 * 60,
        token_exp_max_by_aud: std::collections::HashMap::new(),
    }
}

async fn redis() -> redis::aio::ConnectionManager {
    let client = redis::Client::open("redis://localhost").unwrap();
    redis::cmd("FLUSHALL")
        .exec(&mut client.get_connection().unwrap())
        .unwrap();
    redis::aio::ConnectionManager::new(client).await.unwrap()
}

async fn android_attestation(redis: &redis::aio::ConnectionManager) -> AndroidAttestationService {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/status")
        .with_status(200)
        .with_header("Cache-Control", "max-age=60")
        .with_body(r#"{"entries":{}}"#)
        .create();
    AndroidAttestationService::new(
        CertChainBuilder::new_from_default_pem().unwrap(),
        RevocationList::connect(format!("{}/status", server.url()))
            .await
            .unwrap(),
        RateLimitService::new(redis.clone(), Some(10)),
        AnalyticsService::new(
            "arn:aws:kinesis:us-west-1:000000000000:stream/attestation-gateway-data-reports"
                .to_string(),
        )
        .await
        .unwrap(),
        Arc::new(AllowAllAndroidRiskEvaluator),
    )
}

/// Redis, flushed once per test, and a nonce issuer as `/c` would use it.
struct Setup {
    redis: redis::aio::ConnectionManager,
    nonce_db: NonceDb,
}

impl Setup {
    async fn new() -> Self {
        let redis = redis().await;
        Self {
            nonce_db: NonceDb::new(redis.clone()),
            redis,
        }
    }

    /// A fresh `/c` nonce.
    async fn nonce(&mut self) -> String {
        let details =
            TokenDetailsFactory::from_config(&global_config(vec![])).from_aud("takt".to_string());
        self.nonce_db.generate_nonce(&details).await.unwrap()
    }

    /// The gateway, trusting `apple_root_ca_pem` for App Attest.
    async fn router(
        &self,
        issuer: Option<TaktIssuer>,
        apple_root_ca_pem: Vec<u8>,
    ) -> aide::axum::ApiRouter {
        attestation_gateway::routes::handler()
            .layer(Extension(global_config(apple_root_ca_pem)))
            .layer(Extension(android_attestation(&self.redis).await))
            .layer(Extension(NonceDb::new(self.redis.clone())))
            .layer(Extension(self.redis.clone()))
            .layer(Extension(issuer.map(Arc::new)))
    }

    /// A router and a valid iOS `/takt` request for `key` and `build_version`.
    async fn ios(
        &mut self,
        key: &VerifyingKey,
        build_version: u32,
    ) -> (aide::axum::ApiRouter, Value) {
        let nonce = self.nonce().await;
        let attestation = apple_attestation(&apple_challenge(&nonce, build_version, key));
        let router = self
            .router(Some(issuer()), attestation.root_ca_pem.clone())
            .await;
        let request = ios_request(&nonce, build_version, key, &attestation.attestation_base64);
        (router, request)
    }
}

async fn call(router: &aide::axum::ApiRouter, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn post_takt(router: &aide::axum::ApiRouter, request: &Value) -> (StatusCode, Value) {
    call(
        router,
        Request::builder()
            .uri("/takt")
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(request.to_string()))
            .unwrap(),
    )
    .await
}

async fn get_metadata(router: &aide::axum::ApiRouter) -> (StatusCode, Value) {
    call(
        router,
        Request::builder()
            .uri("/.well-known/world-id-authenticator.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn assertion_key(byte: u8) -> VerifyingKey {
    *SigningKey::from_bytes(&[byte; 32].into())
        .unwrap()
        .verifying_key()
}

/// The App Attest challenge, written out independently of the route:
/// `n=<nonce>,av=<app_version>,bv=<build_version>,k=<hex SHA-256 of the COSE_Key>`.
fn apple_challenge(nonce: &str, build_version: u32, key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let mut cose_key = vec![0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose_key.extend_from_slice(point.x().unwrap());
    cose_key.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose_key.extend_from_slice(point.y().unwrap());
    format!(
        "n={nonce},av=1.0.0,bv={build_version},k={}",
        hex::encode(sha256(&cose_key))
    )
}

/// An App Attest attestation over `challenge`, and the root CA it chains to.
fn apple_attestation(challenge: &str) -> apple::test_helpers::TestAttestation {
    apple::test_helpers::build_test_attestation(
        BUNDLE.apple_app_id().unwrap(),
        challenge,
        "appattestdevelop",
    )
}

fn ios_request(nonce: &str, build_version: u32, key: &VerifyingKey, attestation: &str) -> Value {
    json!({
        "nonce": nonce,
        "app_version": "1.0.0",
        "bundle_identifier": BUNDLE.to_string(),
        "build_version": build_version,
        "assertion_key": STANDARD.encode(key.to_encoded_point(false).as_bytes()),
        "apple_attestation": attestation,
    })
}

/// Decodes the TAKT in a response and verifies it under the issuer key.
fn decode_takt(body: &Value) -> TrustAnchorKeyToken {
    let cwt = URL_SAFE_NO_PAD
        .decode(body["takt"].as_str().unwrap())
        .unwrap();
    TrustAnchorKeyToken::verify(&cwt, &issuer_key().public()).unwrap()
}

// SECTION --- tests ---

#[tokio::test]
#[serial]
async fn test_takt_ios_success() {
    let mut setup = Setup::new().await;
    let key = assertion_key(9);
    let (router, request) = setup.ios(&key, 41).await;
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let takt = decode_takt(&body);
    assert_eq!(takt.assertion_key(), &key);
    let flags = takt.sec_flags();
    assert_eq!((flags.platform(), flags.sec_level()), (2, 1));
    assert_eq!((flags.build_version(), flags.sec_meta()), (41, 0));
    let lifetime = u64::from(takt.exp()) - now();
    assert!(lifetime > 0 && lifetime <= u64::from(TAKT_LIFETIME_SECS));
}

#[tokio::test]
#[serial]
async fn test_takt_ios_rejects_a_key_the_attestation_does_not_cover() {
    let mut setup = Setup::new().await;
    let (router, mut request) = setup.ios(&assertion_key(9), 41).await;
    request["assertion_key"] =
        json!(STANDARD.encode(assertion_key(8).to_encoded_point(false).as_bytes()));
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
#[serial]
async fn test_takt_ios_rejects_a_changed_build_version() {
    let mut setup = Setup::new().await;
    let (router, mut request) = setup.ios(&assertion_key(9), 41).await;
    request["build_version"] = json!(42);
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
#[serial]
async fn test_takt_nonce_is_single_use() {
    let mut setup = Setup::new().await;
    let (router, request) = setup.ios(&assertion_key(9), 41).await;
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "nonce_not_found");
}

#[tokio::test]
#[serial]
async fn test_takt_rejects_other_sec_flags_for_the_same_key() {
    let mut setup = Setup::new().await;
    let key = assertion_key(9);

    // Re-attesting with the same flags succeeds, e.g. to renew a TAKT.
    for _ in 0..2 {
        let (router, request) = setup.ios(&key, 41).await;
        let (status, body) = post_takt(&router, &request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // WIP-106 §3.4: no TAKT with differing `sec_flags` for the same `assertion_key`.
    let (router, request) = setup.ios(&key, 42).await;
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "attestation_rejected");

    // Another key is unaffected.
    let (router, request) = setup.ios(&assertion_key(8), 42).await;
    let (status, body) = post_takt(&router, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
#[serial]
async fn test_takt_rejects_invalid_requests() {
    let mut setup = Setup::new().await;
    let key = assertion_key(9);

    let (router, mut request) = setup.ios(&key, 41).await;
    request["assertion_key"] = json!("not a key");
    assert_eq!(
        post_takt(&router, &request).await.0,
        StatusCode::BAD_REQUEST
    );

    let (router, mut request) = setup.ios(&key, 41).await;
    request.as_object_mut().unwrap().remove("build_version");
    assert_eq!(
        post_takt(&router, &request).await.0,
        StatusCode::BAD_REQUEST
    );

    let (router, mut request) = setup.ios(&key, 41).await;
    request["android_attestation"] = json!(["both platforms"]);
    assert_eq!(
        post_takt(&router, &request).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[serial]
async fn test_takt_routes_are_disabled_without_a_signing_key() {
    let mut setup = Setup::new().await;
    let nonce = setup.nonce().await;
    let router = setup.router(None, vec![]).await;
    let request = ios_request(&nonce, 41, &assertion_key(9), "attestation");
    assert_eq!(post_takt(&router, &request).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get_metadata(&router).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn test_authenticator_metadata() {
    let setup = Setup::new().await;
    let router = setup.router(Some(issuer()), vec![]).await;
    let (status, metadata) = get_metadata(&router).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata["version"], 1);
    assert_eq!(metadata["provider_id"], "test-provider");
    let key = &metadata["trust_anchor_keys"][0];
    assert_eq!(
        key["kid"],
        hex::encode(issuer_key().public().to_compressed_bytes().unwrap())
    );
    assert_eq!(key["status"], "active");
    assert!(metadata["sec_meta"].is_object());
    assert!(metadata["authenticator_meta"].is_object());
}
