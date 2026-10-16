//! `POST /takt`: issues WIP-106 Trust Anchor Key Tokens for a device-bound `assertion_key`.
//!
//! Uses the same `/c` nonce and key attestations as `/a`: on Android the attested Keystore key is
//! the `assertion_key`; on iOS the App Attest challenge commits to a separate Secure Enclave key,
//! as the App Attest key itself can not sign arbitrary data.

use std::{sync::Arc, time::SystemTime};

use axum::{Extension, http::HeaderMap};
use axum_jsonschema::Json;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::VerifyingKey;
use redis::{AsyncCommands, aio::ConnectionManager};
use schemars::JsonSchema;
use world_id_primitives::authenticator_assertion::{Platform, SecFlags, SecLevel};

use super::a::{
    headers_to_map, map_android_attestation_error,
    validate_apple_attestation_and_get_device_public_key,
};
use crate::{
    android::{AndroidAttestationInput, AndroidAttestationService},
    nonces::{NonceDb, NonceDbError, TokenDetails},
    takt_issuer::{AuthenticatorMetadata, IssueError, TaktIssuer},
    utils::{BundleIdentifier, ErrorCode, GlobalConfig, RequestError, client_session_id},
};

/// Request for a WIP-106 Trust Anchor Key Token.
#[derive(serde::Deserialize, JsonSchema)]
pub struct TaktRequest {
    /// Single-use nonce from `/c`.
    pub nonce: String,
    pub app_version: String,
    pub bundle_identifier: BundleIdentifier,
    /// iOS only: the App Attest attestation, with the challenge from [`apple_challenge`].
    pub apple_attestation: Option<String>,
    /// iOS only: the Secure Enclave `assertion_key`, base64 of its uncompressed SEC1 encoding.
    pub assertion_key: Option<String>,
    /// iOS only: the Authenticator's build. Android attests its `versionCode` instead.
    pub build_version: Option<u32>,
    /// Android only: the Key Attestation certificate chain of the `assertion_key`, as for `/a`.
    pub android_attestation: Option<Vec<String>>,
    pub device_model: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TaktResponse {
    /// The TAKT's CWT encoding, base64url without padding.
    pub takt: String,
}

/// Why a TAKT request failed, as the bounded `reason` tag of the `takt.failure` metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureReason {
    /// `TAKT_SIGNING_KEY` is unset.
    Disabled,
    BundleDisabled,
    InvalidRequest,
    NonceNotFound,
    /// The platform rejected the attestation; see `error_code`.
    AttestationRejected,
    /// Android attested no `versionCode` for the app.
    MissingBuildVersion,
    /// The `assertion_key` was attested before with other security flags (WIP-106 §3.4).
    SecFlagsConflict,
    /// The signing key is outside the window in which it may sign; needs a key rotation.
    KeyNotValid,
    /// Unexpected error in a dependency (Redis, nonce store) or building the token.
    InternalError,
}

impl FailureReason {
    const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::BundleDisabled => "bundle_disabled",
            Self::InvalidRequest => "invalid_request",
            Self::NonceNotFound => "nonce_not_found",
            Self::AttestationRejected => "attestation_rejected",
            Self::MissingBuildVersion => "missing_build_version",
            Self::SecFlagsConflict => "sec_flags_conflict",
            Self::KeyNotValid => "key_not_valid",
            Self::InternalError => "internal_error",
        }
    }
}

struct Failure {
    reason: FailureReason,
    error: RequestError,
}

const fn fail(reason: FailureReason, code: ErrorCode) -> Failure {
    Failure {
        reason,
        error: RequestError {
            code,
            details: None,
        },
    }
}

fn bad_request(details: &str) -> Failure {
    Failure {
        reason: FailureReason::InvalidRequest,
        error: RequestError {
            code: ErrorCode::BadRequest,
            details: Some(details.to_string()),
        },
    }
}

const fn internal_error() -> Failure {
    fail(FailureReason::InternalError, ErrorCode::InternalServerError)
}

/// Platform tag from the attestation fields, before they are validated.
const fn platform_tag(request: &TaktRequest) -> &'static str {
    match (&request.apple_attestation, &request.android_attestation) {
        (Some(_), None) => "ios",
        (None, Some(_)) => "android",
        _ => "unknown",
    }
}

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(global_config): Extension<GlobalConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(mut nonce_db): Extension<NonceDb>,
    Extension(mut android_attestation): Extension<AndroidAttestationService>,
    Extension(issuer): Extension<Option<Arc<TaktIssuer>>>,
    headers: HeaderMap,
    Json(request): Json<TaktRequest>,
) -> Result<Json<TaktResponse>, RequestError> {
    let platform = platform_tag(&request);
    metrics::counter!("takt.request", "platform" => platform).increment(1);

    let result = handle(
        issuer.as_deref(),
        &request,
        &global_config,
        &mut redis,
        &mut nonce_db,
        &mut android_attestation,
        &headers,
    )
    .await;
    match result {
        Ok(takt) => {
            metrics::counter!("takt.success", "platform" => platform).increment(1);
            Ok(Json(TaktResponse { takt }))
        }
        Err(Failure { reason, error }) => {
            metrics::counter!(
                "takt.failure",
                "platform" => platform,
                "reason" => reason.tag(),
                "error_code" => error.code.to_string(),
            )
            .increment(1);
            Err(error)
        }
    }
}

async fn handle(
    issuer: Option<&TaktIssuer>,
    request: &TaktRequest,
    config: &GlobalConfig,
    redis: &mut ConnectionManager,
    nonce_db: &mut NonceDb,
    android_attestation: &mut AndroidAttestationService,
    headers: &HeaderMap,
) -> Result<String, Failure> {
    let issuer = issuer.ok_or(fail(FailureReason::Disabled, ErrorCode::NotFound))?;
    config
        .require_enabled_bundle(&request.bundle_identifier)
        .map_err(|error| Failure {
            reason: FailureReason::BundleDisabled,
            error,
        })?;
    let session_id = client_session_id(headers);

    let token_details = nonce_db
        .consume_nonce(&request.nonce)
        .await
        .map_err(|e| match e {
            NonceDbError::NonceNotFound => {
                fail(FailureReason::NonceNotFound, ErrorCode::NonceNotFound)
            }
            e => {
                tracing::error!(error = ?e, "Error consuming TAKT nonce");
                internal_error()
            }
        })?;

    let (assertion_key, platform, build_version) = attest(
        request,
        config,
        android_attestation,
        headers,
        &token_details,
        session_id,
    )
    .await?;

    // Both attestations prove a hardware-bound key: App Attest, or Android Key Attestation in a
    // TEE or StrongBox (enforced by the Android verifier).
    let sec_flags = SecFlags::new(
        platform.into(),
        SecLevel::HardwareKey.into(),
        build_version,
        0,
    )
    .map_err(|e| {
        tracing::error!(error = ?e, "Invalid TAKT security flags");
        internal_error()
    })?;

    let now = unix_now().ok_or_else(internal_error)?;
    let max_exp = u64::try_from(token_details.exp_max).unwrap_or(0);
    claim_sec_flags(redis, &assertion_key, sec_flags, issuer.lifetime_secs()).await?;

    let cwt = issuer
        .issue(assertion_key, sec_flags, now, max_exp)
        .map_err(|e| match e {
            // High-frequency once it happens; alert on the `key_not_valid` metric instead of logging.
            IssueError::KeyNotValid => {
                fail(FailureReason::KeyNotValid, ErrorCode::InternalServerError)
            }
            IssueError::Token(e) => {
                tracing::error!(error = ?e, "Error issuing TAKT");
                internal_error()
            }
        })?;
    Ok(URL_SAFE_NO_PAD.encode(cwt))
}

/// Verifies the platform attestation and returns the `assertion_key`, its platform and the
/// `build_version` to attest.
async fn attest(
    request: &TaktRequest,
    config: &GlobalConfig,
    android_attestation: &mut AndroidAttestationService,
    headers: &HeaderMap,
    token_details: &TokenDetails,
    session_id: &str,
) -> Result<(VerifyingKey, Platform, u32), Failure> {
    match (&request.apple_attestation, &request.android_attestation) {
        (Some(apple_attestation), None) => {
            let assertion_key = request
                .assertion_key
                .as_deref()
                .and_then(|key| STANDARD.decode(key).ok())
                .and_then(|key| VerifyingKey::from_sec1_bytes(&key).ok())
                .ok_or_else(|| {
                    bad_request("`assertion_key` must be a base64 SEC1 P-256 public key.")
                })?;
            let build_version = request
                .build_version
                .ok_or_else(|| bad_request("`build_version` is required on iOS."))?;
            let challenge = apple_challenge(
                &request.nonce,
                &request.app_version,
                build_version,
                &assertion_key,
            );
            validate_apple_attestation_and_get_device_public_key(
                "/takt",
                &config.apple_root_ca_pem,
                &challenge,
                &request.bundle_identifier,
                apple_attestation.clone(),
            )
            .map_err(|error| Failure {
                reason: FailureReason::AttestationRejected,
                error,
            })?;
            Ok((assertion_key, Platform::Ios, build_version))
        }
        (None, Some(raw_cert_chain)) => {
            let output = android_attestation
                .verify(AndroidAttestationInput {
                    raw_cert_chain,
                    nonce: &request.nonce,
                    requested_exp: None,
                    app_version: &request.app_version,
                    bundle_identifier: &request.bundle_identifier,
                    device_model: request.device_model.as_deref(),
                    request_headers: &headers_to_map(headers),
                    token_details,
                })
                .await
                .map_err(|e| Failure {
                    reason: FailureReason::AttestationRejected,
                    error: map_android_attestation_error(&e, "/takt", session_id),
                })?;
            let assertion_key = VerifyingKey::from_sec1_bytes(&output.device_public_key)
                .map_err(|_| bad_request("The attested key is not a P-256 key."))?;
            let build_version = output
                .version_code
                .and_then(|version| u32::try_from(version).ok())
                .ok_or(fail(
                    FailureReason::MissingBuildVersion,
                    ErrorCode::AttestationRejected,
                ))?;
            Ok((assertion_key, Platform::Android, build_version))
        }
        _ => Err(bad_request(
            "Provide either `apple_attestation` or `android_attestation`.",
        )),
    }
}

/// Records the `sec_flags` an `assertion_key` is attested with for one TAKT lifetime, and rejects
/// other flags for the same key (WIP-106 §3.4). Stores only a hash of the key, never a device
/// identifier (§3.7).
async fn claim_sec_flags(
    redis: &mut ConnectionManager,
    assertion_key: &VerifyingKey,
    sec_flags: SecFlags,
    lifetime_secs: u32,
) -> Result<(), Failure> {
    let redis_key = format!(
        "takt:sec_flags:{}",
        hex::encode(openssl::sha::sha256(
            assertion_key.to_encoded_point(false).as_bytes()
        ))
    );
    let packed = sec_flags.pack();
    let redis_error = |e: redis::RedisError| {
        tracing::error!(error = ?e, "Error recording TAKT security flags");
        internal_error()
    };
    let options = redis::SetOptions::default()
        .conditional_set(redis::ExistenceCheck::NX)
        .with_expiration(redis::SetExpiry::EX(u64::from(lifetime_secs)));
    let created: bool = redis
        .set_options(&redis_key, packed, options)
        .await
        .map_err(redis_error)?;
    let stored: Option<u64> = if created {
        None
    } else {
        redis.get(&redis_key).await.map_err(redis_error)?
    };
    match stored {
        None => Ok(()),
        Some(stored) if stored == packed => Ok(()),
        Some(_) => Err(Failure {
            reason: FailureReason::SecFlagsConflict,
            error: RequestError {
                code: ErrorCode::AttestationRejected,
                details: Some(
                    "`assertion_key` is already attested with other security flags.".to_string(),
                ),
            },
        }),
    }
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| tracing::error!(error = ?e, "System clock is before the Unix epoch"))
        .ok()
}

/// The App Attest challenge for a TAKT: `/a`'s `n=<nonce>,av=<app_version>`, extended with the
/// reported `build_version` and `k=`, the lowercase hex SHA-256 of the `assertion_key`'s EC2
/// `COSE_Key` (WIP-106 §3.7).
fn apple_challenge(
    nonce: &str,
    app_version: &str,
    build_version: u32,
    assertion_key: &VerifyingKey,
) -> String {
    let key = hex::encode(openssl::sha::sha256(&cose_key(assertion_key)));
    format!("n={nonce},av={app_version},bv={build_version},k={key}")
}

/// The EC2 P-256 `COSE_Key` `{1: 2, -1: 1, -2: x, -3: y}` in deterministic CBOR, as carried in the
/// TAKT's `cnf` claim.
fn cose_key(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    let mut out = Vec::with_capacity(75);
    // map(4), kty (1): EC2 (2), crv (-1): P-256 (1), x (-2): bstr(32)
    out.extend_from_slice(&[0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out.extend_from_slice(point.x().expect("uncompressed point"));
    // y (-3): bstr(32)
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(point.y().expect("uncompressed point"));
    out
}

/// Serves `/.well-known/world-id-authenticator.json` (WIP-106 §3.9).
pub async fn metadata_handler(
    Extension(issuer): Extension<Option<Arc<TaktIssuer>>>,
) -> Result<axum::Json<AuthenticatorMetadata>, RequestError> {
    let not_found = RequestError {
        code: ErrorCode::NotFound,
        details: None,
    };
    let issuer = issuer.ok_or(not_found)?;
    let internal = || RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    };
    let now = unix_now().ok_or_else(internal)?;
    let metadata = issuer.metadata(now).map_err(|e| {
        tracing::error!(error = ?e, "Error building authenticator metadata");
        internal()
    })?;
    Ok(axum::Json(metadata))
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;

    fn key(byte: u8) -> VerifyingKey {
        *SigningKey::from_bytes(&[byte; 32].into())
            .unwrap()
            .verifying_key()
    }

    #[test]
    fn cose_key_matches_the_takt_cnf_claim() {
        // WIP-106 Appendix A1: the `assertion_key` secret is 32 bytes of `0x09`, and its
        // `COSE_Key` sits at offset 13 of the TAKT's `cnf` claim.
        let encoded = hex::encode(cose_key(&key(9)));
        assert_eq!(encoded.len(), 150);
        assert!(encoded.starts_with("a40102200121582071"));
        assert!(encoded.ends_with("588776724"));
    }

    #[test]
    fn apple_challenge_binds_every_value() {
        let reference = apple_challenge("n1", "1.0", 2006, &key(9));
        assert!(reference.starts_with("n=n1,av=1.0,bv=2006,k="));
        assert_ne!(apple_challenge("n2", "1.0", 2006, &key(9)), reference);
        assert_ne!(apple_challenge("n1", "1.1", 2006, &key(9)), reference);
        assert_ne!(apple_challenge("n1", "1.0", 2007, &key(9)), reference);
        assert_ne!(apple_challenge("n1", "1.0", 2006, &key(8)), reference);
    }

    #[test]
    fn failure_reason_tags_are_distinct() {
        use FailureReason::*;
        let reasons = [
            Disabled,
            BundleDisabled,
            InvalidRequest,
            NonceNotFound,
            AttestationRejected,
            MissingBuildVersion,
            SecFlagsConflict,
            KeyNotValid,
            InternalError,
        ];
        let tags: std::collections::HashSet<_> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), reasons.len());
    }
}
