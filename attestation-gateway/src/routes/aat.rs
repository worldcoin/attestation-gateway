use std::{str::FromStr, sync::Arc, time::SystemTime};

use axum::Extension;
use axum_jsonschema::Json;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions, aio::ConnectionManager};
use schemars::JsonSchema;
use world_id_primitives::FieldElement;
use world_id_proof::authenticator_assertion::{Platform, SecFlags, SecLevel, UserPresence};

use crate::{
    aat_issuer::{AatIssuer, AuthenticatorMetadata},
    android, apple,
    utils::{
        BundleIdentifier, ClientException, ErrorCode, GlobalConfig, RequestError,
        handle_redis_error,
    },
};

const AAT_COMMITMENT_REDIS_KEY_PREFIX: &str = "aat_commitment:";
/// Outlives every AAT, so a commitment is never signed twice while a token could still be used.
const AAT_COMMITMENT_LOCK_TTL: u64 = 60 * 60;

/// Request for a WIP-106 Authenticator Assertion Token.
///
/// The platform evidence's challenge is [`challenge`] over every value the AAT signs on the
/// Authenticator's word: it is the App Attest `clientDataHash` preimage and the Play Integrity
/// `nonce`.
#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct AatRequest {
    pub bundle_identifier: BundleIdentifier,
    /// `H_8(DS_REQ; aud, nonce, cdh, blind)` as `0x`-prefixed, 32-byte big-endian hex.
    pub aat_commitment: String,
    /// The Authenticator's build. Play Integrity attests it, and a different value is rejected.
    pub build_version: u32,
    /// The presence check the Authenticator ran for this request (WIP-106 §3.5.1).
    pub user_presence: u8,
    pub integrity_token: Option<String>,
    pub apple_assertion: Option<String>,
    pub apple_public_key: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct AatResponse {
    /// The AAT's CWT encoding, base64url without padding.
    pub aat: String,
}

enum Evidence {
    Android {
        integrity_token: String,
    },
    AppleAssertion {
        apple_assertion: String,
        apple_public_key: String,
    },
}

impl Evidence {
    fn from_request(request: &AatRequest) -> Result<Self, RequestError> {
        match (
            &request.integrity_token,
            &request.apple_assertion,
            &request.apple_public_key,
        ) {
            (Some(integrity_token), None, None) => Ok(Self::Android {
                integrity_token: integrity_token.clone(),
            }),
            (None, Some(apple_assertion), Some(apple_public_key)) => Ok(Self::AppleAssertion {
                apple_assertion: apple_assertion.clone(),
                apple_public_key: apple_public_key.clone(),
            }),
            _ => Err(bad_request(
                "Provide either `integrity_token`, or `apple_assertion` with `apple_public_key`.",
            )),
        }
    }

    const fn platform(&self) -> &'static str {
        match self {
            Self::Android { .. } => "android",
            Self::AppleAssertion { .. } => "ios",
        }
    }
}

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(aws_config): Extension<aws_config::SdkConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Extension(issuer): Extension<Option<Arc<AatIssuer>>>,
    Json(request): Json<AatRequest>,
) -> Result<Json<AatResponse>, RequestError> {
    let issuer = issuer.ok_or(RequestError {
        code: ErrorCode::NotFound,
        details: None,
    })?;
    global_config.require_enabled_bundle(&request.bundle_identifier)?;

    let aat_commitment = FieldElement::from_str(&request.aat_commitment)
        .map_err(|_| bad_request("`aat_commitment` must be a 32-byte hex field element."))?;
    let user_presence = UserPresence::try_from(request.user_presence)
        .map_err(|_| bad_request("`user_presence` must be between 0 and 4."))?;
    let challenge = challenge(aat_commitment, user_presence, request.build_version);
    // Canonical form, so a commitment is signed at most once whatever flags it is sent with.
    let lock_key = aat_commitment.to_string();
    let evidence = Evidence::from_request(&request)?;
    let platform = evidence.platform();

    metrics::counter!("aat.request", "platform" => platform).increment(1);

    if !lock_commitment(&lock_key, &mut redis).await? {
        return Err(RequestError {
            code: ErrorCode::DuplicateRequestHash,
            details: None,
        });
    }

    let result = issue(
        &issuer,
        evidence,
        &request,
        aat_commitment,
        &challenge,
        user_presence,
        &global_config,
        &aws_config,
    )
    .await;

    match result {
        Ok(aat) => {
            metrics::counter!("aat.success", "platform" => platform).increment(1);
            Ok(Json(AatResponse { aat }))
        }
        Err(e) => {
            metrics::counter!("aat.failure", "platform" => platform, "error_code" => e.code.to_string())
                .increment(1);
            // Keep the original error: a failed release is already logged by `handle_redis_error`,
            // and the lock expires on its own after `AAT_COMMITMENT_LOCK_TTL`.
            if release_commitment(&lock_key, &mut redis).await.is_err() {
                metrics::counter!("aat.lock_release_failure").increment(1);
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn issue(
    issuer: &AatIssuer,
    evidence: Evidence,
    request: &AatRequest,
    aat_commitment: FieldElement,
    challenge: &str,
    user_presence: UserPresence,
    config: &GlobalConfig,
    aws_config: &aws_config::SdkConfig,
) -> Result<String, RequestError> {
    let bundle = &request.bundle_identifier;
    let (output, platform, sec_level) = match evidence {
        Evidence::Android { integrity_token } => {
            let keys = config.android_response_keys(bundle);
            let output = android::verify(
                &integrity_token,
                bundle,
                challenge,
                keys.outer_jwe_private_key.clone(),
                keys.inner_jws_public_key.clone(),
            );
            (output, Platform::Android, SecLevel::PlatformVerdict)
        }
        Evidence::AppleAssertion {
            apple_assertion,
            apple_public_key,
        } => {
            let output = apple::verify(
                apple_assertion,
                apple_public_key,
                bundle,
                challenge,
                aws_config,
                &config.apple_keys_dynamo_table_name,
            )
            .await;
            (output, Platform::Ios, SecLevel::HardwareKey)
        }
    };
    let output = output.map_err(|e| map_verification_error(&e))?;
    if !output.success {
        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            details: None,
        });
    }

    // WIP-106 §3.6.2/§3.6.4: the reported build is in the challenge; where the platform attests one
    // (Play Integrity `versionCode`) it must agree.
    if let Some(version) = output.app_version
        && version.parse::<u32>().ok() != Some(request.build_version)
    {
        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            details: Some("`build_version` does not match the attested app version.".to_string()),
        });
    }
    let build_version = request.build_version;
    let sec_flags = SecFlags::new(
        platform.into(),
        sec_level.into(),
        build_version,
        0,
        user_presence,
    )
    .map_err(|e| {
        tracing::error!(error = ?e, "Invalid AAT security flags");
        internal_error()
    })?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| internal_error())?
        .as_secs();
    let cwt = issuer.issue(aat_commitment, sec_flags, now).map_err(|e| {
        tracing::error!(error = ?e, "Error issuing AAT");
        internal_error()
    })?;
    Ok(URL_SAFE_NO_PAD.encode(cwt))
}

/// The platform challenge: lowercase hex of
/// `SHA-256(aat_commitment (32 bytes, big-endian) || user_presence (1 byte) || build_version (4 bytes, big-endian))`.
///
/// Binding the reported values into the evidence keeps them from being changed after the
/// Authenticator produced it (WIP-106 §3.5.1).
fn challenge(
    aat_commitment: FieldElement,
    user_presence: UserPresence,
    build_version: u32,
) -> String {
    let mut preimage = Vec::with_capacity(37);
    preimage.extend_from_slice(&aat_commitment.to_be_bytes());
    preimage.push(user_presence.into());
    preimage.extend_from_slice(&build_version.to_be_bytes());
    hex::encode(openssl::sha::sha256(&preimage))
}

fn map_verification_error(e: &eyre::Report) -> RequestError {
    if let Some(client_error) = e.downcast_ref::<ClientException>() {
        tracing::debug!(error = ?e, "Client exception verifying AAT evidence");
        return RequestError {
            code: client_error.code,
            details: None,
        };
    }
    tracing::error!(error = ?e, "Error verifying AAT evidence");
    internal_error()
}

/// Serves `/.well-known/world-id-authenticator.json` (WIP-106 §3.8).
pub async fn metadata_handler(
    Extension(issuer): Extension<Option<Arc<AatIssuer>>>,
) -> Result<axum::Json<AuthenticatorMetadata>, RequestError> {
    let issuer = issuer.ok_or(RequestError {
        code: ErrorCode::NotFound,
        details: None,
    })?;
    let metadata = issuer.metadata().map_err(|e| {
        tracing::error!(error = ?e, "Error building authenticator metadata");
        internal_error()
    })?;
    Ok(axum::Json(metadata))
}

async fn lock_commitment(
    aat_commitment: &str,
    redis: &mut ConnectionManager,
) -> Result<bool, RequestError> {
    let options = SetOptions::default()
        .conditional_set(ExistenceCheck::NX)
        .with_expiration(SetExpiry::EX(AAT_COMMITMENT_LOCK_TTL));
    redis
        .set_options::<String, bool, bool>(
            format!("{AAT_COMMITMENT_REDIS_KEY_PREFIX}{aat_commitment}"),
            true,
            options,
        )
        .await
        .map_err(handle_redis_error)
}

async fn release_commitment(
    aat_commitment: &str,
    redis: &mut ConnectionManager,
) -> Result<(), RequestError> {
    redis
        .del::<String, usize>(format!("{AAT_COMMITMENT_REDIS_KEY_PREFIX}{aat_commitment}"))
        .await
        .map_err(handle_redis_error)?;
    Ok(())
}

fn bad_request(details: &str) -> RequestError {
    RequestError {
        code: ErrorCode::BadRequest,
        details: Some(details.to_string()),
    }
}

const fn internal_error() -> RequestError {
    RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_binds_every_reported_value() {
        let commitment = FieldElement::from(42u64);
        let reference = challenge(commitment, UserPresence::PresentVerified, 2006);
        assert_eq!(reference.len(), 64);
        assert_ne!(
            challenge(
                FieldElement::from(43u64),
                UserPresence::PresentVerified,
                2006
            ),
            reference
        );
        assert_ne!(
            challenge(commitment, UserPresence::Undetermined, 2006),
            reference
        );
        assert_ne!(
            challenge(commitment, UserPresence::PresentVerified, 2007),
            reference
        );
    }

    #[test]
    fn challenge_matches_known_answer() {
        // Computed independently: SHA-256(31 zero bytes || 0x2a || 0x02 || 0x000007d6).
        assert_eq!(
            challenge(
                FieldElement::from(42u64),
                UserPresence::PresentVerified,
                2006
            ),
            "a45df5e6f762c267a8a8113537d125588592712dab90d33a58158e66d2404ca6"
        );
    }
}
