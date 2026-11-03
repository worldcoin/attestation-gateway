//! The `takt` format of `/a`: WIP-106 Trust Anchor Key Tokens.
//!
//! On Android the attested Keystore key is the `assertion_key`. On iOS the App Attest challenge
//! commits to a separate Secure Enclave key, as the App Attest key itself can not sign arbitrary
//! data.

use std::time::SystemTime;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::VerifyingKey;
use schemars::JsonSchema;
use world_id_primitives::authenticator_assertion::{self, SecFlags, SecLevel};

use crate::{
    takt_issuer::{IssueError, TaktIssuer},
    utils::{ErrorCode, Platform, RequestError},
};

/// Output format of `/a`.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TokenFormat {
    /// A JWT integrity token signed with KMS.
    #[default]
    Jwt,
    /// A WIP-106 Trust Anchor Key Token, as base64url of its CWT encoding without padding.
    Takt,
}

/// The iOS inputs of a TAKT: the Secure Enclave `assertion_key` and the reported build.
pub(super) struct IosInputs {
    assertion_key: VerifyingKey,
    build_version: u32,
}

impl IosInputs {
    /// Parses the request's `assertion_key` (base64 SEC1 P-256) and `build_version`.
    pub(super) fn parse(
        assertion_key: Option<&str>,
        build_version: Option<u32>,
    ) -> Result<Self, RequestError> {
        let assertion_key = assertion_key
            .and_then(|key| STANDARD.decode(key).ok())
            .and_then(|key| VerifyingKey::from_sec1_bytes(&key).ok())
            .ok_or_else(|| {
                bad_request("`assertion_key` must be a base64 SEC1 P-256 public key.")
            })?;
        let build_version =
            build_version.ok_or_else(|| bad_request("`build_version` is required on iOS."))?;
        Ok(Self {
            assertion_key,
            build_version,
        })
    }

    /// The App Attest challenge for a TAKT: `/a`'s `n=<nonce>,av=<app_version>`, extended with
    /// the reported `build_version` and `k=`, the lowercase hex SHA-256 of the `assertion_key`'s
    /// EC2 `COSE_Key` (WIP-106 §3.7).
    pub(super) fn apple_challenge(&self, nonce: &str, app_version: &str) -> String {
        let key = hex::encode(openssl::sha::sha256(&cose_key(&self.assertion_key)));
        format!(
            "n={nonce},av={app_version},bv={},k={key}",
            self.build_version
        )
    }
}

/// The attested `assertion_key` and `build_version` a TAKT is issued for.
pub(super) enum Attested {
    /// The App Attest challenge committed to these inputs.
    Ios(IosInputs),
    /// The attested Keystore key (uncompressed SEC1) and the app's attested `versionCode`.
    Android {
        key: Vec<u8>,
        version_code: Option<u64>,
    },
}

/// The issuer, or a 400 if this deployment does not issue TAKTs.
pub(super) fn enabled(issuer: Option<&TaktIssuer>) -> Result<&TaktIssuer, RequestError> {
    issuer.ok_or_else(|| {
        rejected("disabled");
        bad_request("Format `takt` is not enabled.")
    })
}

/// Issues a TAKT for an attested key, expiring at `max_exp` at the latest. Both attestations
/// prove a hardware-bound key: App Attest, or Android Key Attestation in a TEE or `StrongBox`
/// (enforced by the Android verifier).
pub(super) fn issue(
    issuer: &TaktIssuer,
    attested: Attested,
    max_exp: i64,
) -> Result<String, RequestError> {
    let (platform, assertion_key, build_version) = match attested {
        Attested::Ios(inputs) => (
            Platform::AppleIOS,
            inputs.assertion_key,
            inputs.build_version,
        ),
        Attested::Android { key, version_code } => {
            let key = VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| bad_request("The attested key is not a P-256 key."))?;
            let build_version = version_code
                .and_then(|version| u32::try_from(version).ok())
                .ok_or_else(|| {
                    rejected("missing_build_version");
                    RequestError {
                        code: ErrorCode::AttestationRejected,
                        details: None,
                    }
                })?;
            (Platform::Android, key, build_version)
        }
    };
    let takt_platform = match platform {
        Platform::AppleIOS => authenticator_assertion::Platform::Ios,
        Platform::Android => authenticator_assertion::Platform::Android,
    };
    let sec_flags = SecFlags::new(
        takt_platform.into(),
        SecLevel::HardwareKey.into(),
        build_version,
        0,
    )
    .map_err(|e| internal_error("Invalid TAKT security flags", &e))?;

    let now = unix_now()?;
    let cwt = issuer
        .issue(
            assertion_key,
            sec_flags,
            now,
            u64::try_from(max_exp).unwrap_or(0),
        )
        .map_err(|e| match e {
            // High-frequency once it happens; alert on the metric instead of logging.
            IssueError::KeyNotValid => {
                rejected("key_not_valid");
                RequestError {
                    code: ErrorCode::InternalServerError,
                    details: None,
                }
            }
            IssueError::Token(e) => internal_error("Error issuing TAKT", &e),
        })?;
    metrics::counter!("attestation_gateway.takt_issued", "platform" => platform.to_string())
        .increment(1);
    Ok(URL_SAFE_NO_PAD.encode(cwt))
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

fn unix_now() -> Result<u64, RequestError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| internal_error("System clock is before the Unix epoch", &e))
}

fn rejected(reason: &'static str) {
    metrics::counter!("attestation_gateway.takt_rejected", "reason" => reason).increment(1);
}

fn bad_request(details: &str) -> RequestError {
    tracing::warn!(endpoint = "/a", format = "takt", message = %details);
    RequestError {
        code: ErrorCode::BadRequest,
        details: Some(details.to_string()),
    }
}

fn internal_error(message: &'static str, error: &dyn std::fmt::Debug) -> RequestError {
    tracing::error!(?error, message);
    RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    }
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

    fn challenge(nonce: &str, app_version: &str, build_version: u32, key: VerifyingKey) -> String {
        IosInputs {
            assertion_key: key,
            build_version,
        }
        .apple_challenge(nonce, app_version)
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
        let reference = challenge("n1", "1.0", 2006, key(9));
        assert!(reference.starts_with("n=n1,av=1.0,bv=2006,k="));
        assert_ne!(challenge("n2", "1.0", 2006, key(9)), reference);
        assert_ne!(challenge("n1", "1.1", 2006, key(9)), reference);
        assert_ne!(challenge("n1", "1.0", 2007, key(9)), reference);
        assert_ne!(challenge("n1", "1.0", 2006, key(8)), reference);
    }

    #[test]
    fn format_defaults_to_jwt() {
        assert_eq!(TokenFormat::default(), TokenFormat::Jwt);
        assert_eq!(
            serde_json::from_str::<TokenFormat>("\"takt\"").unwrap(),
            TokenFormat::Takt
        );
    }
}
