//! WIP-106 Trust Anchor Key Token (TAKT) issuance.
//!
//! The `trust_anchor_key` is a `BabyJubJub` key that KMS cannot hold, so it is loaded from the
//! environment. It should move to a TEE or HSM before production (WIP-106 §3.3).

use std::env;

use eddsa_babyjubjub::EdDSAPrivateKey;
use p256::ecdsa::VerifyingKey;
use schemars::JsonSchema;
use serde::Serialize;
use world_id_primitives::FieldElement;
use world_id_primitives::authenticator_assertion::{
    MAX_TAKT_LIFETIME_SECS, SecFlags, TrustAnchorKeyToken,
};

/// Longest validity window of one key (WIP-106 §3.3).
const MAX_KEY_VALIDITY_SECS: u64 = 15_552_000;

/// Default TAKT lifetime (7 days), below `MAX_TAKT_LIFETIME_SECS` to limit how long a TAKT
/// outlives a device compromised after issuance.
const DEFAULT_TAKT_LIFETIME_SECS: u32 = 604_800;

/// Why a TAKT could not be issued.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// `now` is outside the window in which the key may sign (see [`TaktIssuer::issue`]).
    #[error("trust anchor key may not sign at this time")]
    KeyNotValid,
    #[error(transparent)]
    Token(#[from] eyre::Report),
}

/// Issues TAKTs with the Authenticator Provider's `trust_anchor_key`.
pub struct TaktIssuer {
    key: EdDSAPrivateKey,
    provider_id: String,
    not_before: u64,
    not_after: u64,
    lifetime_secs: u32,
}

impl TaktIssuer {
    /// Loads the issuer from the environment. Returns `None` if `TAKT_SIGNING_KEY` is unset, which
    /// disables the `/takt` route.
    ///
    /// # Panics
    /// If any `TAKT_*` variable is malformed, so a misconfigured issuer fails at startup.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key = env::var("TAKT_SIGNING_KEY").ok()?;
        let key: [u8; 32] = hex::decode(key.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("`TAKT_SIGNING_KEY` must be 32 bytes of hex");
        let parse = |name: &str| -> u64 {
            env::var(name)
                .unwrap_or_else(|_| panic!("`{name}` is required with `TAKT_SIGNING_KEY`"))
                .parse()
                .unwrap_or_else(|_| panic!("`{name}` must be seconds since the Unix epoch"))
        };
        let lifetime_secs = env::var("TAKT_LIFETIME_SECS")
            .map_or(DEFAULT_TAKT_LIFETIME_SECS, |v| {
                v.parse().expect("`TAKT_LIFETIME_SECS` must be a u32")
            });
        Some(Self::new(
            EdDSAPrivateKey::from_bytes(key),
            env::var("TAKT_PROVIDER_ID")
                .expect("`TAKT_PROVIDER_ID` is required with `TAKT_SIGNING_KEY`"),
            parse("TAKT_KEY_NOT_BEFORE"),
            parse("TAKT_KEY_NOT_AFTER"),
            lifetime_secs,
        ))
    }

    /// # Panics
    /// If the validity window or lifetime break WIP-106 §3.3 or §3.7, or the window is not
    /// longer than one TAKT lifetime.
    #[must_use]
    pub fn new(
        key: EdDSAPrivateKey,
        provider_id: String,
        not_before: u64,
        not_after: u64,
        lifetime_secs: u32,
    ) -> Self {
        assert!(
            not_before < not_after && not_after - not_before <= MAX_KEY_VALIDITY_SECS,
            "trust anchor key validity window must be non-empty and at most 180 days"
        );
        assert!(
            lifetime_secs > 0 && lifetime_secs <= MAX_TAKT_LIFETIME_SECS,
            "`TAKT_LIFETIME_SECS` must be in (0, {MAX_TAKT_LIFETIME_SECS}]"
        );
        assert!(
            not_after - not_before > u64::from(lifetime_secs),
            "trust anchor key validity window must be longer than one TAKT lifetime"
        );
        assert!(
            u32::try_from(not_after).is_ok(),
            "`TAKT_KEY_NOT_AFTER` must fit in a u32"
        );
        Self {
            key,
            provider_id,
            not_before,
            not_after,
            lifetime_secs,
        }
    }

    /// How long issued TAKTs live, at most.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u32 {
        self.lifetime_secs
    }

    /// Last second (exclusive) at which the key signs, so every TAKT expires within the key's
    /// validity window (WIP-106 §3.4).
    fn signing_end(&self) -> u64 {
        self.not_after - u64::from(self.lifetime_secs)
    }

    /// Signs a TAKT attesting `assertion_key` and returns its CWT encoding. The TAKT expires
    /// `lifetime_secs` after `now`, or at `max_exp` if that is earlier.
    ///
    /// # Errors
    /// [`IssueError::KeyNotValid`] if `now` is outside `[not_before, not_after - lifetime)`;
    /// [`IssueError::Token`] if the token can not be built or encoded.
    pub fn issue(
        &self,
        assertion_key: VerifyingKey,
        sec_flags: SecFlags,
        now: u64,
        max_exp: u64,
    ) -> Result<Vec<u8>, IssueError> {
        if !(self.not_before..self.signing_end()).contains(&now) {
            return Err(IssueError::KeyNotValid);
        }
        let to_u32 = |value: u64| {
            u32::try_from(value).map_err(|_| eyre::eyre!("TAKT time {value} does not fit in a u32"))
        };
        let exp = (now + u64::from(self.lifetime_secs)).min(max_exp);
        let token = TrustAnchorKeyToken::new(
            to_u32(now)?,
            to_u32(exp)?,
            to_u32(self.not_after)?,
            assertion_key,
            sec_flags,
        )
        .map_err(eyre::Report::from)?;
        Ok(token.sign(&self.key).map_err(eyre::Report::from)?)
    }

    /// The Authenticator Metadata document (WIP-106 §3.9). The key is `retired` once it stops
    /// signing.
    ///
    /// # Errors
    /// If the public key can not be encoded.
    pub fn metadata(&self, now: u64) -> eyre::Result<AuthenticatorMetadata> {
        let public = self.key.public();
        Ok(AuthenticatorMetadata {
            version: 1,
            provider_id: self.provider_id.clone(),
            trust_anchor_keys: vec![TrustAnchorKey {
                kid: hex::encode(public.to_compressed_bytes()?),
                x: hex::encode(FieldElement::from(public.pk.x).to_be_bytes()),
                y: hex::encode(FieldElement::from(public.pk.y).to_be_bytes()),
                status: if now < self.signing_end() {
                    "active"
                } else {
                    "retired"
                },
                not_before: self.not_before,
                not_after: self.not_after,
            }],
            sec_meta: serde_json::Map::new(),
            authenticator_meta: serde_json::Map::new(),
        })
    }
}

/// `/.well-known/world-id-authenticator.json` (WIP-106 Appendix A2).
#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthenticatorMetadata {
    pub version: u32,
    pub provider_id: String,
    pub trust_anchor_keys: Vec<TrustAnchorKey>,
    /// No `sec_meta` bits are defined, so none are ever set.
    pub sec_meta: serde_json::Map<String, serde_json::Value>,
    /// No `authenticator_meta` provider-bit values are defined; Authenticators set none.
    pub authenticator_meta: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TrustAnchorKey {
    pub kid: String,
    pub x: String,
    pub y: String,
    pub status: &'static str,
    pub not_before: u64,
    pub not_after: u64,
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use world_id_primitives::authenticator_assertion::{Platform, SecLevel};

    use super::*;

    const NOW: u64 = 1_783_446_000;

    /// Valid from `NOW - 100`; signs until `NOW + 100`, then lets its last tokens expire.
    fn issuer() -> TaktIssuer {
        TaktIssuer::new(
            EdDSAPrivateKey::from_bytes([7u8; 32]),
            "test".into(),
            NOW - 100,
            NOW + 100 + u64::from(DEFAULT_TAKT_LIFETIME_SECS),
            DEFAULT_TAKT_LIFETIME_SECS,
        )
    }

    fn assertion_key() -> VerifyingKey {
        *SigningKey::from_bytes(&[9u8; 32].into())
            .unwrap()
            .verifying_key()
    }

    fn flags() -> SecFlags {
        SecFlags::new(Platform::Ios.into(), SecLevel::HardwareKey.into(), 2006, 0).unwrap()
    }

    #[test]
    fn issued_token_verifies() {
        let issuer = issuer();
        let cwt = issuer
            .issue(assertion_key(), flags(), NOW, u64::MAX)
            .unwrap();
        let takt = TrustAnchorKeyToken::verify(&cwt, &issuer.key.public()).unwrap();
        assert_eq!(takt.assertion_key(), &assertion_key());
        assert_eq!(takt.sec_flags(), flags());
        assert_eq!(
            u64::from(takt.exp()),
            NOW + u64::from(DEFAULT_TAKT_LIFETIME_SECS)
        );
    }

    #[test]
    fn caps_expiry_at_max_exp() {
        let issuer = issuer();
        let cwt = issuer
            .issue(assertion_key(), flags(), NOW, NOW + 60)
            .unwrap();
        let takt = TrustAnchorKeyToken::verify(&cwt, &issuer.key.public()).unwrap();
        assert_eq!(u64::from(takt.exp()), NOW + 60);
    }

    #[test]
    fn signs_only_while_tokens_expire_within_key_validity() {
        let issuer = issuer();
        let issue = |now| issuer.issue(assertion_key(), flags(), now, u64::MAX);
        assert!(issue(NOW - 100).is_ok());
        assert!(issue(NOW + 99).is_ok());
        assert!(matches!(issue(NOW - 101), Err(IssueError::KeyNotValid)));
        assert!(matches!(issue(NOW + 100), Err(IssueError::KeyNotValid)));
    }

    #[test]
    fn metadata_matches_spec_test_vector_key() {
        // WIP-106 Appendix A1 uses the same key.
        let key = &issuer().metadata(NOW).unwrap().trust_anchor_keys[0];
        assert_eq!(
            key.kid,
            "2d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987"
        );
        assert_eq!(key.status, "active");
    }

    #[test]
    fn metadata_retires_key_once_it_stops_signing() {
        let metadata = issuer().metadata(NOW + 100).unwrap();
        assert_eq!(metadata.trust_anchor_keys[0].status, "retired");
    }

    #[test]
    #[should_panic(expected = "at most 180 days")]
    fn rejects_overlong_key_validity() {
        let _ = TaktIssuer::new(
            EdDSAPrivateKey::from_bytes([7u8; 32]),
            "test".into(),
            0,
            MAX_KEY_VALIDITY_SECS + 1,
            DEFAULT_TAKT_LIFETIME_SECS,
        );
    }
}
