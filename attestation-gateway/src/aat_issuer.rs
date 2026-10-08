//! WIP-106 Authenticator Assertion Token (AAT) issuance.
//!
//! The `authenticator_provider_key` is a `BabyJubJub` key that KMS cannot hold, so it is
//! loaded from the environment. It should move to a TEE or HSM before production (WIP-106 §3.2.7).

use std::env;

use eddsa_babyjubjub::EdDSAPrivateKey;
use schemars::JsonSchema;
use serde::Serialize;
use world_id_primitives::FieldElement;
use world_id_primitives::authenticator_assertion::{
    AuthenticatorAssertionToken, MAX_AAT_LIFETIME_SECS, SecFlags,
};

/// Longest validity window of one key (WIP-106 §3.2.5).
const MAX_KEY_VALIDITY_SECS: u64 = 15_552_000;

/// Default AAT lifetime, below `MAX_AAT_LIFETIME_SECS` so verifier clocks running behind do not
/// reject fresh tokens.
const DEFAULT_AAT_LIFETIME_SECS: u32 = 1200;

/// Why an AAT could not be issued.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// `now` is outside the window in which the key may sign (see [`AatIssuer::issue`]).
    #[error("AAT key may not sign at this time")]
    KeyNotValid,
    #[error(transparent)]
    Token(#[from] eyre::Report),
}

/// Issues AATs with the Authenticator Provider's key.
pub struct AatIssuer {
    key: EdDSAPrivateKey,
    provider_id: String,
    not_before: u64,
    not_after: u64,
    lifetime_secs: u32,
}

impl AatIssuer {
    /// Loads the issuer from the environment. Returns `None` if `AAT_SIGNING_KEY` is unset, which
    /// disables the `/aat` route.
    ///
    /// # Panics
    /// If any `AAT_*` variable is malformed, so a misconfigured issuer fails at startup.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key = env::var("AAT_SIGNING_KEY").ok()?;
        let key: [u8; 32] = hex::decode(key.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("`AAT_SIGNING_KEY` must be 32 bytes of hex");
        let parse = |name: &str| -> u64 {
            env::var(name)
                .unwrap_or_else(|_| panic!("`{name}` is required with `AAT_SIGNING_KEY`"))
                .parse()
                .unwrap_or_else(|_| panic!("`{name}` must be seconds since the Unix epoch"))
        };
        let lifetime_secs = env::var("AAT_LIFETIME_SECS").map_or(DEFAULT_AAT_LIFETIME_SECS, |v| {
            v.parse().expect("`AAT_LIFETIME_SECS` must be a u32")
        });
        Some(Self::new(
            EdDSAPrivateKey::from_bytes(key),
            env::var("AAT_PROVIDER_ID")
                .expect("`AAT_PROVIDER_ID` is required with `AAT_SIGNING_KEY`"),
            parse("AAT_KEY_NOT_BEFORE"),
            parse("AAT_KEY_NOT_AFTER"),
            lifetime_secs,
        ))
    }

    /// # Panics
    /// If the validity window or lifetime break WIP-106 §3.2.5 or §3.6.3, or the window is not
    /// longer than one AAT lifetime.
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
            "AAT key validity window must be non-empty and at most 180 days"
        );
        assert!(
            lifetime_secs > 0 && lifetime_secs <= MAX_AAT_LIFETIME_SECS,
            "`AAT_LIFETIME_SECS` must be in (0, {MAX_AAT_LIFETIME_SECS}]"
        );
        assert!(
            not_after - not_before > u64::from(lifetime_secs),
            "AAT key validity window must be longer than one AAT lifetime"
        );
        Self {
            key,
            provider_id,
            not_before,
            not_after,
            lifetime_secs,
        }
    }

    /// Last second (exclusive) at which the key signs, so every AAT expires within the key's
    /// validity window and RPs never see a token from a key past `not_after`.
    fn signing_end(&self) -> u64 {
        self.not_after - u64::from(self.lifetime_secs)
    }

    /// Signs an AAT for `aat_commitment` and returns its CWT encoding.
    ///
    /// # Errors
    /// [`IssueError::KeyNotValid`] if `now` is outside `[not_before, not_after - lifetime)`;
    /// [`IssueError::Token`] if the token can not be built or encoded.
    pub fn issue(
        &self,
        aat_commitment: FieldElement,
        sec_flags: SecFlags,
        now: u64,
    ) -> Result<Vec<u8>, IssueError> {
        if !(self.not_before..self.signing_end()).contains(&now) {
            return Err(IssueError::KeyNotValid);
        }
        let exp = u32::try_from(now)
            .ok()
            .and_then(|now| now.checked_add(self.lifetime_secs))
            .ok_or_else(|| eyre::eyre!("AAT expiry does not fit in a u32"))?;
        let token = AuthenticatorAssertionToken::new(exp, aat_commitment, sec_flags)
            .map_err(eyre::Report::from)?;
        Ok(token.sign(&self.key).map_err(eyre::Report::from)?)
    }

    /// The Authenticator Metadata document (WIP-106 §3.8). The key is `retired` once it stops
    /// signing.
    ///
    /// # Errors
    /// If the public key can not be encoded.
    pub fn metadata(&self, now: u64) -> eyre::Result<AuthenticatorMetadata> {
        let public = self.key.public();
        Ok(AuthenticatorMetadata {
            version: 1,
            provider_id: self.provider_id.clone(),
            authenticator_provider_keys: vec![AuthenticatorProviderKey {
                kid: hex::encode(public.to_compressed_bytes()?),
                x: FieldElement::from(public.pk.x).to_string(),
                y: FieldElement::from(public.pk.y).to_string(),
                status: if now < self.signing_end() {
                    "active"
                } else {
                    "retired"
                },
                not_before: self.not_before,
                not_after: self.not_after,
            }],
            sec_meta: serde_json::Map::new(),
        })
    }
}

/// `/.well-known/world-id-authenticator.json` (WIP-106 Appendix A2).
#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthenticatorMetadata {
    pub version: u32,
    pub provider_id: String,
    pub authenticator_provider_keys: Vec<AuthenticatorProviderKey>,
    /// No `sec_meta` bits are defined, so none are ever set.
    pub sec_meta: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthenticatorProviderKey {
    pub kid: String,
    pub x: String,
    pub y: String,
    pub status: &'static str,
    pub not_before: u64,
    pub not_after: u64,
}

#[cfg(test)]
mod tests {
    use world_id_primitives::authenticator_assertion::{
        Platform, SecLevel, SignedAuthenticatorAssertionToken, UserPresence,
    };

    use super::*;

    const NOW: u64 = 1_783_446_000;

    /// Valid from `NOW - 100`; signs until `NOW + 100`, then expires its last tokens.
    fn issuer() -> AatIssuer {
        AatIssuer::new(
            EdDSAPrivateKey::from_bytes([7u8; 32]),
            "test".into(),
            NOW - 100,
            NOW + 100 + u64::from(DEFAULT_AAT_LIFETIME_SECS),
            DEFAULT_AAT_LIFETIME_SECS,
        )
    }

    fn flags() -> SecFlags {
        SecFlags::new(
            Platform::Ios.into(),
            SecLevel::HardwareKey.into(),
            2006,
            0,
            UserPresence::Undetermined,
        )
        .unwrap()
    }

    #[test]
    fn issued_token_decodes_and_verifies() {
        let issuer = issuer();
        let commitment = FieldElement::from(42u64);
        let cwt = issuer.issue(commitment, flags(), NOW).unwrap();

        let decoded = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();
        assert_eq!(decoded.token.aat_commitment(), commitment);
        assert_eq!(decoded.token.sec_flags(), flags());
        assert_eq!(
            u64::from(decoded.token.exp()),
            NOW + u64::from(DEFAULT_AAT_LIFETIME_SECS)
        );
        assert!(
            issuer
                .key
                .public()
                .verify(*decoded.token.message_hash(), &decoded.signature)
        );
    }

    #[test]
    fn signs_only_while_tokens_expire_within_key_validity() {
        let issuer = issuer();
        let issue = |now| issuer.issue(FieldElement::ZERO, flags(), now);
        assert!(issue(NOW - 100).is_ok());
        assert!(issue(NOW + 99).is_ok());
        assert!(matches!(issue(NOW - 101), Err(IssueError::KeyNotValid)));
        assert!(matches!(issue(NOW + 100), Err(IssueError::KeyNotValid)));
    }

    #[test]
    fn metadata_matches_spec_test_vector_key() {
        // WIP-106 Appendix A1 uses the same key.
        let key = &issuer().metadata(NOW).unwrap().authenticator_provider_keys[0];
        assert_eq!(
            key.kid,
            "2d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987"
        );
        assert_eq!(key.status, "active");
    }

    #[test]
    fn metadata_retires_key_once_it_stops_signing() {
        let metadata = issuer().metadata(NOW + 100).unwrap();
        assert_eq!(metadata.authenticator_provider_keys[0].status, "retired");
    }

    #[test]
    #[should_panic(expected = "at most 180 days")]
    fn rejects_overlong_key_validity() {
        let _ = AatIssuer::new(
            EdDSAPrivateKey::from_bytes([7u8; 32]),
            "test".into(),
            0,
            MAX_KEY_VALIDITY_SECS + 1,
            DEFAULT_AAT_LIFETIME_SECS,
        );
    }
}
