use std::{
    collections::HashSet,
    sync::{Arc, LazyLock},
};

use regex::Regex;
use thiserror::Error;

use crate::utils::GlobalConfig;

// Starts with "app_" or "app_staging_" followed by 32 lowercase hex characters
static APP_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^app(_staging)?_[a-f0-9]{32}$").expect("valid app ID regex"));
// Starts with "rp_" followed by 16 hexadecimal characters (case-insensitive)
static RP_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^rp_[0-9a-fA-F]{16}$").expect("valid RP ID regex"));

#[derive(Debug, Error)]
pub enum AudienceAuthorizationError {
    #[error("audience is not authorized")]
    NotAuthorized,
}

#[derive(Clone)]
pub struct AudienceAuthorizer {
    static_audiences: Arc<HashSet<String>>,
}

impl AudienceAuthorizer {
    #[must_use]
    pub fn from_config(global_config: &GlobalConfig) -> Self {
        Self {
            static_audiences: Arc::new(global_config.aud_whitelist.iter().cloned().collect()),
        }
    }

    /// Authorizes static allowlist entries and well-formed app and RP IDs for nonce creation.
    ///
    /// # Errors
    /// Returns an error for other audiences.
    pub fn ensure_authorized(&self, aud: &str) -> Result<(), AudienceAuthorizationError> {
        if self.static_audiences.contains(aud)
            || APP_ID_REGEX.is_match(aud)
            || RP_ID_REGEX.is_match(aud)
        {
            return Ok(());
        }

        Err(AudienceAuthorizationError::NotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::AudienceAuthorizer;

    #[test]
    fn static_allowlist_authorizes_domains() {
        let authorizer = AudienceAuthorizer {
            static_audiences: std::sync::Arc::new(
                ["face.worldcoin.org".to_owned()].into_iter().collect(),
            ),
        };

        authorizer.ensure_authorized("face.worldcoin.org").unwrap();
    }

    #[test]
    fn app_and_rp_ids_are_authorized_without_external_services() {
        let authorizer = AudienceAuthorizer {
            static_audiences: std::sync::Arc::default(),
        };

        for aud in [
            "app_0123456789abcdef0123456789abcdef",
            "app_staging_0123456789abcdef0123456789abcdef",
            "rp_0123456789abcdef",
            "rp_0123456789ABCDEF",
        ] {
            authorizer.ensure_authorized(aud).unwrap();
        }
    }

    #[test]
    fn unknown_domains_and_malformed_ids_are_denied() {
        let authorizer = AudienceAuthorizer {
            static_audiences: std::sync::Arc::default(),
        };

        for aud in [
            "unknown.worldcoin.org",
            "",
            "app_/../../../../public/v1/miniapps/prices",
            "app_0123456789abcdef0123456789abcde",
            "rp_0123456789abcde",
            "rp_0123456789abcdef0",
            "rp_0123456789abcdeg",
        ] {
            authorizer.ensure_authorized(aud).unwrap_err();
        }
    }
}
