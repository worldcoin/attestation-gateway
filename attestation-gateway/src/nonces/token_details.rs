use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::utils::{GlobalConfig, TokenExpiration};

const DEFAULT_TOKEN_EXP_MAX: Duration = Duration::from_mins(5);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenDetails {
    pub aud: String,
    pub exp_max: i64,
}

/// Builds [`TokenDetails`] with the `/a` token lifetime configured for each `aud`.
#[derive(Debug, Clone, Default)]
pub struct TokenDetailsFactory {
    exp_max_by_aud: HashMap<String, TokenExpiration>,
}

impl TokenDetailsFactory {
    #[must_use]
    pub fn from_config(global_config: &GlobalConfig) -> Self {
        Self {
            exp_max_by_aud: global_config.token_exp_max_by_aud.clone(),
        }
    }

    #[must_use]
    pub fn from_aud(&self, aud: String) -> TokenDetails {
        let ttl = self
            .exp_max_by_aud
            .get(&aud)
            .map_or(DEFAULT_TOKEN_EXP_MAX, |ttl| ttl.as_duration());
        metrics::counter!("attestation_gateway.token_exp_max", "ttl_secs" => ttl.as_secs().to_string())
            .increment(1);

        let now = DateTime::<Utc>::from(SystemTime::now());
        let exp_max = (now + ttl).timestamp();

        TokenDetails { aud, exp_max }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factory_with(json: &str) -> TokenDetailsFactory {
        TokenDetailsFactory {
            exp_max_by_aud: serde_json::from_str(json).unwrap(),
        }
    }

    fn assert_expires_in(token_details: &TokenDetails, ttl: Duration) {
        let now = DateTime::<Utc>::from(SystemTime::now()).timestamp();
        let ttl = i64::try_from(ttl.as_secs()).unwrap();
        assert!((now + ttl - 1..=now + ttl).contains(&token_details.exp_max));
    }

    #[test]
    fn test_from_aud_uses_override_for_listed_aud_only() {
        let factory = factory_with(r#"{"app.orb.worldcoin.org": 1800}"#);

        let orb = factory.from_aud("app.orb.worldcoin.org".to_string());
        assert_eq!(orb.aud, "app.orb.worldcoin.org");
        assert_expires_in(&orb, Duration::from_mins(30));

        let face = factory.from_aud("app.face.worldcoin.org".to_string());
        assert_expires_in(&face, DEFAULT_TOKEN_EXP_MAX);
    }

    #[test]
    fn test_to_json() {
        let token_details = TokenDetailsFactory::default().from_aud("android".to_string());
        let json = serde_json::to_string(&token_details).unwrap();

        assert!(json.contains("\"aud\":\"android\""));
        assert!(json.contains("\"exp_max\":"));
    }

    #[test]
    fn test_deserialize_from_json() {
        let json = r#"{"aud":"test-audience","exp_max":1000000000}"#;
        let token_details: TokenDetails = serde_json::from_str(json).unwrap();

        assert_eq!(token_details.aud, "test-audience");
        assert_eq!(token_details.exp_max, 1000000000);
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let original = TokenDetailsFactory::default().from_aud("roundtrip-aud".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TokenDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.aud, original.aud);
        assert_eq!(deserialized.exp_max, original.exp_max);
    }
}
