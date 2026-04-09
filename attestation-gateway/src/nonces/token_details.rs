use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenDetails {
    pub aud: String,
    pub exp_max: i64,
}

impl TokenDetails {
    #[must_use]
    pub fn from_aud(aud: String) -> Self {
        let now = DateTime::<Utc>::from(SystemTime::now());
        let ttl = Duration::from_mins(5);
        let exp_max = (now + ttl).timestamp();

        Self { aud, exp_max }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_aud() {
        let token_details = TokenDetails::from_aud("android".to_string());

        assert_eq!(token_details.aud, "android");
        assert!(token_details.exp_max > DateTime::<Utc>::from(SystemTime::now()).timestamp());
    }

    #[test]
    fn test_to_json() {
        let token_details = TokenDetails::from_aud("android".to_string());
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
        let original = TokenDetails::from_aud("roundtrip-aud".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TokenDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.aud, original.aud);
        assert_eq!(deserialized.exp_max, original.exp_max);
    }
}
