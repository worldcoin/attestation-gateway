use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn serialize_system_time<S>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| serde::ser::Error::custom("exp time is before UNIX_EPOCH"))
        .and_then(|secs| s.serialize_u64(secs))
}

fn deserialize_system_time<'de, D>(d: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(d)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenDetails {
    pub aud: String,

    #[serde(
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub exp: SystemTime,
}

impl TokenDetails {
    pub fn from_aud(aud: String) -> Self {
        let ttl_seconds = match aud.as_str() {
            _ => 3600,
        };

        let exp = SystemTime::now() + Duration::from_secs(ttl_seconds);

        Self { aud, exp }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_from_aud() {
        let token_details = TokenDetails::from_aud("android".to_string());
        assert_eq!(token_details.aud, "android");
        assert!(token_details.exp > SystemTime::now());
    }

    #[test]
    fn test_to_json() {
        let token_details = TokenDetails::from_aud("android".to_string());
        let json = serde_json::to_string(&token_details).unwrap();
        println!("json: {}", json);
        assert!(json.contains("\"aud\":\"android\""));
        assert!(json.contains("\"exp\":"));
    }

    #[test]
    fn test_deserialize_from_json() {
        let json = r#"{"aud":"test-audience","exp":1000000000}"#;
        let token_details: TokenDetails = serde_json::from_str(json).unwrap();
        assert_eq!(token_details.aud, "test-audience");
        assert_eq!(
            token_details
                .exp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1000000000
        );
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let original = TokenDetails::from_aud("roundtrip-aud".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TokenDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.aud, original.aud);
        // Serialization uses whole seconds only, so compare secs
        assert_eq!(
            deserialized
                .exp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            original.exp.duration_since(UNIX_EPOCH).unwrap().as_secs()
        );
    }
}
