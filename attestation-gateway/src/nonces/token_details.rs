use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTime};

fn serialize_system_time<S>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let t: DateTime<Utc> = (*t).into();
    let rfc3339 = t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    s.serialize_str(&rfc3339)
}

fn deserialize_system_time<'de, D>(d: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let rfc3339 = String::deserialize(d)?;
    let dt = DateTime::parse_from_rfc3339(&rfc3339).map_err(serde::de::Error::custom)?;
    let s: SystemTime = dt.into();

    Ok(s)
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
    #[must_use]
    pub fn from_aud(aud: String) -> Self {
        let ttl = Duration::from_mins(5);

        let exp = SystemTime::now() + ttl;

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

        assert!(json.contains("\"aud\":\"android\""));
        assert!(json.contains("\"exp\":"));
    }

    #[test]
    fn test_deserialize_from_json() {
        let json = r#"{"aud":"test-audience","exp":"2001-09-09T01:46:40.000Z"}"#;
        let token_details: TokenDetails = serde_json::from_str(json).unwrap();

        assert_eq!(token_details.aud, "test-audience");
        assert_eq!(
            token_details.exp,
            SystemTime::from(DateTime::parse_from_rfc3339("2001-09-09T01:46:40.000Z").unwrap())
        );
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let original = TokenDetails::from_aud("roundtrip-aud".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TokenDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.aud, original.aud);
        assert_eq!(
            deserialized
                .exp
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            original.exp.duration_since(UNIX_EPOCH).unwrap().as_millis()
        );
    }
}
