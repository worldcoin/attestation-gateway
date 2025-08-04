use openssl::sha::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AllowedHttpMethod {
    Get,
    Post,
}

impl AllowedHttpMethod {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Get => b"GET",
            Self::Post => b"POST",
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientName {
    Ios,
    Android,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenerateRequestHashInput {
    path_uri: String,
    method: AllowedHttpMethod,
    body: Option<String>,
}

pub struct RequestHasher {}

/// This is an implementation of the Request Hasher.
/// It takes in a request and returns a hash of the request in a consistent format
/// with the fields sorted alphabetically.
/// [Reference](https://www.notion.so/worldcoin/Consistent-JSON-Serialization-and-Hashing-37e9585165674770a9751bc72e3dbb44?pvs=4)
impl RequestHasher {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Generate a hash of a **JSON request** in a consistent format with the fields sorted alphabetically.
    ///
    /// # Errors
    /// This function will return an error if the input JSON is invalid.
    pub fn generate_json_request_hash(
        &self,
        input: &GenerateRequestHashInput,
    ) -> Result<String, eyre::Error> {
        let mut map = serde_json::Map::new();
        if let Some(body_str) = &input.body {
            let body_json: Value = serde_json::from_str(body_str)?;
            map.insert("body".to_string(), sort_json(&body_json));
        }

        map.insert("method".to_string(), serde_json::json!(input.method));
        map.insert("pathUri".to_string(), serde_json::json!(input.path_uri));

        let serialized = serde_json::to_string(&map)?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        Ok(hex::encode(hasher.finish()))
    }
}

// Helper function to recursively sort JSON objects by their keys
fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted_map = serde_json::Map::new();
            let mut sorted_keys: Vec<_> = map.keys().collect();
            sorted_keys.sort();

            for key in sorted_keys {
                sorted_map.insert(key.clone(), sort_json(&map[key]));
            }

            Value::Object(sorted_map)
        }
        Value::Array(vec) => Value::Array(vec.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
pub mod test;
