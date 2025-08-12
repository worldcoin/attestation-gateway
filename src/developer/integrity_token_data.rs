use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperInnerTokenExtraClaims {
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperInnerTokenClaims {
    pub exp: f64,
    pub iat: f64,
    pub iss: String,
    pub sub: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperOuterTokenExtraClaims {
    pub certificate: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperOuterTokenClaims {
    pub exp: f64,
    pub iat: f64,
    pub jti: String,
    pub certificate: String,
}

impl DeveloperOuterTokenClaims {
    /// Parses a Tools for Humanity outer JWT token from a JSON string
    ///
    /// # Errors
    ///
    /// Returns an error if the JWT is invalid or the payload cannot be parsed
    pub fn from_json(json: &str) -> eyre::Result<Self> {
        let parts: Vec<&str> = json.split('.').collect();
        if parts.len() != 3 {
            eyre::bail!("Invalid JWT format: expected 3 parts");
        }

        let payload_b64 = parts[1];

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
            .map_err(|e| eyre::eyre!("Failed to decode JWT payload as base64url: {e}"))?;

        let parsed_payload: Self = serde_json::from_slice(&payload_bytes)?;

        Ok(parsed_payload)
    }
}
