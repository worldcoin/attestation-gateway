use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperTokenExtraClaims {
    pub public_key: String,
}

/// Claims contained within a developer token's inner JWT.
///
/// This represents the payload of the inner JWT that is embedded within the outer actor token's
/// certificate field. The inner JWT contains the developer's public key and standard JWT claims.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperTokenClaims {
    /// Token expiration time (Unix timestamp)
    pub exp: f64,
    /// Token issued at time (Unix timestamp)
    pub iat: f64,
    /// Issuer of the token
    pub iss: String,
    /// Subject (typically the developer/user identifier)
    pub sub: String,
    /// The developer's public key (can be in PEM or JWK format)
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ActorTokenExtraClaims {
    pub certificate: String,
}

/// Claims contained within the outer actor token.
///
/// This represents the payload of the outer JWT that wraps the developer token.
/// The outer token contains standard JWT claims along with a certificate field
/// that holds the inner developer token as a JWT string.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ActorTokenClaims {
    /// Token expiration time (Unix timestamp)
    pub exp: f64,
    /// Token issued at time (Unix timestamp)
    pub iat: f64,
    /// JWT ID - unique identifier for this token that contains the request hash
    pub jti: String,
    /// The inner developer token as a JWT string
    pub certificate: String,
}

impl ActorTokenClaims {
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
