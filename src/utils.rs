use schemars::JsonSchema;

#[derive(Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct TokenGenerationRequest {
    pub integrity_token: String,
    pub client_error: Option<String>,
    pub aud: String,
    pub bundle_identifier: String,
    pub request_hash: String,
    pub apple_initial_attestation: String,
    pub apple_public_key: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TokenGenerationResponse {
    pub attestation_gateway_token: String,
}
