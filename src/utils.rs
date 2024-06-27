use schemars::JsonSchema;

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TokenGenerationResponse {
    pub attestation_gateway_token: String,
}
