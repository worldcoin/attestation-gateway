use axum::http::StatusCode;
use axum_jsonschema::Json;

use crate::utils::TokenGenerationResponse;

pub async fn handler() -> Result<Json<TokenGenerationResponse>, StatusCode> {
    let response = TokenGenerationResponse {
        attestation_gateway_token: "sample_token".to_string(),
    };
    Ok(Json(response))
}
