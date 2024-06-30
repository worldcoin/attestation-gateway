use axum::http::StatusCode;
use axum_jsonschema::Json;

use crate::utils::{TokenGenerationRequest, TokenGenerationResponse};

pub async fn handler(
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, StatusCode> {
    let response = TokenGenerationResponse {
        attestation_gateway_token: request.bundle_identifier,
    };
    Ok(Json(response))
}
