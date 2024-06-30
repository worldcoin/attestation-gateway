use axum::http::StatusCode;
use axum_jsonschema::Json;

use crate::utils::{TokenGenerationRequest, TokenGenerationResponse};

pub async fn handler(
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, StatusCode> {
    println!(
        "Processing for platform: {}",
        request.bundle_identifier.platform()
    );
    let response = TokenGenerationResponse {
        attestation_gateway_token: "my_token".to_string(),
    };
    Ok(Json(response))
}
