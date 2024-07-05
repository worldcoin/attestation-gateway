use axum::http::StatusCode;
use axum_jsonschema::Json;

use crate::{
    android,
    utils::{Platform, TokenGenerationRequest, TokenGenerationResponse},
};

pub async fn handler(
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, StatusCode> {
    // Verify the integrity token
    match request.bundle_identifier.platform() {
        Platform::Android => {
            // TODO: Error response text
            android::verify_token(&request.integrity_token, &request.bundle_identifier)
                .map_err(|_e| StatusCode::BAD_REQUEST)?
        }
        Platform::AppleIOS => {}
    }

    let response = TokenGenerationResponse {
        attestation_gateway_token: "my_token".to_string(),
    };
    Ok(Json(response))
}
