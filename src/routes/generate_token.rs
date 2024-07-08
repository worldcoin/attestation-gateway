use axum_jsonschema::Json;

use crate::{
    android,
    utils::{Platform, RequestError, TokenGenerationRequest, TokenGenerationResponse},
};

pub async fn handler(
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    // Verify the integrity token
    match request.bundle_identifier.platform() {
        Platform::Android => {
            // TODO: Error response text
            android::verify_token(
                &request.integrity_token,
                &request.bundle_identifier,
                &request.request_hash,
            )?;
        }
        Platform::AppleIOS => {}
    }

    let response = TokenGenerationResponse {
        attestation_gateway_token: "my_token".to_string(),
    };

    Ok(Json(response))
}
