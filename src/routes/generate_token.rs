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
            let token = android::verify_token(
                &request.integrity_token,
                &request.bundle_identifier,
                &request.request_hash,
            )
            .map_err(|mut e| {
                if let Some(failed_token) = e.failed_integrity_token.take() {
                    // TODO: Log to failed tokens repository
                    println!("Failed token: {failed_token:?}");
                }

                RequestError {
                    code: e.request_error.code,
                    internal_details: e.request_error.internal_details,
                }
            });

            // TODO: Use token data here
            println!("Parsed token: {token:?}");
        }
        Platform::AppleIOS => {}
    }

    let response = TokenGenerationResponse {
        attestation_gateway_token: "my_token".to_string(),
    };

    Ok(Json(response))
}
