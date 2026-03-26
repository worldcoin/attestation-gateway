use axum::{Extension, Json};
use chrono::Utc;
use schemars::JsonSchema;

use crate::nonces::{NonceDb, TokenDetails};
use crate::utils::{ErrorCode, GlobalConfig, RequestError};

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub aud: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Response {
    pub nonce: String,
    pub device_key_expires_at: String,
}

/// Request a nonce to use as part of a challenge in the subsequent attestation request.
/// For android also returns the expiration time that should be set for device key which
/// ia also expiration that token generated will use.
///
/// # Example
///
/// Request:
/// ```json
/// {
///     "aud": "android"
/// }
/// ```
///
/// Response:
/// ```json
/// {
///     "nonce": "1234567890",
///     "device_key_expires_at": "2026-03-26T12:00:00Z"
/// }
/// ```
pub async fn handler(
    Extension(mut nonce_db): Extension<NonceDb>,
    Extension(global_config): Extension<GlobalConfig>,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let tracing_span =
        tracing::span!(tracing::Level::DEBUG, "c", aud = %request.aud, endpoint = "/c");
    let _enter = tracing_span.enter();

    if !global_config.aud_whitelist.contains(&request.aud) {
        return Err(RequestError {
            code: ErrorCode::BadRequest,
            details: Some("This audience is currently unavailable.".to_string()),
        });
    }

    let token_details = TokenDetails::from_aud(request.aud.clone());
    let nonce = nonce_db
        .generate_nonce(&token_details)
        .await
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to generate nonce.".to_string()),
        })?;

    let device_key_expires_at: chrono::DateTime<Utc> = token_details.exp.into();
    let device_key_expires_at =
        device_key_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    Ok(Json(Response {
        nonce,
        device_key_expires_at,
    }))
}
