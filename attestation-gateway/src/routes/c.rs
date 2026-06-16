use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;

use crate::audience_authorizer::{AudienceAuthorizationError, AudienceAuthorizer};
use crate::nonces::{NonceDb, TokenDetails};
use crate::utils::{ErrorCode, RequestError};

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub aud: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Response {
    pub nonce: String,
    pub token_exp_max: i64,
    pub device_key_expires_at: String,
}

/// Request a nonce to use as part of a challenge in the subsequent attestation request.
/// For android also returns the expiration time that should be set for device key which
/// is also expiration that the generated token will use.
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
    Extension(audience_authorizer): Extension<AudienceAuthorizer>,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let tracing_span =
        tracing::span!(tracing::Level::DEBUG, "c", aud = %request.aud, endpoint = "/c");
    let _enter = tracing_span.enter();

    audience_authorizer.ensure_authorized(&request.aud).await?;

    let token_details = TokenDetails::from_aud(request.aud.clone());
    let nonce = nonce_db.generate_nonce(&token_details).await.map_err(|e| {
        tracing::error!(error = ?e, "Failed to generate nonce.");

        RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to generate nonce.".to_string()),
        }
    })?;

    let device_key_expires_at =
        DateTime::<Utc>::from_timestamp(token_details.exp_max, 0).ok_or(RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to generate device key expires at.".to_string()),
        })?;

    let device_key_expires_at =
        device_key_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    Ok(Json(Response {
        nonce,
        token_exp_max: token_details.exp_max,
        device_key_expires_at,
    }))
}

impl From<AudienceAuthorizationError> for RequestError {
    fn from(error: AudienceAuthorizationError) -> Self {
        match error {
            AudienceAuthorizationError::NotAuthorized => Self {
                code: ErrorCode::BadRequest,
                details: Some("This audience is currently unavailable.".to_owned()),
            },
            error => {
                tracing::error!(error = ?error, "Failed to authorize audience");

                Self {
                    code: ErrorCode::InternalServerError,
                    details: Some("Failed to authorize audience.".to_owned()),
                }
            }
        }
    }
}
