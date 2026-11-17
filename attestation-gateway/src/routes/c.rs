use axum::{Extension, Json, http::HeaderMap};
use schemars::JsonSchema;
use time::{OffsetDateTime, macros::format_description};

use crate::audience_authorizer::{AudienceAuthorizationError, AudienceAuthorizer};
use crate::nonces::{NonceDb, TokenDetailsFactory};
use crate::utils::{ErrorCode, RequestError, client_session_id};

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
    Extension(token_details_factory): Extension<TokenDetailsFactory>,
    Extension(mut nonce_db): Extension<NonceDb>,
    Extension(audience_authorizer): Extension<AudienceAuthorizer>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let session_id = client_session_id(&headers);
    let tracing_span = tracing::span!(
        tracing::Level::DEBUG,
        "c",
        aud = %request.aud,
        endpoint = "/c",
        session_id = %session_id
    );
    let _enter = tracing_span.enter();

    crate::latency::measure_sync("audience_authorization", || {
        audience_authorizer.ensure_authorized(&request.aud)
    })
    .map_err(|error| {
        tracing::warn!(
            aud = %request.aud,
            endpoint = "/c",
            session_id = %session_id,
            message = "Audience is not authorized"
        );
        RequestError::from(error)
    })?;

    let token_details = token_details_factory.from_aud(request.aud.clone());
    let nonce = crate::latency::measure("nonce_create", nonce_db.generate_nonce(&token_details))
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to generate nonce.");

            RequestError {
                code: ErrorCode::InternalServerError,
                details: Some("Failed to generate nonce.".to_string()),
            }
        })?;

    let device_key_expires_at = format_device_key_expiry(token_details.exp_max)?;

    Ok(Json(Response {
        nonce,
        token_exp_max: token_details.exp_max,
        device_key_expires_at,
    }))
}

fn format_device_key_expiry(timestamp: i64) -> Result<String, RequestError> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to generate device key expires at.".to_string()),
        })?
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to generate device key expires at.".to_string()),
        })
}

impl From<AudienceAuthorizationError> for RequestError {
    fn from(error: AudienceAuthorizationError) -> Self {
        match error {
            AudienceAuthorizationError::NotAuthorized => Self {
                code: ErrorCode::BadRequest,
                details: Some("This audience is currently unavailable.".to_owned()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format_device_key_expiry;
    use time::macros::datetime;

    #[test]
    fn device_key_expiry_preserves_millisecond_utc_wire_format() {
        assert_eq!(
            format_device_key_expiry(0).unwrap(),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            format_device_key_expiry(-1).unwrap(),
            "1969-12-31T23:59:59.000Z"
        );
        assert_eq!(
            format_device_key_expiry(datetime!(2028-02-29 12:34:56 UTC).unix_timestamp()).unwrap(),
            "2028-02-29T12:34:56.000Z"
        );
    }

    #[test]
    fn device_key_expiry_rejects_out_of_range_timestamps() {
        assert!(format_device_key_expiry(i64::MAX).is_err());
        assert!(format_device_key_expiry(i64::MIN).is_err());
    }
}
