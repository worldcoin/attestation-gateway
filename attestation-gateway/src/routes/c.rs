use axum::{Extension, Json};
use chrono::Utc;
use schemars::JsonSchema;

use crate::challenges::{ChallengesDb, TokenDetails};
use crate::utils::{ErrorCode, RequestError};

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub aud: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Response {
    pub challenge: String,
    pub device_key_expires_at: String,
}

pub async fn handler(
    Extension(mut challenges_db): Extension<ChallengesDb>,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let tracing_span =
        tracing::span!(tracing::Level::DEBUG, "c", aud = %request.aud, endpoint = "/c");
    let _enter = tracing_span.enter();

    let token_details = TokenDetails::from_aud(request.aud.clone());
    let challenge = challenges_db
        .create_token_challenge(&token_details)
        .await
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to create token challenge.".to_string()),
        })?;

    let device_key_expires_at: chrono::DateTime<Utc> = token_details.exp.into();
    let device_key_expires_at =
        device_key_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    Ok(Json(Response {
        challenge,
        device_key_expires_at,
    }))
}
