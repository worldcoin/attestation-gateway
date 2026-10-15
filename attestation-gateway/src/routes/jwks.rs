use crate::aws_clients::AwsClients;
use axum::{Extension, Json};
use redis::aio::ConnectionManager;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    keys::fetch_all,
    utils::{ErrorCode, RequestError},
};

#[derive(Debug, Serialize, JsonSchema)]
pub struct KeysOutput {
    pub keys: Vec<Map<String, Value>>, // we can't use `josekit::jwk::Jwk` directly because it does not implement the JsonSchema trait
}

pub async fn handler(
    Extension(aws_clients): Extension<AwsClients>,
    Extension(mut redis): Extension<ConnectionManager>,
) -> Result<Json<KeysOutput>, RequestError> {
    let signing_keys = fetch_all(&mut redis, &aws_clients.kms).await.map_err(|e| {
        tracing::error!(error = ?e, "error fetching signing keys.");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    let keys = signing_keys
        .iter()
        .map(|key| key.jwk.clone().into())
        .collect();

    Ok(Json(KeysOutput { keys }))
}

// NOTE: Integration tests for route handlers are in the `/tests` module
