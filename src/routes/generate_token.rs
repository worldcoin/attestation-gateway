use axum::Extension;
use axum_jsonschema::Json;
use redis::{aio::ConnectionManager, AsyncCommands};
use std::time::SystemTime;

use crate::{
    android, kms_jws,
    utils::{
        handle_redis_error, DataReport, ErrorCode, GlobalConfig, OutEnum, OutputTokenPayload,
        Platform, RequestError, TokenGenerationRequest, TokenGenerationResponse,
    },
};

static REQUEST_HASH_REDIS_KEY_PREFIX: &str = "request_hash:";

pub async fn handler(
    Extension(kms_client): Extension<aws_sdk_kms::Client>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    // Check the request hash is unique
    if redis
        .exists::<_, bool>(format!(
            "{REQUEST_HASH_REDIS_KEY_PREFIX}{:?}",
            request.request_hash.clone()
        ))
        .await
        .map_err(handle_redis_error)?
    {
        return Err(RequestError {
            code: ErrorCode::DuplicateRequestHash,
            internal_details: Some("Duplicate request hash".to_string()),
        });
    };

    // Prepare output report for logging (analytics & debugging)
    let mut report = DataReport {
        pass: false,
        out: OutEnum::Fail,
        timestamp: SystemTime::now(),
        request_hash: request.request_hash.clone(),
        bundle_identifier: request.bundle_identifier.clone(),
        client_error: request.client_error,
        aud: request.aud.clone(),
        internal_error_details: None,
        play_integrity: None,
    };

    // Verify the Apple/Google integrity token
    match request.bundle_identifier.platform() {
        Platform::Android => {
            match android::verify_token(
                &request.integrity_token,
                &request.bundle_identifier,
                &request.request_hash,
            ) {
                Ok(token) => {
                    report.play_integrity = Some(token);
                    report.pass = true;
                    report.out = OutEnum::Pass;
                }
                Err(e) => {
                    if let Some(failed_token) = e.failed_integrity_token {
                        let unwrapped_token: android::PlayIntegrityToken = *failed_token;
                        report.play_integrity = Some(unwrapped_token);
                    }

                    report.internal_error_details = e.request_error.internal_details;

                    // TODO: Report to Kinesis
                    tracing::debug!("Report: {:?}", report);

                    return Err(RequestError {
                        code: e.request_error.code,
                        internal_details: report.internal_error_details,
                    });
                }
            }
        }
        Platform::AppleIOS => {}
    }

    // TODO: Report to Kinesis
    tracing::debug!("Report: {:?}", report);

    // Generate output attestation token
    let output_token_payload = OutputTokenPayload {
        aud: request.aud,
        request_hash: request.request_hash.clone(),
        pass: report.pass,
        out: report.out,
        error: None, // TODO: Implement in the future
    }
    .generate()?;

    let attestation_gateway_token = kms_jws::generate_output_token(
        kms_client,
        global_config.output_token_kms_key_arn.clone(),
        output_token_payload,
    )
    .await?;

    // Store the request hash in Redis to prevent duplicate use
    redis
        .set_ex::<_, _, ()>(
            format!("{REQUEST_HASH_REDIS_KEY_PREFIX}{:?}", request.request_hash),
            true,
            60 * 60 * 24, // 24 hours
        )
        .await
        .map_err(handle_redis_error)?;

    let response = TokenGenerationResponse {
        attestation_gateway_token,
    };

    Ok(Json(response))
}

// NOTE: Integration tests for route handlers are in the `/tests` module
