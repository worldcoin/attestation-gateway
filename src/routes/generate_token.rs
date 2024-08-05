use axum::Extension;
use axum_jsonschema::Json;
use redis::{aio::ConnectionManager, AsyncCommands};
use std::time::SystemTime;

use crate::{
    android, apple, kms_jws,
    utils::{
        handle_redis_error, ClientError, DataReport, ErrorCode, GlobalConfig, OutEnum,
        OutputTokenPayload, Platform, RequestError, TokenGenerationRequest,
        TokenGenerationResponse,
    },
};

static REQUEST_HASH_REDIS_KEY_PREFIX: &str = "request_hash:";

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(kms_client): Extension<aws_sdk_kms::Client>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    let aud = request.aud.clone();
    let request_hash = request.request_hash.clone();

    // Platform-specific request validation
    match request.bundle_identifier.platform() {
        Platform::Android => {
            if request.integrity_token.is_none() {
                return Err(RequestError {
                    code: ErrorCode::BadRequest,
                    details: Some(
                        "`integrity_token` is required for this bundle identifier.".to_string(),
                    ),
                });
            }
        }
        Platform::AppleIOS => {
            if request.apple_assertion.is_none() || request.apple_public_key.is_none() {
                return Err(RequestError {
                    code: ErrorCode::BadRequest,
                    details: Some(
                        "`apple_assertion` and `apple_public_key` is required for this bundle identifier."
                            .to_string(),
                    ),
                });
            }
        }
    }

    // Check the request hash is unique
    if redis
        .exists::<_, bool>(format!(
            "{REQUEST_HASH_REDIS_KEY_PREFIX}{:?}",
            request_hash.clone()
        ))
        .await
        .map_err(handle_redis_error)?
    {
        return Err(RequestError {
            code: ErrorCode::DuplicateRequestHash,
            details: None,
        });
    };

    let report =
        verify_android_or_apple_integrity(request, global_config.clone()).map_err(|e| {
            // Check if we have a ClientError in the error chain and return to the client without further logging
            if let Some(client_error) = e.downcast_ref::<ClientError>() {
                return RequestError {
                    code: client_error.code,
                    details: None,
                };
            }

            tracing::error!(?e, "Error verifying Android or Apple integrity");
            RequestError {
                code: ErrorCode::InternalServerError,
                details: None,
            }
        })?;

    // FIXME: Report to Kinesis
    tracing::debug!("Report: {:?}", report);

    // TODO: Initial roll out does not include generating failure tokens
    if !report.pass {
        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            details: None,
        });
    }

    // Generate output attestation token
    let output_token_payload = OutputTokenPayload {
        aud,
        request_hash: request_hash.clone(),
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
    .await
    .map_err(|e| {
        tracing::error!(?e, "Error generating output token");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    // Store the request hash in Redis to prevent duplicate use
    redis
        .set_ex::<_, _, ()>(
            format!("{REQUEST_HASH_REDIS_KEY_PREFIX}{:?}", request_hash.clone()),
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

fn verify_android_or_apple_integrity(
    request: TokenGenerationRequest,
    config: GlobalConfig,
) -> eyre::Result<DataReport> {
    // Prepare output report for logging (analytics & debugging)
    // Only integrity failures and successes are logged to Kinesis. Client and server errors are logged regularly to Datadog.
    let mut report = DataReport {
        pass: false,
        out: OutEnum::Fail,
        timestamp: SystemTime::now(),
        request_hash: request.request_hash.clone(),
        bundle_identifier: request.bundle_identifier.clone(),
        client_error: request.client_error,
        aud: request.aud.clone(),
        internal_debug_info: None,
        play_integrity: None,
    };

    let verify_result = match request.bundle_identifier.platform() {
        Platform::Android => android::verify(
            &request.integrity_token.unwrap(), // Safe to unwrap because we've already validated this in the handler
            &request.bundle_identifier,
            &request.request_hash,
            config.android_outer_jwe_private_key,
        )?,

        Platform::AppleIOS => apple::verify(
            &request.apple_assertion.unwrap(),
            &request.apple_public_key.unwrap(),
            request.apple_initial_attestation.as_ref(),
        )?,
    };

    report.play_integrity = verify_result.parsed_play_integrity_token;
    report.pass = verify_result.success;
    report.out = if verify_result.success {
        OutEnum::Pass
    } else {
        OutEnum::Fail
    };
    report.internal_debug_info = verify_result
        .client_error
        .map(|err| err.internal_debug_info);

    Ok(report)
}
