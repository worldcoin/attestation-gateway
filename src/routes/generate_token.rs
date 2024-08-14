use axum::Extension;
use axum_jsonschema::Json;
use redis::{aio::ConnectionManager, AsyncCommands};
use std::time::SystemTime;

use crate::{
    android, apple,
    keys::fetch_active_key,
    kms_jws,
    utils::{
        handle_redis_error, BundleIdentifier, ClientError, DataReport, ErrorCode, GlobalConfig,
        IntegrityVerificationInput, OutEnum, OutputTokenPayload, RequestError,
        TokenGenerationRequest, TokenGenerationResponse,
    },
};

static REQUEST_HASH_REDIS_KEY_PREFIX: &str = "request_hash:";

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(aws_config): Extension<aws_config::SdkConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    let aud = request.aud.clone();
    let request_hash = request.request_hash.clone();

    let integrity_verification_input = IntegrityVerificationInput::from_request(&request)?;

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

    let report = verify_android_or_apple_integrity(
        integrity_verification_input,
        request.request_hash,
        request.bundle_identifier,
        &request.aud,
        request.client_error,
        global_config.clone(),
        &aws_config,
    )
    .await
    .map_err(|e| {
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

    let key = fetch_active_key(&mut redis, &aws_config)
        .await
        .map_err(|e| {
            tracing::error!(?e, "Error fetching active key");
            RequestError {
                code: ErrorCode::InternalServerError,
                details: None,
            }
        })?;

    let attestation_gateway_token =
        kms_jws::generate_output_token(&aws_config, key.key_definition.arn, output_token_payload)
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

async fn verify_android_or_apple_integrity(
    verification_input: IntegrityVerificationInput,
    request_hash: String,
    bundle_identifier: BundleIdentifier,
    aud: &str,
    client_error: Option<String>,
    config: GlobalConfig,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<DataReport> {
    // Prepare output report for logging (analytics & debugging)
    // Only integrity failures and successes are logged to Kinesis. Client and server errors are logged regularly to Datadog.
    let mut report = DataReport {
        pass: false,
        out: OutEnum::Fail,
        timestamp: SystemTime::now(),
        request_hash: request_hash.clone(),
        bundle_identifier: bundle_identifier.clone(),
        client_error: client_error.clone(),
        aud: aud.to_string(),
        internal_debug_info: None,
        play_integrity: None,
    };

    let verify_result = match verification_input {
        IntegrityVerificationInput::Android { integrity_token } => android::verify(
            &integrity_token,
            &bundle_identifier,
            &request_hash,
            config.android_outer_jwe_private_key,
        )?,
        IntegrityVerificationInput::AppleInitialAttestation {
            apple_initial_attestation,
        } => {
            apple::verify_initial_attestation(
                apple_initial_attestation,
                bundle_identifier,
                request_hash,
                aws_config,
                &config.apple_keys_dynamo_table_name,
            )
            .await?
        }

        IntegrityVerificationInput::AppleAssertion {
            apple_assertion,
            apple_public_key,
        } => {
            apple::verify(
                apple_assertion,
                apple_public_key,
                &bundle_identifier,
                &request_hash,
                aws_config,
                &config.apple_keys_dynamo_table_name,
            )
            .await?
        }
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
