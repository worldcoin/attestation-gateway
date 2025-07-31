use crate::tools_for_humanity;
use aws_sdk_kinesis::Client as KinesisClient;
use axum::Extension;
use axum_jsonschema::Json;
use redis::{aio::ConnectionManager, AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};
use std::time::SystemTime;

use crate::{
    android, apple,
    keys::fetch_active_key,
    kinesis::send_kinesis_stream_event,
    kms_jws,
    utils::{
        handle_redis_error, BundleIdentifier, ClientException, DataReport, ErrorCode, GlobalConfig,
        IntegrityVerificationInput, OutEnum, OutputTokenPayload, RequestError,
        TokenGenerationRequest, TokenGenerationResponse, VerificationOutput,
    },
};

const REQUEST_HASH_REDIS_KEY_PREFIX: &str = "request_hash:";
const REQUEST_HASH_CACHE_TTL: u64 = 60 * 60 * 24; // 24 hours

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(aws_config): Extension<aws_config::SdkConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Extension(kinesis_client): Extension<KinesisClient>,
    Extension(tfh_user): Extension<tools_for_humanity::User>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    let aud = request.aud.clone();
    let request_hash = request.request_hash.clone();

    let my_span = tracing::span!(
        tracing::Level::DEBUG,
        "generate_token",
        request_hash = %request_hash,
        endpoint = "/g"
    );

    let _enter = my_span.enter();

    let integrity_verification_input =
        IntegrityVerificationInput::from_request(&request, &Some(tfh_user))?;

    handle_client_error_if_applicable(
        &integrity_verification_input,
        &request,
        &kinesis_client,
        global_config.kinesis_stream_arn.as_deref().unwrap_or(""),
        global_config.log_client_errors,
    )
    .await?;

    if !global_config
        .enabled_bundle_identifiers
        .contains(&request.bundle_identifier)
    {
        return Err(RequestError {
            code: ErrorCode::BadRequest,
            details: Some("This bundle identifier is currently unavailable.".to_string()),
        });
    }

    metrics::counter!("generate_token",  "bundle_identifier" => request.bundle_identifier.to_string()).increment(1);

    // Lock the `request_hash` in Redis to prevent duplicate requests and race conditions
    let lock_set = set_redis_lock(request_hash.clone(), &mut redis).await?;
    if !lock_set {
        return Err(RequestError {
            code: ErrorCode::DuplicateRequestHash,
            details: None,
        });
    }

    // REVIEW: failures from DataReport.pass vs. ClientException
    let report = verify_android_or_apple_integrity(
        integrity_verification_input,
        request_hash.clone(),
        request.bundle_identifier.clone(),
        &request.aud,
        request.client_error,
        global_config.clone(),
        &aws_config,
    )
    .await
    .map_err(|e| {
        // Check if we have a `ClientException` in the error chain and return to the client without further logging
        if let Some(client_error) = e.downcast_ref::<ClientException>() {
            if global_config.log_client_errors {
                tracing::info!(error = ?e, request_hash = request_hash, bundle_identifier = %request.bundle_identifier, "Client exception verifying Android or Apple integrity");
            }else {
                tracing::debug!(error = ?e, "Client exception verifying Android or Apple integrity");
            }

            metrics::counter!("generate_token.client_exception",  "bundle_identifier" => request.bundle_identifier.to_string(), "error_code" => client_error.code.to_string()).increment(1);

            return RequestError {
                code: client_error.code,
                details: None,
            };
        }

        tracing::error!(error = ?e, "Error verifying Android or Apple integrity");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    });

    // If the report is an error, release the request hash to allow re-use and return the error
    let report = match report {
        Err(e) => {
            let _ = release_request_hash(request_hash, &mut redis).await;
            return Err(e);
        }
        Ok(value) => value,
    };

    let response = match process_and_finalize_report(
        &global_config,
        report,
        request_hash.clone(),
        aud,
        &mut redis,
        aws_config,
        &kinesis_client,
        global_config.kinesis_stream_arn.as_deref().unwrap_or(""),
    )
    .await
    {
        Ok(res) => res,
        Err(err) => {
            let _ = release_request_hash(request_hash, &mut redis).await;
            return Err(err);
        }
    };

    metrics::counter!("generate_token.success",  "bundle_identifier" => request.bundle_identifier.to_string()).increment(1);

    Ok(Json(response))
}

async fn set_redis_lock(
    request_hash: String,
    redis: &mut ConnectionManager,
) -> Result<bool, RequestError> {
    let request_hash_lock_options = SetOptions::default()
        .conditional_set(ExistenceCheck::NX)
        .with_expiration(SetExpiry::EX(REQUEST_HASH_CACHE_TTL));

    let lock_set = redis
        .set_options::<String, bool, bool>(
            format!("{REQUEST_HASH_REDIS_KEY_PREFIX}{:}", request_hash.clone()),
            true,
            request_hash_lock_options,
        )
        .await
        .map_err(handle_redis_error)?;

    Ok(lock_set)
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
        app_version: None,
    };

    let verify_result = match verification_input {
        IntegrityVerificationInput::Android { integrity_token } => android::verify(
            &integrity_token,
            &bundle_identifier,
            &request_hash,
            config.android_outer_jwe_private_key,
            config.android_inner_jws_public_key,
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

        IntegrityVerificationInput::ClientError { client_error: _ } => {
            eyre::bail!("Unexpected variant reached in verify_android_or_apple_integrity.");
        }

        IntegrityVerificationInput::ToolsForHumanity { principal } => {
            tracing::info!(principal = principal, "Tools for Humanity verification");
            VerificationOutput {
                success: true,
                app_version: None,
                parsed_play_integrity_token: None,
                client_exception: None,
            }
        }
    };

    report.play_integrity = verify_result.parsed_play_integrity_token;
    report.pass = verify_result.success;
    report.app_version = verify_result.app_version;
    report.out = if verify_result.success {
        OutEnum::Pass
    } else {
        OutEnum::Fail
    };
    report.internal_debug_info = verify_result
        .client_exception
        .map(|err| err.internal_debug_info);

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn process_and_finalize_report(
    global_config: &GlobalConfig,
    report: DataReport,
    request_hash: String,
    aud: String,
    redis: &mut ConnectionManager,
    aws_config: aws_config::SdkConfig,
    kinesis_client: &KinesisClient,
    kinesis_stream_arn: &str,
) -> Result<TokenGenerationResponse, RequestError> {
    // Report result to Kinesis
    if !kinesis_stream_arn.is_empty() {
        if let Err(e) = send_kinesis_stream_event(kinesis_client, kinesis_stream_arn, &report).await
        {
            tracing::error!("Failed to send Kinesis event: {:?}", e);
        }
    }

    // TODO: Initial roll out does not include generating failure tokens
    if !report.pass {
        if global_config.log_client_errors {
            tracing::info!(
                request_hash = request_hash,
                bundle_identifier = %report.bundle_identifier,
                message = "Integrity verification failed",
                internal_debug_info = report.internal_debug_info
            );
        }
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
        error: None, // TODO: Implement in the future (see L76)
        app_version: report.app_version.clone(),
    }
    .generate()?;

    let key = fetch_active_key(redis, &aws_config).await.map_err(|e| {
        tracing::error!(error = ?e, "Error fetching active key");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    let attestation_gateway_token =
        kms_jws::generate_output_token(&aws_config, key.key_definition.arn, output_token_payload)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Error generating output token");
                RequestError {
                    code: ErrorCode::InternalServerError,
                    details: None,
                }
            })?;

    let response = TokenGenerationResponse {
        attestation_gateway_token,
    };

    Ok(response)
}

async fn release_request_hash(
    request_hash: String,
    redis: &mut ConnectionManager,
) -> Result<(), RequestError> {
    redis
        .del::<String, usize>(format!("{REQUEST_HASH_REDIS_KEY_PREFIX}{request_hash}"))
        .await
        .map_err(handle_redis_error)?;
    Ok(())
}

/// If the request comes with a `client_error` from the mobile apps, log it and return an integrity failed response. Note the request hash is not locked.
async fn handle_client_error_if_applicable(
    integrity_verification_input: &IntegrityVerificationInput,
    request: &TokenGenerationRequest,
    kinesis_client: &KinesisClient,
    kinesis_stream_arn: &str,
    log_client_errors: bool,
) -> Result<(), RequestError> {
    if let IntegrityVerificationInput::ClientError { client_error } = integrity_verification_input {
        let report = DataReport::from_client_error(
            client_error.clone(),
            request.request_hash.clone(),
            request.bundle_identifier.clone(),
            request.aud.clone(),
            Some("`client_error` provided in the request".to_string()),
        );

        send_kinesis_stream_event(kinesis_client, kinesis_stream_arn, &report)
            .await
            .map_err(|e| {
                tracing::error!("Failed to send `client_error` to Kinesis: {:?}", e);
                RequestError {
                    code: ErrorCode::InternalServerError,
                    details: None,
                }
            })?;

        if log_client_errors {
            tracing::info!(
                client_error = client_error,
                bundle_identifier = ?request.bundle_identifier,
                request_hash = request.request_hash,
                "Client error provided in the request",
            );
        }

        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            details: None,
        });
    }

    Ok(())
}
