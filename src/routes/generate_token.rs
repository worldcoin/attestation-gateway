use aws_sdk_kinesis::Client as KinesisClient;
use axum::Extension;
use axum_jsonschema::Json;
use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};
use std::time::SystemTime;

use crate::{
    android, apple,
    keys::fetch_active_key,
    kinesis::{send_seon_action_stream_event, AttestationFailure, SeonEventStreamInput},
    kms_jws,
    utils::{
        handle_redis_error, BundleIdentifier, ClientError, DataReport, ErrorCode, GlobalConfig,
        IntegrityVerificationInput, OutEnum, OutputTokenPayload, RequestError,
        TokenGenerationRequest, TokenGenerationResponse,
    },
};

const REQUEST_HASH_REDIS_KEY_PREFIX: &str = "request_hash:";
const REQUEST_HASH_CACHE_TTL: usize = 60 * 60 * 24; // 24 hours

// NOTE: Integration tests for route handlers are in the `/tests` module

pub async fn handler(
    Extension(aws_config): Extension<aws_config::SdkConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(global_config): Extension<GlobalConfig>,
    Extension(kinesis_client): Extension<KinesisClient>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    let aud = request.aud.clone();
    let request_hash = request.request_hash.clone();
    let public_key_id = request.public_key_id.clone();
    let visitor_id = request.visitor_id.clone();

    let my_span = tracing::span!(
        tracing::Level::DEBUG,
        "generate_token",
        request_hash = request_hash
    );
    let _enter = my_span.enter();

    let integrity_verification_input = IntegrityVerificationInput::from_request(&request)?;

    if global_config
        .disabled_bundle_identifiers
        .contains(&request.bundle_identifier)
    {
        return Err(RequestError {
            code: ErrorCode::BadRequest,
            details: Some("This bundle identifier is currently unavailable.".to_string()),
        });
    }

    metrics::counter!("generate_token",  "bundle_identifier" => request.bundle_identifier.to_string()).increment(1);

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

    if !lock_set {
        return Err(RequestError {
            code: ErrorCode::DuplicateRequestHash,
            details: None,
        });
    }

    let report = verify_android_or_apple_integrity(
        integrity_verification_input,
        request.request_hash,
        request.bundle_identifier.clone(),
        &request.aud,
        request.client_error,
        global_config.clone(),
        &aws_config,
    )
    .await
    .map_err(|e| {
        // Check if we have a ClientError in the error chain and return to the client without further logging
        if let Some(client_error) = e.downcast_ref::<ClientError>() {
            if global_config.log_client_errors {
                tracing::warn!(?e, "Client failure verifying Android or Apple integrity");
            }else {
                tracing::debug!(?e, "Client failure verifying Android or Apple integrity");
            }

            metrics::counter!("generate_token.client_error",  "bundle_identifier" => request.bundle_identifier.to_string(), "error_code" => client_error.code.to_string()).increment(1);

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
        report,
        request_hash.clone(),
        aud,
        &mut redis,
        aws_config,
        &kinesis_client,
        global_config.kinesis_stream_name.as_deref().unwrap_or(""),
        public_key_id,
        visitor_id,
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

async fn process_and_finalize_report(
    report: DataReport,
    request_hash: String,
    aud: String,
    redis: &mut ConnectionManager,
    aws_config: aws_config::SdkConfig,
    kinesis_client: &KinesisClient,
    kinesis_stream_name: &str,
    public_key_id: String,
    visitor_id: Option<String>,
) -> Result<TokenGenerationResponse, RequestError> {
    if !kinesis_stream_name.is_empty() {
        let attestation_failure = AttestationFailure {
            created_at: Utc::now().to_rfc3339(),
            public_key_id,
            visitor_id,
            is_approved: !report.pass,
            failure_reason: report.client_error.unwrap_or_else(|| "Unknown".to_string()),
        };

        let event_input = SeonEventStreamInput {
            request: None,
            response: None,
            attestation_failure: Some(attestation_failure),
        };

        if let Err(e) =
            send_seon_action_stream_event(kinesis_client, kinesis_stream_name, event_input).await
        {
            tracing::error!("Failed to send seon action stream event: {:?}", e);
        }
    }

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
        error: None, // TODO: Implement in the future (see L76)
    }
    .generate()?;

    let key = fetch_active_key(redis, &aws_config).await.map_err(|e| {
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
        .del::<_, _>(format!("{REQUEST_HASH_REDIS_KEY_PREFIX}{request_hash}"))
        .await
        .map_err(handle_redis_error)?;
    Ok(())
}
