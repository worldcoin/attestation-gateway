use axum::Extension;
use axum_jsonschema::Json;
use std::time::SystemTime;

use crate::{
    android, kms_jws,
    utils::{
        DataReport, OutEnum, Platform, RequestError, TokenGenerationRequest,
        TokenGenerationResponse,
    },
};

pub async fn handler(
    Extension(kms_client): Extension<aws_sdk_kms::Client>,
    Json(request): Json<TokenGenerationRequest>,
) -> Result<Json<TokenGenerationResponse>, RequestError> {
    let mut report = DataReport {
        pass: false,
        out: OutEnum::Fail,
        timestamp: SystemTime::now(),
        request_hash: request.request_hash.clone(),
        bundle_identifier: request.bundle_identifier.clone(),
        client_error: request.client_error,
        aud: request.aud,
        internal_error_details: None,
        play_integrity: None,
    };

    // Verify the integrity token
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

    let attestation_gateway_token = kms_jws::generate_output_token(
        kms_client,
        "arn:aws:kms:us-east-1:000000001111:key/c7956b9c-5235-4e8e-bb35-7310fb80f4ca".to_string(),
    )
    .await?;

    let response = TokenGenerationResponse {
        attestation_gateway_token,
    };

    Ok(Json(response))
}
