use std::time::Duration;

use aws_sdk_kinesis::{
    Client as KinesisClient,
    error::{ProvideErrorMetadata, SdkError},
    operation::put_record::PutRecordError,
    primitives::Blob,
};

use crate::utils::DataReport;

const MAX_ATTEMPTS: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 50;

/// Reports a parsed event to a Kinesis stream for debugging and monitoring purposes.
///
/// Retries a few times with exponential backoff on transient AWS failures.
///
/// # Errors
/// Will return an error if serialization fails or PutRecord still fails after retries.
pub async fn send_kinesis_stream_event(
    kinesis_client: &KinesisClient,
    stream_arn: &str,
    data_report: &DataReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let (payload_bytes, partition_key) = data_report.as_vec()?;

    let mut backoff_ms = INITIAL_BACKOFF_MS;

    for attempt in 1..=MAX_ATTEMPTS {
        match kinesis_client
            .put_record()
            .stream_arn(stream_arn)
            .partition_key(&partition_key)
            .data(Blob::new(payload_bytes.clone()))
            .send()
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                if !is_retryable_put_record_error(&error) || attempt == MAX_ATTEMPTS {
                    return Err(error.into());
                }

                tracing::debug!(
                    attempt,
                    backoff_ms,
                    error = ?error,
                    "Retrying Kinesis PutRecord after transient failure"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2);
            }
        }
    }

    unreachable!("loop returns on success or final failure")
}

fn is_retryable_put_record_error(error: &SdkError<PutRecordError>) -> bool {
    match error {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => {
            true
        }
        SdkError::ServiceError(context) => {
            let retryable_code = matches!(
                ProvideErrorMetadata::code(context.err()),
                Some(
                    "InternalFailure"
                        | "ServiceUnavailable"
                        | "ProvisionedThroughputExceededException"
                        | "LimitExceededException"
                )
            );
            retryable_code || context.raw().status().as_u16() >= 500
        }
        _ => false,
    }
}
