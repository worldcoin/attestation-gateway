use crate::utils::DataReport;
use aws_sdk_kinesis::{primitives::Blob, Client as KinesisClient};
use serde_json::to_vec;

/// Reports a parsed event to a Kinesis stream for debugging and monitoring purposes
///
/// # Errors
/// Will return an `aws_sdk_kinesis::Error` if the request to Kinesis fails.
pub async fn send_kinesis_stream_event(
    kinesis_client: &KinesisClient,
    stream_arn: &str,
    data_report: &DataReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let partition_key: &str = "request_hash";

    // Serialize DataReport to JSON
    let payload_bytes = to_vec(data_report)?;

    // Send the serialized data to Kinesis
    kinesis_client
        .put_record()
        .stream_arn(stream_arn)
        .partition_key(partition_key)
        .data(Blob::new(payload_bytes))
        .send()
        .await?;

    Ok(())
}
