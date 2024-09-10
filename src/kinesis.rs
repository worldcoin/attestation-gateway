use crate::utils::DataReport;
use aws_sdk_kinesis::{primitives::Blob, Client as KinesisClient};
use serde_json::to_vec;

pub async fn send_kinesis_stream_event(
    kinesis_client: &KinesisClient,
    stream_name: &str,
    data_report: &DataReport,
) -> Result<(), Box<dyn std::error::Error>> {
    const PARTITION_KEY: &str = "seon-state-request";

    // Serialize DataReport to JSON
    let payload_bytes = to_vec(data_report)?;

    // Send the serialized data to Kinesis
    kinesis_client
        .put_record()
        .stream_name(stream_name)
        .partition_key(PARTITION_KEY)
        .data(Blob::new(payload_bytes))
        .send()
        .await?;

    Ok(())
}
