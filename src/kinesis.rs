use aws_sdk_kinesis::{primitives::Blob, Client as KinesisClient};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationFailure {
    pub created_at: String,
    pub public_key_id: String,
    pub visitor_id: Option<String>,
    pub is_approved: bool,
    pub failure_reason: String,
}

pub async fn send_seon_action_stream_event(
    kinesis_client: &KinesisClient,
    stream_name: &str,
    attestation_failure: AttestationFailure,
) -> Result<(), Box<dyn std::error::Error>> {
    const PARTITION_KEY: &str = "seon-state-request";
    let current_time = Utc::now().to_rfc3339();

    let payload = json!({
        "attestation_failure": {
            "date": current_time,
            "created_at": attestation_failure.created_at,
            "public_key_id": attestation_failure.public_key_id,
            "visitor_id": attestation_failure.visitor_id,
            "is_approved": attestation_failure.is_approved,
            "failure_reason": attestation_failure.failure_reason,
        }
    });

    let payload_bytes = serde_json::to_vec(&payload)?;

    kinesis_client
        .put_record()
        .stream_name(stream_name)
        .partition_key(PARTITION_KEY)
        .data(Blob::new(payload_bytes))
        .send()
        .await?;

    Ok(())
}
