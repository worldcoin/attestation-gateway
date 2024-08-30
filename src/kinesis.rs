use aws_sdk_kinesis::{primitives::Blob, Client as KinesisClient, Error as KinesisError};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AttestationFailure {
    pub created_at: String,
    pub public_key_id: String,
    pub visitor_id: Option<String>,
    pub is_approved: bool,
    pub failure_reason: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SeonEventStreamInput {
    pub request: Option<serde_json::Value>,
    pub response: Option<serde_json::Value>,
    pub attestation_failure: Option<AttestationFailure>,
}

pub async fn send_seon_action_stream_event(
    kinesis_client: &KinesisClient,
    stream_name: &str,
    data: SeonEventStreamInput,
) -> Result<(), KinesisError> {
    let payload = if let Some(attestation_failure) = data.attestation_failure {
        json!({
            "attestation_failure": {
                "date": Utc::now().to_rfc3339(),
                "created_at": attestation_failure.created_at,
                "public_key_id": attestation_failure.public_key_id,
                "visitor_id": attestation_failure.visitor_id,
                "is_approved": attestation_failure.is_approved,
                "failure_reason": attestation_failure.failure_reason,
            }
        })
    } else {
        json!({
            "request": {
                "date": Utc::now().to_rfc3339(),
                "data": data.request
            },
            "response": {
                "date": Utc::now().to_rfc3339(),
                "data": data.response
            }
        })
    };

    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    kinesis_client
        .put_record()
        .stream_name(stream_name)
        .partition_key("seon-state-request")
        .data(Blob::new(payload_bytes))
        .send()
        .await?;

    Ok(())
}
