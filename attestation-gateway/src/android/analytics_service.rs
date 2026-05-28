use std::time::SystemTime;

use aws_config::Region;
use aws_sdk_kinesis::{Client as KinesisClient, primitives::Blob};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{android::cert_chain::CertChain, utils::BundleIdentifier};

#[derive(Clone)]
pub struct AnalyticsService {
    kinesis_stream_arn: String,
    kinesis_client: KinesisClient,
}

#[derive(Debug, Error)]
pub enum AnalyticsServiceNewError {
    #[error("invalid kinesis stream ARN: {0}")]
    InvalidKinesisStreamArn(String),
}

#[derive(Serialize)]
pub struct AndroidAttestationAnalyticsEvent {
    pub base64_cert_chain: Vec<String>,
    pub aud: String,
    pub nonce: String,
    pub app_version: String,
    pub bundle_identifier: BundleIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_chain: Option<CertChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub timestamp: SystemTime,
}

impl AnalyticsService {
    pub async fn new(kinesis_stream_arn: String) -> Result<Self, AnalyticsServiceNewError> {
        let region = kinesis_stream_arn
            .split(":")
            .nth(3)
            .ok_or(AnalyticsServiceNewError::InvalidKinesisStreamArn(
                kinesis_stream_arn.clone(),
            ))?
            .to_string();

        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let mut config_builder = aws_config.into_builder();
        config_builder.set_region(Some(Region::new(region)));
        let config = config_builder.build();
        let kinesis_client = KinesisClient::new(&config);

        Ok(Self {
            kinesis_stream_arn,
            kinesis_client,
        })
    }

    pub fn spawn_record(&self, event: AndroidAttestationAnalyticsEvent) {
        let service = self.clone();
        tokio::spawn(async move {
            service.record(event).await;
        });
    }

    pub async fn record(&self, event: AndroidAttestationAnalyticsEvent) {
        let (payload_bytes, partition_key) = match Self::serialize_event(&event) {
            Ok(serialized) => serialized,
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    "Failed to serialize Android attestation analytics event"
                );
                return;
            }
        };

        if let Err(e) = self
            .kinesis_client
            .put_record()
            .stream_arn(&self.kinesis_stream_arn)
            .partition_key(&partition_key)
            .data(Blob::new(payload_bytes))
            .send()
            .await
        {
            tracing::error!(
                error = ?e,
                "Failed to send Android attestation analytics event to Kinesis"
            );
        }
    }

    fn serialize_event(
        event: &AndroidAttestationAnalyticsEvent,
    ) -> Result<(Vec<u8>, String), serde_json::Error> {
        let mut payload = serde_json::to_value(event)?;
        let obj = payload
            .as_object_mut()
            .expect("AndroidAttestationAnalyticsEvent serializes to a JSON object");

        let id = Uuid::new_v4().simple().to_string();
        obj.insert(
            "id".to_string(),
            serde_json::Value::String(format!("android_attestation_{id}")),
        );

        let bytes = serde_json::to_vec(&payload)?;
        Ok((bytes, id))
    }
}

impl AnalyticsServiceNewError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::InvalidKinesisStreamArn(_) => "invalid_kinesis_stream_arn".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::BundleIdentifier;

    #[test]
    fn serializes_event_without_cert_chain_or_error() {
        let event = AndroidAttestationAnalyticsEvent {
            base64_cert_chain: vec!["cert".to_string()],
            aud: "dev".to_string(),
            nonce: "nonce".to_string(),
            app_version: "1.0".to_string(),
            bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
            cert_chain: None,
            error: None,
            timestamp: SystemTime::UNIX_EPOCH,
        };

        let (bytes, partition_key) = AnalyticsService::serialize_event(&event).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(!partition_key.is_empty());
        assert!(
            json.get("id")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("android_attestation_")
        );
        assert_eq!(json["aud"], "dev");
        assert_eq!(json["nonce"], "nonce");
        assert_eq!(json["app_version"], "1.0");
        assert_eq!(json["bundle_identifier"], "com.worldcoin.dev");
        assert!(json.get("cert_chain").is_none());
        assert!(json.get("error").is_none());
        assert!(json.get("timestamp").is_some());
    }

    #[test]
    fn serializes_event_with_error() {
        let event = AndroidAttestationAnalyticsEvent {
            base64_cert_chain: vec![],
            aud: "prod".to_string(),
            nonce: "n".to_string(),
            app_version: "2.0".to_string(),
            bundle_identifier: BundleIdentifier::AndroidProdWorldApp,
            cert_chain: None,
            error: Some("invalid challenge".to_string()),
            timestamp: SystemTime::UNIX_EPOCH,
        };

        let (bytes, _) = AnalyticsService::serialize_event(&event).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["error"], "invalid challenge");
    }
}
