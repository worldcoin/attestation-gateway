//! Storage of the WIP-106 Authenticator Provider keys: one `DynamoDB` item per key slot, with the
//! secret encrypted by KMS, since KMS can not hold `BabyJubJub` keys itself.

use std::{collections::HashMap, future::Future, time::Duration};

use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kms::primitives::Blob;
use eddsa_babyjubjub::EdDSAPrivateKey;

/// Upper bound for each `DynamoDB` or KMS call, so a slow dependency fails the request instead of
/// eating the 5s route timeout.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);

/// A stored key, decrypted.
#[derive(Clone)]
pub struct StoredKey {
    pub slot: u64,
    pub key: EdDSAPrivateKey,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}

pub struct AatKeyStore {
    dynamo: aws_sdk_dynamodb::Client,
    kms: aws_sdk_kms::Client,
    table: String,
    kms_key_arn: String,
}

impl AatKeyStore {
    #[must_use]
    pub fn new(aws_config: &aws_config::SdkConfig, table: String, kms_key_arn: String) -> Self {
        Self {
            dynamo: aws_sdk_dynamodb::Client::new(aws_config),
            kms: aws_sdk_kms::Client::new(aws_config),
            table,
            kms_key_arn,
        }
    }

    /// Loads and decrypts every key with `not_after >= since`.
    ///
    /// # Errors
    /// If `DynamoDB` or KMS fail or time out, or an item is malformed.
    pub async fn load(&self, since: u64) -> eyre::Result<Vec<StoredKey>> {
        let mut keys = Vec::new();
        let mut start_key = None;
        loop {
            let page = timed(
                self.dynamo
                    .scan()
                    .table_name(&self.table)
                    .filter_expression("#not_after >= :since")
                    .expression_attribute_names("#not_after", "not_after")
                    .expression_attribute_values(":since", AttributeValue::N(since.to_string()))
                    .set_exclusive_start_key(start_key)
                    .send(),
            )
            .await?;
            for item in page.items() {
                keys.push(self.decode(item).await?);
            }
            start_key = page.last_evaluated_key().cloned();
            if start_key.is_none() {
                return Ok(keys);
            }
        }
    }

    /// Stores a key for `slot`, unless another instance already did.
    ///
    /// # Errors
    /// If `DynamoDB` or KMS fail or time out.
    pub async fn create(&self, key: &StoredKey) -> eyre::Result<bool> {
        let secret = timed(
            self.kms
                .encrypt()
                .key_id(&self.kms_key_arn)
                .plaintext(Blob::new(key.key.to_bytes()))
                .set_encryption_context(Some(encryption_context(
                    key.slot,
                    key.not_before,
                    key.not_after,
                )))
                .send(),
        )
        .await?
        .ciphertext_blob
        .ok_or_else(|| eyre::eyre!("KMS returned no ciphertext"))?;

        let result = timed(
            self.dynamo
                .put_item()
                .table_name(&self.table)
                .item("slot", AttributeValue::S(slot_id(key.slot)))
                .item("secret", AttributeValue::B(secret))
                .item("not_before", AttributeValue::N(key.not_before.to_string()))
                .item("not_after", AttributeValue::N(key.not_after.to_string()))
                .item("revoked", AttributeValue::Bool(false))
                .condition_expression("attribute_not_exists(#slot)")
                .expression_attribute_names("#slot", "slot")
                .send(),
        )
        .await;
        match result {
            Ok(_) => Ok(true),
            Err(e)
                if e.downcast_ref::<aws_sdk_dynamodb::error::SdkError<
                    aws_sdk_dynamodb::operation::put_item::PutItemError,
                >>()
                .and_then(aws_sdk_dynamodb::error::SdkError::as_service_error)
                .is_some_and(
                    aws_sdk_dynamodb::operation::put_item::PutItemError::is_conditional_check_failed_exception,
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    async fn decode(&self, item: &HashMap<String, AttributeValue>) -> eyre::Result<StoredKey> {
        let number = |name: &str| -> eyre::Result<u64> {
            Ok(item
                .get(name)
                .and_then(|v| v.as_n().ok())
                .ok_or_else(|| eyre::eyre!("AAT key item is missing `{name}`"))?
                .parse()?)
        };
        let slot = item
            .get("slot")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| s.strip_prefix("slot#"))
            .ok_or_else(|| eyre::eyre!("AAT key item is missing `slot`"))?
            .parse()?;
        let not_before = number("not_before")?;
        let not_after = number("not_after")?;
        // Required, so a missing flag never reads as "not revoked".
        let revoked = *item
            .get("revoked")
            .and_then(|v| v.as_bool().ok())
            .ok_or_else(|| eyre::eyre!("AAT key item is missing `revoked`"))?;
        let secret = item
            .get("secret")
            .and_then(|v| v.as_b().ok())
            .ok_or_else(|| eyre::eyre!("AAT key item is missing `secret`"))?;
        let plaintext = timed(
            self.kms
                .decrypt()
                .key_id(&self.kms_key_arn)
                .ciphertext_blob(secret.clone())
                .set_encryption_context(Some(encryption_context(slot, not_before, not_after)))
                .send(),
        )
        .await?
        .plaintext
        .ok_or_else(|| eyre::eyre!("KMS returned no plaintext"))?;
        let bytes: [u8; 32] = plaintext
            .into_inner()
            .try_into()
            .map_err(|_| eyre::eyre!("AAT key secret is not 32 bytes"))?;
        Ok(StoredKey {
            slot,
            key: EdDSAPrivateKey::from_bytes(bytes),
            not_before,
            not_after,
            revoked,
        })
    }
}

/// Binds a secret to its slot and validity window: an item whose fields were changed, or a
/// secret moved to another item, no longer decrypts.
fn encryption_context(slot: u64, not_before: u64, not_after: u64) -> HashMap<String, String> {
    HashMap::from([
        ("slot".to_string(), slot.to_string()),
        ("not_before".to_string(), not_before.to_string()),
        ("not_after".to_string(), not_after.to_string()),
    ])
}

fn slot_id(slot: u64) -> String {
    format!("slot#{slot}")
}

async fn timed<T, E>(call: impl Future<Output = Result<T, E>>) -> eyre::Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    tokio::time::timeout(CALL_TIMEOUT, call)
        .await
        .map_err(|_| eyre::eyre!("AAT key store call timed out after {CALL_TIMEOUT:?}"))?
        .map_err(eyre::Report::new)
}
