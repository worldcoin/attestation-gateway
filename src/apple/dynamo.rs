use aws_sdk_dynamodb::{operation::get_item::GetItemOutput, types::AttributeValue};

use crate::utils::{BundleIdentifier, ClientError, ErrorCode};

/// Insert a new attested public key into the `DynamoDB` table
///
/// # Errors
/// Will return a `ClientError` if the `key_id` is already registered in the DB.
/// Returns an `aws_sdk_dynamodb::Error` if the request fails.
pub async fn insert_apple_public_key(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    bundle_identifier: BundleIdentifier,
    key_id: String,
    public_key: String,
    receipt: String,
) -> eyre::Result<()> {
    let client = aws_sdk_dynamodb::Client::new(aws_config);
    let response = client
        .put_item()
        .table_name(apple_keys_dynamo_table_name)
        .item("key_id", AttributeValue::S(format!("key#{key_id}")))
        .item("public_key", AttributeValue::S(public_key))
        .item("receipt", AttributeValue::S(receipt))
        .item(
            "bundle_identifier",
            AttributeValue::S(bundle_identifier.to_string()),
        )
        // NOTE: we store it as `key_counter` because `COUNTER` is a reserved word in Dynamo
        // https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html
        .item("key_counter", AttributeValue::N("0".to_string()))
        .item(
            "created_at",
            AttributeValue::S(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            ),
        )
        .condition_expression("attribute_not_exists(#pk)")
        .expression_attribute_names("#pk", "key_id")
        .send()
        .await;

    if let Err(e) = response {
        let e = e.into_service_error();
        if e.is_conditional_check_failed_exception() {
            eyre::bail!(ClientError {
                code: ErrorCode::InvalidInitialAttestation,
                internal_debug_info: "the attested apple key ID is already registered in DB"
                    .to_string(),
            });
        }
        eyre::bail!(e);
    }

    Ok(())
}

#[derive(Debug)]
pub struct ApplePublicKeyRecordOutput {
    pub public_key: String,
    pub counter: u32,
    pub bundle_identifier: BundleIdentifier,
}

impl ApplePublicKeyRecordOutput {
    fn from_dynamo_row(value: GetItemOutput, key_id: &str) -> eyre::Result<Self> {
        match value.item {
            Some(item) => {
                let public_key = item
                    .get("public_key")
                    .ok_or_else(|| eyre::eyre!("public_key not found for key: {key_id}"))?
                    .as_s()
                    .map_err(|_| eyre::eyre!("unable to parse public_key as_s for key: {key_id}"))?
                    .to_string();
                let counter = item
                    .get("key_counter")
                    .ok_or_else(|| eyre::eyre!("key_counter not found for key: {key_id}"))?
                    .as_n()
                    .map_err(|_| eyre::eyre!("unable to parse key_counter as_n for key: {key_id}"))?
                    .parse::<u32>()
                    .map_err(|_| {
                        eyre::eyre!("unable to parse key_counter as u32 for key: {key_id}")
                    })?;

                let bundle_identifier: BundleIdentifier = serde_json::from_str(&format!(
                    "\"{:}\"",
                    item.get("bundle_identifier")
                        .ok_or_else(|| eyre::eyre!(
                            "bundle_identifier not found for key: {key_id}"
                        ))?
                        .as_s()
                        .map_err(|_| eyre::eyre!(
                            "unable to parse bundle_identifier as_s for key: {key_id}"
                        ))?
                ))?;

                Ok(Self {
                    public_key,
                    counter,
                    bundle_identifier,
                })
            }
            None => {
                eyre::bail!(ClientError {
                    code: ErrorCode::InvalidPublicKey,
                    internal_debug_info: "the key_id was not found in Dynamo".to_string(),
                });
            }
        }
    }
}

/// Fetches an Apple public key from the relevant table
///
/// # Errors
/// Will return a `ClientError` if the `key_id` is not found in the DB.
/// Returns an `aws_sdk_dynamodb::Error` if the request fails.
pub async fn fetch_apple_public_key(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    key_id: String,
) -> eyre::Result<ApplePublicKeyRecordOutput> {
    let client = aws_sdk_dynamodb::Client::new(aws_config);
    let response = client
        .get_item()
        .table_name(apple_keys_dynamo_table_name)
        .key("key_id", AttributeValue::S(format!("key#{key_id}")))
        .projection_expression("key_id, public_key, key_counter, bundle_identifier")
        .send()
        .await?;

    ApplePublicKeyRecordOutput::from_dynamo_row(response, &key_id)
}

/// Increments the `key_counter` by 1 of an Apple public key (to prevent replay attacks)
///
/// # Errors
/// Will return an `aws_sdk_dynamodb::Error` if the request fails.
pub async fn update_apple_public_key_counter_plus(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    key_id: String,
    new_counter: u32,
) -> eyre::Result<()> {
    let client = aws_sdk_dynamodb::Client::new(aws_config);

    let request = client
        .update_item()
        .table_name(apple_keys_dynamo_table_name)
        .key("key_id", AttributeValue::S(format!("key#{key_id}")))
        // with this condition we ensure there are no race conditions with the counter
        .condition_expression("key_counter < :new_counter")
        .update_expression("SET key_counter = :new_counter")
        .expression_attribute_values(":new_counter", AttributeValue::N(new_counter.to_string()))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await;

    match request {
        Ok(request) => {
            if let Some(attributes) = &request.attributes {
                if attributes.contains_key("key_counter") {
                    return Ok(());
                }
            }

            eyre::bail!(
                "Error updating counter for key: {key_id} \n {:?}",
                request.attributes
            );
        }
        Err(e) => {
            let service_error = e.into_service_error();
            if service_error.is_conditional_check_failed_exception() {
                eyre::bail!(ClientError {
                    code: ErrorCode::ExpiredToken,
                    internal_debug_info:
                        "Counter has already been used in Dynamo, race condition prevented."
                            .to_string(),
                });
            }

            eyre::bail!(service_error);
        }
    }
}
