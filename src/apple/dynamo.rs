use aws_sdk_dynamodb::types::AttributeValue;

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
    let request = client
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
        .expression_attribute_names("#pk", "key_id");

    match request.send().await {
        Ok(_) => {
            println!("Record inserted successfully");
        }
        Err(e) => {
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
    }

    Ok(())
}

#[derive(Debug)]
pub struct ApplePublicKeyRecordOutput {
    pub public_key: String,
    pub counter: u32,
    pub bundle_identifier: BundleIdentifier,
}

pub async fn fetch_apple_public_key(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    key_id: String,
) -> eyre::Result<ApplePublicKeyRecordOutput> {
    let client = aws_sdk_dynamodb::Client::new(aws_config);
    let request = client
        .get_item()
        .table_name(apple_keys_dynamo_table_name)
        .key("key_id", AttributeValue::S(format!("key#{key_id}")))
        .projection_expression("key_id, public_key, key_counter, bundle_identifier")
        .send()
        .await?;

    // FIXME: Unwraps
    match request.item {
        Some(item) => {
            let public_key = item.get("public_key").unwrap().as_s().unwrap().to_string();
            let counter = item
                .get("key_counter")
                .unwrap()
                .as_n()
                .unwrap()
                .parse::<u32>()
                .unwrap();

            let bundle_identifier: BundleIdentifier = serde_json::from_str(&format!(
                "\"{:}\"",
                item.get("bundle_identifier").unwrap().as_s().unwrap()
            ))?;

            Ok(ApplePublicKeyRecordOutput {
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

pub async fn update_apple_public_key_counter_plus(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    key_id: String,
) -> eyre::Result<()> {
    let client = aws_sdk_dynamodb::Client::new(aws_config);

    let request = client
        .update_item()
        .table_name(apple_keys_dynamo_table_name)
        .key("key_id", AttributeValue::S(format!("key#{key_id}")))
        .update_expression(format!("ADD {} :incr", "key_counter"))
        .expression_attribute_values(":incr", AttributeValue::N("1".to_string()))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await?;

    if let Some(attributes) = request.attributes.clone() {
        if let Some(_updated_value) = attributes.get("key_counter") {
            return Ok(());
        }
    }
    eyre::bail!(
        "Error updating counter for key: {key_id} \n {:?}",
        request.attributes
    );
}
