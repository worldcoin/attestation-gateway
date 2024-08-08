use aws_sdk_dynamodb::types::AttributeValue;

use crate::utils::{BundleIdentifier, ClientError, ErrorCode};

pub async fn insert_apple_public_key(
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
    bundle_identifier: &BundleIdentifier,
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
        .item("counter", AttributeValue::N("0".to_string()))
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
                // TODO: Convert to ClientError
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
