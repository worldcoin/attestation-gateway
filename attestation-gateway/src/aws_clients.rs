#[derive(Clone)]
pub struct AwsClients {
    pub kms: aws_sdk_kms::Client,
    pub dynamodb: aws_sdk_dynamodb::Client,
}

impl AwsClients {
    #[must_use]
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            kms: aws_sdk_kms::Client::new(config),
            dynamodb: aws_sdk_dynamodb::Client::new(config),
        }
    }
}
