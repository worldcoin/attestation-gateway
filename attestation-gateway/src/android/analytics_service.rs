use aws_config::Region;
use aws_sdk_kinesis::Client as KinesisClient;
use thiserror::Error;

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
}

impl AnalyticsServiceNewError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::InvalidKinesisStreamArn(_) => "invalid_kinesis_stream_arn".to_string(),
        }
    }
}
