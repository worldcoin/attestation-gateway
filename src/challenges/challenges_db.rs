use chrono::Duration;
use eyre::Result;
use rand::Rng;
use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions, aio::ConnectionManager};

use super::TokenDetails;

#[derive(Clone)]
pub struct ChallengesDb {
    redis: ConnectionManager,
}

impl ChallengesDb {
    pub fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    pub async fn create_token_challenge(&mut self, token_details: &TokenDetails) -> Result<String> {
        let mut challenge = [0; 16];
        rand::rng().fill_bytes(&mut challenge);
        let challenge = hex::encode(challenge);

        let key = format!("challenge:{}", challenge);
        let value = serde_json::to_string(token_details)?;
        let options = SetOptions::default()
            .with_expiration(SetExpiry::EX(Duration::minutes(120).num_seconds() as u64))
            .conditional_set(ExistenceCheck::NX);

        self.redis
            .set_options::<String, String, ()>(key, value, options)
            .await?;

        Ok(challenge)
    }

    pub async fn consume_token_challenge(&mut self, challenge: &str) -> Result<TokenDetails> {
        let key = format!("challenge:{}", challenge);
        let value = self.redis.get_del::<&String, String>(&key).await?;
        let token_details: TokenDetails = serde_json::from_str(&value)?;

        Ok(token_details)
    }
}
