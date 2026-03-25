use chrono::Duration;
use eyre::Result;
use rand::Rng;
use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions, aio::ConnectionManager};

use super::TokenDetails;

#[derive(Clone)]
pub struct NonceDb {
    redis: ConnectionManager,
}

impl NonceDb {
    pub fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    pub async fn generate_nonce(&mut self, token_details: &TokenDetails) -> Result<String> {
        let mut nonce = [0; 16];
        rand::rng().fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);

        let key = format!("nonce:{}", nonce);
        let value = serde_json::to_string(token_details)?;
        let options = SetOptions::default()
            .with_expiration(SetExpiry::EX(Duration::minutes(5).num_seconds() as u64))
            .conditional_set(ExistenceCheck::NX);

        self.redis
            .set_options::<String, String, ()>(key, value, options)
            .await?;

        Ok(nonce)
    }

    pub async fn consume_nonce(&mut self, nonce: &str) -> Result<TokenDetails> {
        let key = format!("nonce:{}", nonce);
        let value = self.redis.get_del::<&String, String>(&key).await?;
        let token_details: TokenDetails = serde_json::from_str(&value)?;

        Ok(token_details)
    }
}
