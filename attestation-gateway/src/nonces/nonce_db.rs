use chrono::Duration;
use rand::Rng;
use redis::{
    AsyncTypedCommands, ExistenceCheck, RedisError, SetExpiry, SetOptions, aio::ConnectionManager,
};
use thiserror::Error;

use super::TokenDetails;

#[derive(Debug, Error)]
pub enum NonceDbError {
    #[error("nonce not found")]
    NonceNotFound,

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("redis error: {0}")]
    RedisError(#[from] RedisError),
}

#[derive(Clone)]
pub struct NonceDb {
    redis: ConnectionManager,
}

impl NonceDb {
    #[must_use]
    #[expect(clippy::missing_const_for_fn)] // `ConnectionManager` is not usable in `const`
    pub fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    /// # Errors
    ///
    /// When `token_details` cannot be serialized to JSON, or Redis rejects `SET`.
    pub async fn generate_nonce(
        &mut self,
        token_details: &TokenDetails,
    ) -> Result<String, NonceDbError> {
        let mut nonce = [0; 16];
        rand::rng().fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);

        let key = format!("nonce:{nonce}");
        let value = serde_json::to_string(token_details)?;
        let options = SetOptions::default()
            .with_expiration(SetExpiry::EX(Duration::minutes(5).num_seconds() as u64))
            .conditional_set(ExistenceCheck::NX);

        self.redis
            .set_options::<String, String>(key, value, options)
            .await?;

        Ok(nonce)
    }

    /// # Errors
    ///
    /// When Redis `GETDEL` fails, the value is missing, or JSON does not decode to [`TokenDetails`].
    pub async fn consume_nonce(&mut self, nonce: &str) -> Result<TokenDetails, NonceDbError> {
        let key = format!("nonce:{nonce}");
        let value = self
            .redis
            .get_del::<String>(key)
            .await?
            .ok_or(NonceDbError::NonceNotFound)?;

        let token_details: TokenDetails = serde_json::from_str(&value)?;

        Ok(token_details)
    }
}
