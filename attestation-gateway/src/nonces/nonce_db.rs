use std::fmt::Display;

use chrono::Duration;
use rand::Rng;
use redis::{
    AsyncTypedCommands, ExistenceCheck, RedisError, SetExpiry, SetOptions, aio::ConnectionManager,
};

use super::TokenDetails;

#[derive(Debug)]
pub enum NonceDbError {
    NonceNotFound,
    SerializationError(serde_json::Error),
    RedisError(RedisError),
}

#[derive(Clone)]
pub struct NonceDb {
    redis: ConnectionManager,
}

impl NonceDb {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // `ConnectionManager` is not usable in `const`
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
        let value = serde_json::to_string(token_details)
            .map_err(|e| NonceDbError::SerializationError(e))?;
        let options = SetOptions::default()
            .with_expiration(SetExpiry::EX(Duration::minutes(5).num_seconds() as u64))
            .conditional_set(ExistenceCheck::NX);

        self.redis
            .set_options::<String, String>(key, value, options)
            .await
            .map_err(|e| NonceDbError::RedisError(e))?;

        Ok(nonce)
    }

    /// # Errors
    ///
    /// When Redis `GETDEL` fails, the value is missing, or JSON does not decode to [`TokenDetails`].
    #[allow(dead_code)] // Used by `POST /a` (separate PR); kept so nonce flow stays in one module.
    pub async fn consume_nonce(&mut self, nonce: &str) -> Result<TokenDetails, NonceDbError> {
        let key = format!("nonce:{nonce}");
        let value = self
            .redis
            .get_del::<String>(key)
            .await
            .map_err(|e| NonceDbError::RedisError(e))?
            .ok_or(NonceDbError::NonceNotFound)?;

        let token_details: TokenDetails =
            serde_json::from_str(&value).map_err(|e| NonceDbError::SerializationError(e))?;

        Ok(token_details)
    }
}

impl Display for NonceDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonceNotFound => write!(f, "nonce not found"),
            Self::SerializationError(e) => write!(f, "serialization error: {e}"),
            Self::RedisError(e) => write!(f, "redis error: {e}"),
        }
    }
}

impl std::error::Error for NonceDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SerializationError(e) => Some(e),
            Self::RedisError(e) => Some(e),
            Self::NonceNotFound => None,
        }
    }
}
