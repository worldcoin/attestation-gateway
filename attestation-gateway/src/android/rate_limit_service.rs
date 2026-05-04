use chrono::{Days, NaiveTime, Utc};
use redis::{AsyncTypedCommands, RedisError, aio::ConnectionManager};
use thiserror::Error;

use crate::android::cert_chain::CertChain;

#[derive(Debug, Clone)]
pub struct RateLimitService {
    redis: ConnectionManager,
    limit_per_day: isize,
}

#[derive(Debug, Error)]
pub enum RateLimitServiceTryIncrError {
    #[error("redis error: {0}")]
    Redis(#[source] RedisError),
}

impl RateLimitService {
    #[must_use]
    pub fn new(redis: ConnectionManager, limit_per_day: isize) -> Self {
        Self {
            redis,
            limit_per_day,
        }
    }

    pub async fn try_incr(
        &mut self,
        aud: &str,
        cert_chain: &CertChain,
    ) -> Result<bool, RateLimitServiceTryIncrError> {
        let today = Utc::now().with_time(NaiveTime::MIN).single().unwrap();
        let tomorrow = today.checked_add_days(Days::new(1)).unwrap();

        let key = format!(
            "android:rate_limit_service:{aud}:{date}:{device_public_key}",
            aud = aud,
            date = today.format("%Y-%m-%d"),
            device_public_key = cert_chain.device_cert().public_key_hex(),
        );

        let (todays_count, _): (isize, bool) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire_at(key, tomorrow.timestamp() + 30)
            .query_async(&mut self.redis)
            .await
            .map_err(RateLimitServiceTryIncrError::Redis)?;

        Ok(todays_count <= self.limit_per_day)
    }
}

impl RateLimitServiceTryIncrError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::Redis(_) => "redis".to_string(),
        }
    }
}
