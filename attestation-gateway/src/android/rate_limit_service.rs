use redis::{RedisError, aio::ConnectionManager};
use thiserror::Error;
use time::{OffsetDateTime, macros::format_description};

use crate::android::cert_chain::CertChain;

#[derive(Debug, Clone)]
pub struct RateLimitService {
    redis: ConnectionManager,
    limit_per_day: Option<isize>,
}

#[derive(Debug, Error)]
pub enum RateLimitServiceTryIncrError {
    #[error("redis error: {0}")]
    Redis(#[source] RedisError),
}

impl RateLimitService {
    #[must_use]
    pub fn new(redis: ConnectionManager, limit_per_day: Option<isize>) -> Self {
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
        let Some(limit) = self.limit_per_day else {
            return Ok(true);
        };

        let (date, expires_at) = daily_window(OffsetDateTime::now_utc());

        let key = format!(
            "android:rate_limit_service:{aud}:{date}:{device_public_key}",
            aud = aud,
            date = date,
            device_public_key = cert_chain.device_cert().public_key_hex(),
        );

        let (todays_count, _expiration_set): (isize, bool) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire_at(key, expires_at)
            .query_async(&mut self.redis)
            .await
            .map_err(RateLimitServiceTryIncrError::Redis)?;

        Ok(todays_count <= limit)
    }
}

fn daily_window(now: OffsetDateTime) -> (String, i64) {
    let today = now
        .to_offset(time::UtcOffset::UTC)
        .replace_time(time::Time::MIDNIGHT);
    let tomorrow = today + time::Duration::DAY;
    (
        today
            .format(format_description!("[year]-[month]-[day]"))
            .expect("valid UTC date"),
        tomorrow.unix_timestamp() + 30,
    )
}

impl RateLimitServiceTryIncrError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::Redis(_) => "redis".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::daily_window;
    use time::macros::datetime;

    #[test]
    fn daily_window_preserves_utc_key_and_midnight_grace() {
        let (date, expires_at) = daily_window(datetime!(2028-02-29 23:59:59.999_999_999 UTC));
        assert_eq!(date, "2028-02-29");
        assert_eq!(
            expires_at,
            datetime!(2028-03-01 00:00:30 UTC).unix_timestamp()
        );
    }

    #[test]
    fn daily_window_uses_utc_not_the_input_offset() {
        let (date, expires_at) = daily_window(datetime!(2026-01-01 00:30 +01:00));
        assert_eq!(date, "2025-12-31");
        assert_eq!(
            expires_at,
            datetime!(2026-01-01 00:00:30 UTC).unix_timestamp()
        );
    }
}
