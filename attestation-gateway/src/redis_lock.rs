//! Redis `SET NX` locks that release on drop unless kept.
//!
//! Dropping a held lock (handler failure or task cancellation, e.g. tower's timeout layer)
//! deletes the key on a spawned task. Call [`RedisNxLock::keep`] when the operation succeeded
//! and the key must remain until its TTL. TTL is still the fallback if release fails.

use redis::{AsyncCommands, ExistenceCheck, RedisError, SetExpiry, SetOptions, aio::ConnectionManager};

/// An acquired Redis `SET NX` lock.
///
/// Releases the key when dropped, unless [`Self::keep`] was called.
pub struct RedisNxLock {
    redis: ConnectionManager,
    key: String,
    keep: bool,
    release_failure_metric: Option<&'static str>,
}

impl RedisNxLock {
    /// Acquires `key` with `SET NX EX ttl_secs`. Returns `Ok(None)` if the key already exists.
    ///
    /// # Errors
    /// Redis transport or protocol errors while setting the key.
    pub async fn acquire(
        redis: &mut ConnectionManager,
        key: String,
        ttl_secs: u64,
    ) -> Result<Option<Self>, RedisError> {
        let options = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl_secs));
        let acquired: bool = redis
            .set_options::<String, bool, bool>(key.clone(), true, options)
            .await?;
        if !acquired {
            return Ok(None);
        }
        Ok(Some(Self::from_held(redis.clone(), key)))
    }

    /// Wraps a key that was already acquired with `SET NX` elsewhere.
    #[must_use]
    pub const fn from_held(redis: ConnectionManager, key: String) -> Self {
        Self {
            redis,
            key,
            keep: false,
            release_failure_metric: None,
        }
    }

    /// Increments this metric if a release (eager or on drop) fails.
    #[must_use]
    pub const fn with_release_failure_metric(mut self, name: &'static str) -> Self {
        self.release_failure_metric = Some(name);
        self
    }

    /// Keep the key until TTL; do not delete it when this guard is dropped.
    pub fn keep(mut self) {
        self.keep = true;
    }

    /// Deletes the key now. Prefer this on the failure path when you need the result;
    /// otherwise dropping the guard is enough (including on cancellation).
    ///
    /// # Errors
    /// Redis transport or protocol errors while deleting the key.
    pub async fn release(mut self) -> Result<(), RedisError> {
        // Only disarm Drop after a successful delete so cancellation mid-release still cleans up.
        self.delete_key().await?;
        self.keep = true;
        Ok(())
    }

    async fn delete_key(&mut self) -> Result<(), RedisError> {
        match self.redis.del::<_, usize>(self.key.as_str()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::error!(error = ?e, key = %self.key, "Failed to release Redis NX lock");
                if let Some(name) = self.release_failure_metric {
                    metrics::counter!(name).increment(1);
                }
                Err(e)
            }
        }
    }
}

impl Drop for RedisNxLock {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let mut redis = self.redis.clone();
        let key = self.key.clone();
        let metric = self.release_failure_metric;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::error!(key = %self.key, "No Tokio runtime to release Redis NX lock");
            if let Some(name) = metric {
                metrics::counter!(name).increment(1);
            }
            return;
        };
        handle.spawn(async move {
            if let Err(e) = redis.del::<_, usize>(key.as_str()).await {
                tracing::error!(error = ?e, key = %key, "Failed to release Redis NX lock on drop");
                if let Some(name) = metric {
                    metrics::counter!(name).increment(1);
                }
            }
        });
    }
}
