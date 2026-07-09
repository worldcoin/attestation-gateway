//! Keybox bypass defense: per-`(batch cert fingerprint, aud)` rate limiting
//! plus an explicit blocklist.
//!
//! Provides a stateful enforcement layer on top of the stateless confidence
//! signals collected in `IntegrityConfidence`. Uses Redis for:
//!
//! * **Sliding-window counter** keyed on
//!   `(SHA256(intermediate_cert_DER), aud)` -- the audience is included so a
//!   single legitimately popular batch cert that issues many tokens for one
//!   verifier does not affect the threshold for a different verifier.
//! * **Blocklist** of known-compromised certificate fingerprints
//!   (`keybox:block:{fingerprint}`).
//!
//! Enforcement defaults to **shadow mode**: the verdict is computed and
//! logged/metered, but `should_reject()` always returns `false` unless the
//! gateway is started with `KEYBOX_DEFENSE_ENFORCE=1`. This lets us tune
//! thresholds against production traffic before flipping to enforcement.

use openssl::sha::sha256;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;

/// Outcome of the keybox defense check on a single attestation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// No anomalies detected.
    Low,
    /// Elevated usage count for this `(fingerprint, aud)` -- could be
    /// legitimate (popular device model) or the start of abuse. Log only.
    Medium,
    /// Usage count exceeds the hard block threshold. The caller should
    /// reject when running in enforcement mode.
    High,
    /// Certificate fingerprint is on the explicit blocklist.
    Blocked,
}

/// Configuration for the defense thresholds.
#[derive(Debug, Clone)]
pub struct KeyboxDefenseConfig {
    /// Requests per `(fingerprint, aud)` within `window_secs` before the
    /// risk level is raised to `Medium` (monitoring threshold).
    pub warn_threshold: u64,
    /// Requests per `(fingerprint, aud)` within `window_secs` before the
    /// risk level is raised to `High` (blocking threshold).
    pub block_threshold: u64,
    /// Sliding window duration in seconds.
    pub window_secs: u64,
    /// When `false` (the default) `should_reject()` returns `false` for
    /// every verdict; verdicts are still logged and metered. Flip via
    /// `KEYBOX_DEFENSE_ENFORCE=1` once thresholds are tuned.
    pub enforce: bool,
}

impl Default for KeyboxDefenseConfig {
    fn default() -> Self {
        Self {
            warn_threshold: 500,
            block_threshold: 5000,
            window_secs: 3600,
            enforce: false,
        }
    }
}

impl KeyboxDefenseConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let warn = std::env::var("KEYBOX_WARN_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let block = std::env::var("KEYBOX_BLOCK_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);
        let window = std::env::var("KEYBOX_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);
        let enforce = std::env::var("KEYBOX_DEFENSE_ENFORCE").ok().as_deref() == Some("1");
        Self {
            warn_threshold: warn,
            block_threshold: block,
            window_secs: window,
            enforce,
        }
    }
}

#[derive(Debug, Error)]
pub enum KeyboxDefenseError {
    #[error("redis error: {0}")]
    Redis(#[source] RedisError),
}

/// Verdict for a single attestation request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyboxDefenseVerdict {
    pub risk_level: RiskLevel,
    pub batch_cert_fingerprint: String,
    pub aud: String,
    pub request_count: u64,
    pub blocklisted: bool,
    /// Mirrors `KeyboxDefenseConfig::enforce` so callers can decide what to
    /// do with `RiskLevel::High` verdicts without re-reading the config.
    pub enforce: bool,
}

impl KeyboxDefenseVerdict {
    /// `true` when the caller should reject the attestation. Always returns
    /// `false` while the defense layer runs in shadow mode (`enforce: false`),
    /// regardless of `risk_level`.
    #[must_use]
    pub const fn should_reject(&self) -> bool {
        if !self.enforce {
            return false;
        }
        matches!(self.risk_level, RiskLevel::Blocked | RiskLevel::High)
    }
}

#[derive(Clone)]
pub struct KeyboxDefense {
    config: KeyboxDefenseConfig,
}

impl KeyboxDefense {
    #[must_use]
    pub const fn new(config: KeyboxDefenseConfig) -> Self {
        Self { config }
    }

    /// SHA-256 fingerprint of the intermediate (batch) certificate DER bytes.
    /// Hex-encoded, lowercase.
    #[must_use]
    pub fn fingerprint(intermediate_cert_der: &[u8]) -> String {
        hex::encode(sha256(intermediate_cert_der))
    }

    /// Evaluate an attestation request.
    ///
    /// 1. Check the blocklist (`keybox:block:{fingerprint}`)
    /// 2. Increment the sliding-window counter (`keybox:count:{fingerprint}:{aud}`)
    /// 3. Map the count to `RiskLevel`
    pub async fn evaluate(
        &self,
        redis: &mut ConnectionManager,
        batch_cert_fingerprint: &str,
        aud: &str,
    ) -> Result<KeyboxDefenseVerdict, KeyboxDefenseError> {
        let block_key = format!("keybox:block:{batch_cert_fingerprint}");
        let count_key = format!("keybox:count:{batch_cert_fingerprint}:{aud}");

        let blocklisted: bool = redis
            .exists(&block_key)
            .await
            .map_err(KeyboxDefenseError::Redis)?;

        if blocklisted {
            metrics::counter!(
                "attestation_gateway.keybox_defense",
                "action" => "blocked",
                "enforce" => self.config.enforce.to_string(),
            )
            .increment(1);

            tracing::warn!(
                fingerprint = %batch_cert_fingerprint,
                aud = %aud,
                enforce = self.config.enforce,
                "blocklisted batch certificate used in attestation"
            );

            return Ok(KeyboxDefenseVerdict {
                risk_level: RiskLevel::Blocked,
                batch_cert_fingerprint: batch_cert_fingerprint.to_string(),
                aud: aud.to_string(),
                request_count: 0,
                blocklisted: true,
                enforce: self.config.enforce,
            });
        }

        let window_secs: i64 = self.config.window_secs.try_into().unwrap_or(i64::MAX);
        let count: u64 = redis::pipe()
            .atomic()
            .incr(&count_key, 1_u64)
            .expire(&count_key, window_secs)
            .ignore()
            .query_async::<Vec<u64>>(redis)
            .await
            .map_err(KeyboxDefenseError::Redis)?
            .first()
            .copied()
            .unwrap_or(1);

        let risk_level = if count >= self.config.block_threshold {
            RiskLevel::High
        } else if count >= self.config.warn_threshold {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        metrics::counter!(
            "attestation_gateway.keybox_defense",
            "risk_level" => format!("{risk_level:?}"),
            "enforce" => self.config.enforce.to_string(),
        )
        .increment(1);

        if risk_level != RiskLevel::Low {
            tracing::warn!(
                fingerprint = %batch_cert_fingerprint,
                aud = %aud,
                count = count,
                risk_level = ?risk_level,
                enforce = self.config.enforce,
                warn_threshold = self.config.warn_threshold,
                block_threshold = self.config.block_threshold,
                "elevated batch certificate usage"
            );
        }

        Ok(KeyboxDefenseVerdict {
            risk_level,
            batch_cert_fingerprint: batch_cert_fingerprint.to_string(),
            aud: aud.to_string(),
            request_count: count,
            blocklisted: false,
            enforce: self.config.enforce,
        })
    }

    /// Add a certificate fingerprint to the blocklist. Persistent until
    /// removed.
    pub async fn blocklist_add(
        redis: &mut ConnectionManager,
        fingerprint: &str,
    ) -> Result<(), KeyboxDefenseError> {
        let key = format!("keybox:block:{fingerprint}");
        redis
            .set::<_, _, ()>(&key, "1")
            .await
            .map_err(KeyboxDefenseError::Redis)?;
        tracing::info!(fingerprint = %fingerprint, "added to keybox blocklist");
        Ok(())
    }

    /// Remove a certificate fingerprint from the blocklist.
    pub async fn blocklist_remove(
        redis: &mut ConnectionManager,
        fingerprint: &str,
    ) -> Result<(), KeyboxDefenseError> {
        let key = format!("keybox:block:{fingerprint}");
        redis
            .del::<_, ()>(&key)
            .await
            .map_err(KeyboxDefenseError::Redis)?;
        tracing::info!(fingerprint = %fingerprint, "removed from keybox blocklist");
        Ok(())
    }
}
