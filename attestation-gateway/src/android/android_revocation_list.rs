//! Google Android Key Attestation revocation feed (`android.googleapis.com/attestation/status`).
//! Cache lifetime follows the response `Cache-Control` header (typically `max-age`).
//!
//! Construct with [`AndroidRevocationList::connect`] (async) so the first snapshot is loaded before
//! use. The live cache is an [`Arc`] swapped atomically ([`arc_swap::ArcSwap`]) — no mutexes.
//!
//! **Contract:** do not run two [`Self::refresh`] calls concurrently (e.g. only one background task).
//! If that is violated, both may still complete; the last successful [`store`](arc_swap::ArcSwap::store)
//! wins. Concurrent refresh plus [`Self::is_revoked`] is always safe.
//!
//! [`Self::is_revoked`] never performs I/O. Use [`Self::spawn_refresh_loop`] to sleep until the
//! current `Cache-Control` window expires, then refresh, or call [`Self::refresh`] directly for a
//! one-off update.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

/// Default URL for Google's attestation status JSON.
pub const DEFAULT_ATTESTATION_STATUS_URL: &str =
    "https://android.googleapis.com/attestation/status";

const DEFAULT_FALLBACK_MAX_AGE: Duration = Duration::from_secs(300);

/// Sleep after a failed refresh before retrying (avoids hammering the endpoint).
const REFRESH_FAILURE_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum AndroidRevocationListError {
    #[error("reqwest error: {0}")]
    ReqwestError(#[source] reqwest::Error),

    #[error("fetch revocations http error: {0}")]
    FetchRevocationsHttp(#[source] reqwest::Error),

    #[error("fetch revocations json error: {0}")]
    FetchRevocationsJsonParsing(#[source] serde_json::Error),
}

/// Shared handle to Google's attestation revocation JSON (thread-safe, cheap to clone).
#[derive(Clone)]
pub struct AndroidRevocationList {
    inner: Arc<Inner>,
}

struct Inner {
    cache: ArcSwap<CacheState>,
    client: Client,
    url: String,
}

struct CacheState {
    revoked_ids: HashSet<String>,
    valid_until: Option<Instant>,
}

fn build_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .build()
}

impl AndroidRevocationList {
    /// Fetches the revocation feed once and returns a list whose cache is populated.
    ///
    /// # Errors
    ///
    /// - [`AndroidRevocationListError::ReqwestError`] if the HTTP client cannot be constructed.
    /// - [`AndroidRevocationListError::FetchRevocationsHttp`] if the GET fails or the response body
    ///   cannot be read (network, timeout, transport).
    /// - [`AndroidRevocationListError::FetchRevocationsJsonParsing`] if the body is not valid JSON
    ///   or does not deserialize into the expected attestation status shape.
    pub async fn connect(url: impl Into<String>) -> Result<Self, AndroidRevocationListError> {
        let url = url.into();
        let client = build_http_client().map_err(AndroidRevocationListError::ReqwestError)?;
        let state = fetch_revocations(&client, &url).await?;

        Ok(Self {
            inner: Arc::new(Inner {
                cache: ArcSwap::new(Arc::new(state)),
                client,
                url,
            }),
        })
    }

    /// Same as [`Self::connect`] with [`DEFAULT_ATTESTATION_STATUS_URL`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect`].
    pub async fn connect_google_default() -> Result<Self, AndroidRevocationListError> {
        Self::connect(DEFAULT_ATTESTATION_STATUS_URL).await
    }

    /// Returns `true` if `certificate_id` matches a key in the cached JSON `entries` map (decimal or
    /// lowercase hex string, as published by Google).
    ///
    /// Never performs I/O. Stale data is still returned until [`Self::refresh`] runs successfully.
    #[must_use]
    pub fn is_revoked(&self, certificate_id: &str) -> bool {
        self.inner.cache.load().revoked_ids.contains(certificate_id)
    }

    /// Remaining validity implied by the last response `max-age` (approximately): time until the
    /// current snapshot should be refreshed.
    ///
    /// Returns [`Duration::ZERO`] if already stale or if no expiry was recorded.
    #[must_use]
    pub fn duration_until_stale(&self) -> Duration {
        let state = self.inner.cache.load();
        let Some(until) = state.valid_until else {
            return Duration::ZERO;
        };
        until
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO)
    }

    /// Fetches and replaces the cache. Respects `Cache-Control` on the response.
    ///
    /// Must not be invoked concurrently with another refresh; see module documentation.
    ///
    /// # Errors
    ///
    /// - [`AndroidRevocationListError::FetchRevocationsHttp`] if the GET fails or the response body
    ///   cannot be read.
    /// - [`AndroidRevocationListError::FetchRevocationsJsonParsing`] if the body is not valid JSON
    ///   or does not deserialize into the expected attestation status shape.
    ///
    /// The HTTP client is already built at connect time, so [`AndroidRevocationListError::ReqwestError`]
    /// is not returned from this method.
    pub async fn refresh(&self) -> Result<(), AndroidRevocationListError> {
        let state = fetch_revocations(&self.inner.client, &self.inner.url).await?;
        self.inner.cache.store(Arc::new(state));
        Ok(())
    }

    /// Runs until the task is cancelled: sleeps ~[`Self::duration_until_stale`], then
    /// [`Self::refresh`], repeating. On refresh failure, waits [`REFRESH_FAILURE_BACKOFF`] before
    /// retrying.
    #[must_use]
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        let list = self.clone();

        tokio::spawn(async move {
            loop {
                let wait = list.duration_until_stale();
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }

                match list.refresh().await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "android attestation revocation list refresh failed; retrying after backoff"
                        );

                        tokio::time::sleep(REFRESH_FAILURE_BACKOFF).await;
                    }
                }
            }
        })
    }
}

async fn fetch_revocations(
    client: &Client,
    url: &str,
) -> Result<CacheState, AndroidRevocationListError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(AndroidRevocationListError::FetchRevocationsHttp)?
        .error_for_status()
        .map_err(AndroidRevocationListError::FetchRevocationsHttp)?;

    let max_age = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_cache_control_max_age)
        .unwrap_or(DEFAULT_FALLBACK_MAX_AGE);

    let body = response
        .bytes()
        .await
        .map_err(AndroidRevocationListError::FetchRevocationsHttp)?;

    let parsed: StatusResponse = serde_json::from_slice(&body)
        .map_err(AndroidRevocationListError::FetchRevocationsJsonParsing)?;

    let mut revoked = HashSet::with_capacity(parsed.entries.len());
    for (key, entry) in parsed.entries {
        if entry.status.eq_ignore_ascii_case("REVOKED") {
            revoked.insert(key);
        }
    }

    Ok(CacheState {
        revoked_ids: revoked,
        valid_until: Some(Instant::now() + max_age),
    })
}

impl AndroidRevocationListError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::ReqwestError(_) => "reqwest_error".to_string(),
            Self::FetchRevocationsHttp(_) => "fetch_revocations_http".to_string(),
            Self::FetchRevocationsJsonParsing(_) => "fetch_revocations_json".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::ReqwestError(_)
            | Self::FetchRevocationsHttp(_)
            | Self::FetchRevocationsJsonParsing(_) => false,
        }
    }
}

#[derive(Deserialize)]
struct StatusResponse {
    entries: std::collections::HashMap<String, StatusEntry>,
}

#[derive(Deserialize)]
struct StatusEntry {
    status: String,
}

/// Parses `max-age` from a `Cache-Control` header value (e.g. `public, max-age=3600`).
fn parse_cache_control_max_age(cache_control: &str) -> Option<Duration> {
    for part in cache_control.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("max-age=") {
            let rest = rest.trim();
            if let Ok(secs) = rest.parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cache_control_max_age_extracts_seconds() {
        assert_eq!(
            parse_cache_control_max_age("public, max-age=3600"),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_cache_control_max_age("max-age=60"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(parse_cache_control_max_age("no-cache"), None);
    }

    #[test]
    fn parses_status_json() {
        let j = r#"{"entries":{"42":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"7":{"status":"OK"}}}"#;
        let parsed: StatusResponse = serde_json::from_str(j).unwrap();
        assert_eq!(parsed.entries.len(), 2);
    }

    #[tokio::test]
    async fn connect_loads_initial_cache() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/status")
            .with_status(200)
            .with_header("Cache-Control", "max-age=60")
            .with_body(r#"{"entries":{"1":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#)
            .create();

        let url = format!("{}/status", server.url());
        let list = AndroidRevocationList::connect(url).await.unwrap();
        assert!(list.is_revoked("1"));
        assert!(!list.is_revoked("2"));
        let until = list.duration_until_stale();
        assert!(!until.is_zero());
        assert!(until <= Duration::from_secs(60));
    }
}
