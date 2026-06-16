use std::{collections::HashSet, sync::Arc, time::Duration};

use redis::aio::ConnectionManager;
use thiserror::Error;

use crate::utils::GlobalConfig;

const CACHE_KEY_PREFIX: &str = "audience_authorization:v1:";
const DEVELOPER_PORTAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum AudienceAuthorizationError {
    #[error("audience is not authorized")]
    NotAuthorized,

    #[error("developer portal base URL is not configured")]
    MissingDeveloperPortalUrl,

    #[error("developer portal request failed: {0}")]
    DeveloperPortalRequest(#[from] reqwest::Error),

    #[error("developer portal returned an unexpected status: {0}")]
    DeveloperPortalUnexpectedStatus(reqwest::StatusCode),
}

#[derive(Clone)]
pub struct AudienceAuthorizer {
    static_audiences: Arc<HashSet<String>>,
    developer_portal_base_url: Option<String>,
    aud_authorization_cache_ttl_secs: u64,
    http_client: reqwest::Client,
    redis: ConnectionManager,
}

impl AudienceAuthorizer {
    #[must_use]
    pub fn from_config(redis: ConnectionManager, global_config: &GlobalConfig) -> Self {
        Self {
            static_audiences: Arc::new(global_config.aud_whitelist.iter().cloned().collect()),
            developer_portal_base_url: global_config.developer_portal_base_url.clone(),
            aud_authorization_cache_ttl_secs: global_config.aud_authorization_cache_ttl_secs,
            http_client: build_http_client(),
            redis,
        }
    }

    /// Ensures an audience is authorized for nonce creation.
    ///
    /// Static allowlist entries are always authorized. Dynamic Developer Portal lookup is only
    /// attempted for `app_...` and valid `rp_...` audiences.
    ///
    /// # Errors
    ///
    /// Returns an error when the dynamic audience cannot be checked because the Developer Portal
    /// request failed.
    pub async fn ensure_authorized(&self, aud: &str) -> Result<(), AudienceAuthorizationError> {
        if self.static_audiences.contains(aud) {
            return Ok(());
        }

        if !is_dynamic_audience(aud) {
            return Err(AudienceAuthorizationError::NotAuthorized);
        }

        match self.is_cached(aud).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(error = ?error, aud, "Failed to read audience authorization cache");
            }
        }

        self.ensure_developer_portal_audience(aud).await?;
        self.cache_authorized_audience(aud).await;

        Ok(())
    }

    async fn ensure_developer_portal_audience(
        &self,
        aud: &str,
    ) -> Result<(), AudienceAuthorizationError> {
        let base_url = self
            .developer_portal_base_url
            .as_ref()
            .ok_or(AudienceAuthorizationError::MissingDeveloperPortalUrl)?;
        let url = format!(
            "{}/api/v4/app-status/{}",
            base_url.trim_end_matches('/'),
            aud
        );
        let response = self.http_client.get(url).send().await?;
        let status = response.status();

        if status.is_success() {
            return Ok(());
        }

        if status.is_client_error() {
            return Err(AudienceAuthorizationError::NotAuthorized);
        }

        Err(AudienceAuthorizationError::DeveloperPortalUnexpectedStatus(
            status,
        ))
    }

    async fn is_cached(&self, aud: &str) -> Result<bool, redis::RedisError> {
        let mut redis = self.redis.clone();
        let cached_value = redis::cmd("GET")
            .arg(cache_key(aud))
            .query_async::<Option<String>>(&mut redis)
            .await?;

        Ok(cached_value.is_some())
    }

    async fn cache_authorized_audience(&self, aud: &str) {
        let mut redis = self.redis.clone();
        if let Err(error) = redis::cmd("SET")
            .arg(cache_key(aud))
            .arg("1")
            .arg("EX")
            .arg(self.aud_authorization_cache_ttl_secs)
            .query_async::<()>(&mut redis)
            .await
        {
            tracing::warn!(error = ?error, aud, "Failed to write audience authorization cache");
        }
    }
}

#[must_use]
pub fn cache_key(aud: &str) -> String {
    format!("{CACHE_KEY_PREFIX}{aud}")
}

fn is_dynamic_audience(aud: &str) -> bool {
    aud.starts_with("app_") || is_valid_rp_id(aud)
}

fn is_valid_rp_id(rp_id: &str) -> bool {
    if !rp_id.starts_with("rp_") {
        return false;
    }

    let hex_part = &rp_id[3..];
    hex_part.len() == 16 && hex_part.chars().all(|char| char.is_ascii_hexdigit())
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DEVELOPER_PORTAL_REQUEST_TIMEOUT)
        .build()
        .expect("failed to build developer portal audience HTTP client")
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use mockito::Server;
    use serial_test::serial;

    use super::{AudienceAuthorizationError, AudienceAuthorizer, build_http_client, cache_key};

    const APP_ID: &str = "app_123";
    const RP_ID: &str = "rp_0123456789abcdef";
    const APP_STATUS_RESPONSE: &str = r#"{"verified":false}"#;

    async fn redis_client() -> redis::aio::ConnectionManager {
        let client = redis::Client::open("redis://localhost").unwrap();
        redis::cmd("FLUSHALL")
            .exec(&mut client.clone().get_connection().unwrap())
            .unwrap();

        redis::aio::ConnectionManager::new(client).await.unwrap()
    }

    async fn authorizer(
        static_audiences: &[&str],
        developer_portal_base_url: Option<String>,
    ) -> AudienceAuthorizer {
        AudienceAuthorizer {
            static_audiences: Arc::new(
                static_audiences
                    .iter()
                    .map(ToString::to_string)
                    .collect::<HashSet<_>>(),
            ),
            developer_portal_base_url,
            aud_authorization_cache_ttl_secs: 60 * 60,
            http_client: build_http_client(),
            redis: redis_client().await,
        }
    }

    async fn assert_not_authorized(authorizer: &AudienceAuthorizer, aud: &str) {
        let error = authorizer.ensure_authorized(aud).await.unwrap_err();
        assert!(matches!(error, AudienceAuthorizationError::NotAuthorized));
    }

    #[tokio::test]
    #[serial]
    async fn static_allowlist_authorizes_without_developer_portal_url() {
        let authorizer = authorizer(&["face.worldcoin.org"], None).await;

        authorizer
            .ensure_authorized("face.worldcoin.org")
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn unknown_non_static_domain_is_denied() {
        let authorizer = authorizer(&["face.worldcoin.org"], None).await;

        assert_not_authorized(&authorizer, "unknown.worldcoin.org").await;
    }

    #[tokio::test]
    #[serial]
    async fn app_id_is_authorized_on_successful_developer_portal_response() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", format!("/api/v4/app-status/{APP_ID}").as_str())
            .with_status(200)
            .with_body(APP_STATUS_RESPONSE)
            .create_async()
            .await;
        let authorizer = authorizer(&[], Some(server.url())).await;

        authorizer.ensure_authorized(APP_ID).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    #[serial]
    async fn rp_id_is_authorized_on_successful_developer_portal_response() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", format!("/api/v4/app-status/{RP_ID}").as_str())
            .with_status(200)
            .with_body(APP_STATUS_RESPONSE)
            .create_async()
            .await;
        let authorizer = authorizer(&[], Some(server.url())).await;

        authorizer.ensure_authorized(RP_ID).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    #[serial]
    async fn successful_response_caches_requested_audience_only() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", format!("/api/v4/app-status/{APP_ID}").as_str())
            .with_status(200)
            .with_body(APP_STATUS_RESPONSE)
            .expect(1)
            .create_async()
            .await;
        let authorizer = authorizer(&[], Some(server.url())).await;

        authorizer.ensure_authorized(APP_ID).await.unwrap();
        authorizer.ensure_authorized(APP_ID).await.unwrap();

        mock.assert_async().await;
        assert!(authorizer.is_cached(APP_ID).await.unwrap());
        assert!(!authorizer.is_cached(RP_ID).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn developer_portal_not_found_denies_and_does_not_cache() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", format!("/api/v4/app-status/{APP_ID}").as_str())
            .with_status(404)
            .expect(2)
            .create_async()
            .await;
        let authorizer = authorizer(&[], Some(server.url())).await;

        assert_not_authorized(&authorizer, APP_ID).await;
        assert_not_authorized(&authorizer, APP_ID).await;

        mock.assert_async().await;
        assert!(!authorizer.is_cached(APP_ID).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn developer_portal_failure_fails_without_cache_and_allows_with_cache() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", format!("/api/v4/app-status/{APP_ID}").as_str())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let authorizer = authorizer(&[], Some(server.url())).await;

        assert!(authorizer.ensure_authorized(APP_ID).await.is_err());
        authorizer.cache_authorized_audience(APP_ID).await;
        authorizer.ensure_authorized(APP_ID).await.unwrap();

        mock.assert_async().await;
    }

    #[test]
    fn cache_key_has_v1_prefix() {
        assert_eq!(
            cache_key("app_123"),
            "audience_authorization:v1:app_123".to_string()
        );
    }
}
