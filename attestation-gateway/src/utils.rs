use crate::{android::PlayIntegrityToken, developer::DeveloperTokenClaims};
use aide::OperationIo;
use axum::response::IntoResponse;
use josekit::{JoseError, jwt::JwtPayload};
use redis::RedisError;
use schemars::JsonSchema;
use std::collections::HashMap;
use std::{env, fmt::Display, time::SystemTime};
use uuid::Uuid;

static OUTPUT_TOKEN_EXPIRATION: std::time::Duration = std::time::Duration::from_secs(60 * 10);

/// A Play Integrity response-encryption key pair (the self-managed "download my keys" pair):
/// the outer JWE decryption key (AES-256, base64) and the inner JWS verification key (EC, base64).
#[derive(Debug, Clone)]
pub struct AndroidResponseKeys {
    pub outer_jwe_private_key: String,
    pub inner_jws_public_key: String,
}

impl AndroidResponseKeys {
    /// Loads a key pair from the given env vars, returning `None` unless BOTH are set
    /// (both-or-none) so the caller can fall back to the default keys.
    fn from_env_pair(outer_var: &str, inner_var: &str) -> Option<Self> {
        match (env::var(outer_var), env::var(inner_var)) {
            (Ok(outer_jwe_private_key), Ok(inner_jws_public_key)) => Some(Self {
                outer_jwe_private_key,
                inner_jws_public_key,
            }),
            _ => None,
        }
    }
}

/// App family used to select the correct Play Integrity response-encryption keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidApp {
    WorldApp,
    WorldId,
}

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    /// Default Android response keys (legacy World App pair). Used as the fallback for any bundle
    /// without a configured per-app key; see [`GlobalConfig::android_response_keys`].
    pub android_default_keys: AndroidResponseKeys,
    pub android_world_app_keys: Option<AndroidResponseKeys>,
    pub android_world_id_keys: Option<AndroidResponseKeys>,
    pub apple_keys_dynamo_table_name: String,
    pub developer_inner_jwks_url: Option<String>,
    pub enabled_bundle_identifiers: Vec<BundleIdentifier>,
    /// Determines whether to log the client errors as warnings for debugging purposes (should generally only be enabled in development or staging)
    pub log_client_errors: bool,
    pub kinesis_stream_arn: Option<String>,
    pub apple_root_ca_pem: Vec<u8>,
    pub aud_whitelist: Vec<String>,
    pub jwt_issuer: String,
    pub developer_portal_base_url: Option<String>,
    pub aud_authorization_cache_ttl_secs: u64,
}

impl GlobalConfig {
    /// Loads global config from environment variables
    ///
    /// # Panics
    /// If required environment variables are not set
    pub fn from_env() -> Self {
        // Default (legacy) Android response keys — kept required so the service always has a
        // working fallback. Per-app namespaced keys are layered on top below.
        let android_default_keys = AndroidResponseKeys {
            outer_jwe_private_key: env::var("ANDROID_OUTER_JWE_PRIVATE_KEY")
                .expect("env var `ANDROID_OUTER_JWE_PRIVATE_KEY` is required"),
            inner_jws_public_key: env::var("ANDROID_INNER_JWS_PUBLIC_KEY")
                .expect("env var `ANDROID_INNER_JWS_PUBLIC_KEY` is required"),
        };

        // Optional per-app response keys. When unset, the corresponding app family falls back to
        // `android_default_keys` (see `GlobalConfig::android_response_keys`).
        let android_world_app_keys = AndroidResponseKeys::from_env_pair(
            "ANDROID_WORLD_APP_JWE_PRIVATE_KEY",
            "ANDROID_WORLD_APP_JWS_PUBLIC_KEY",
        );
        let android_world_id_keys = AndroidResponseKeys::from_env_pair(
            "ANDROID_WORLD_ID_JWE_PRIVATE_KEY",
            "ANDROID_WORLD_ID_JWS_PUBLIC_KEY",
        );

        let apple_keys_dynamo_table_name = env::var("APPLE_KEYS_DYNAMO_TABLE_NAME")
            .expect("env var `APPLE_KEYS_DYNAMO_TABLE_NAME` is required");

        let developer_inner_jwks_url = env::var("DEVELOPER_INNER_JWKS_URL").ok();

        let log_client_errors = env::var("LOG_CLIENT_ERRORS")
            .is_ok_and(|val| val.to_lowercase() == "true" || val == "1");

        let kinesis_stream_arn = env::var("KINESIS_STREAM_ARN").ok();

        // Disabling bundle identifiers is helpful so that the production deployment of this service does not accept staging apps (or viceversa)
        let enabled_bundle_identifiers = env::var("ENABLED_BUNDLE_IDENTIFIERS");
        let enabled_bundle_identifiers: Vec<BundleIdentifier> = enabled_bundle_identifiers
            .map_or_else(
                |_| Vec::new(),
                |val| {
                    val.split(',')
                        .filter_map(|s| serde_json::from_str(&format!("\"{s}\"")).ok())
                        .collect()
                },
            );

        let aud_whitelist = env::var("AUD_WHITELIST").map_or_else(
            |_| Vec::new(),
            |val| val.split(',').map(str::to_string).collect(),
        );

        let jwt_issuer =
            env::var("JWT_ISSUER").unwrap_or_else(|_| "attestation.worldcoin.org".to_string());

        let developer_portal_base_url = env::var("DEVELOPER_PORTAL_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let aud_authorization_cache_ttl_secs = env::var("AUD_AUTHORIZATION_CACHE_TTL_SECS")
            .map_or(Ok(60 * 60), |value| value.parse::<u64>())
            .expect("AUD_AUTHORIZATION_CACHE_TTL_SECS must be a valid u64");

        tracing::info!(
            "Running with enabled bundle identifiers: {:?}",
            enabled_bundle_identifiers
        );

        Self {
            android_default_keys,
            android_world_app_keys,
            android_world_id_keys,
            apple_keys_dynamo_table_name,
            developer_inner_jwks_url,
            enabled_bundle_identifiers,
            log_client_errors,
            kinesis_stream_arn,
            apple_root_ca_pem: include_bytes!("apple/apple_app_attestation_root_ca.pem").to_vec(),
            aud_whitelist,
            jwt_issuer,
            developer_portal_base_url,
            aud_authorization_cache_ttl_secs,
        }
    }

    /// Selects the Play Integrity response-encryption keys for `bundle`. Each app family looks up
    /// its own namespaced key and falls back to `android_default_keys` when that key is not
    /// configured (or the bundle has no Android mapping). Never errors: a mismatched key simply
    /// fails decryption rather than passing a bad token, so falling back is safe. Fallbacks are
    /// counted (metric only — no per-request log, to avoid spam on high-volume bundles) so a
    /// missing expected key or an unmapped enabled bundle is observable.
    #[must_use]
    pub fn android_response_keys(&self, bundle: &BundleIdentifier) -> &AndroidResponseKeys {
        let configured = match bundle.android_app() {
            Some(AndroidApp::WorldApp) => self.android_world_app_keys.as_ref(),
            Some(AndroidApp::WorldId) => self.android_world_id_keys.as_ref(),
            None => None,
        };

        configured.unwrap_or_else(|| {
            metrics::counter!(
                "generate_token.android_response_key_fallback",
                "bundle_identifier" => bundle.to_string(),
            )
            .increment(1);
            &self.android_default_keys
        })
    }
}

#[derive(Debug)]
/// Configuration for the signature of output tokens (JWS) from Attestation Gateway
pub struct SigningConfigDefinition {
    pub key_spec: aws_sdk_kms::types::KeySpec,
    pub curve_str: &'static str,
    pub jose_kit_algorithm: josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm,
    pub kms_algorithm: aws_sdk_kms::types::SigningAlgorithmSpec,
    pub signature_len: usize,
    pub key_ttl_signing: i64, // Time (in seconds) the key is available for signing new tokens
    pub key_ttl_verification: i64, // Time (in seconds) the key is available for retrieval and hence for verification by third-parties
}

// NOTE: These attributes must always match each other
pub const SIGNING_CONFIG: SigningConfigDefinition = SigningConfigDefinition {
    // We use ES256 with the NIST P-256 curve for signing JWS
    key_spec: aws_sdk_kms::types::KeySpec::EccNistP256,
    curve_str: "P-256",
    jose_kit_algorithm: josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256,
    kms_algorithm: aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256,
    signature_len: 64,
    key_ttl_signing: 60 * 60 * 24 * 180,      // 180 days
    key_ttl_verification: 60 * 60 * 24 * 182, // 182 days
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    AppleIOS,
    Android,
}

impl Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::AppleIOS => write!(f, "ios"),
            Self::Android => write!(f, "android"),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, JsonSchema, PartialEq, Eq, Clone)]
pub enum BundleIdentifier {
    #[serde(rename = "com.worldcoin")]
    ComWorldcoin,

    #[serde(rename = "com.worldcoin.staging")]
    ComWorldcoinStaging,

    #[serde(rename = "com.worldcoin.dev")]
    ComWorldcoinDev,

    #[serde(rename = "com.worldcoin.sandbox")]
    ComWorldcoinSandbox,

    #[serde(rename = "org.worldcoin.insight")]
    OrgWorldcoinInsight,

    #[serde(rename = "org.worldcoin.insight.staging")]
    OrgWorldcoinInsightStaging,

    #[serde(rename = "org.worldcoin.insight.sandbox")]
    OrgWorldcoinInsightSandbox,

    #[serde(rename = "org.world.id")]
    OrgWorldId,

    #[serde(rename = "org.world.staging.id")]
    OrgWorldStagingId,

    #[serde(rename = "org.world.sandbox.id")]
    OrgWorldSandboxId,

    #[serde(rename = "org.world.id.staging")]
    OrgWorldIdStaging,

    #[serde(rename = "org.world.id.dev")]
    OrgWorldIdDev,

    #[serde(rename = "org.world.id.sandbox")]
    OrgWorldIdSandbox,
}

impl BundleIdentifier {
    /// Play Integrity prod checks (`PlayRecognized`, `Licensed`) for World App and World ID prod.
    #[must_use]
    pub const fn requires_play_store_prod_checks(&self) -> bool {
        matches!(self, Self::ComWorldcoin | Self::OrgWorldId)
    }

    /// App family this bundle belongs to, used to select Play Integrity response-encryption keys.
    /// Returns `None` for iOS bundles (no Android Play Integrity flow).
    #[must_use]
    pub const fn android_app(&self) -> Option<AndroidApp> {
        match self {
            Self::ComWorldcoin
            | Self::ComWorldcoinStaging
            | Self::ComWorldcoinDev
            | Self::ComWorldcoinSandbox => Some(AndroidApp::WorldApp),
            Self::OrgWorldId
            | Self::OrgWorldIdStaging
            | Self::OrgWorldIdDev
            | Self::OrgWorldIdSandbox => Some(AndroidApp::WorldId),
            Self::OrgWorldcoinInsight
            | Self::OrgWorldcoinInsightStaging
            | Self::OrgWorldcoinInsightSandbox
            | Self::OrgWorldStagingId
            | Self::OrgWorldSandboxId => None,
        }
    }

    /// Expected app signing-certificate digest (hex) for Android Play Integrity (`POST /g`).
    #[must_use]
    pub const fn android_certificate_sha256_digest(&self) -> Option<&str> {
        match self {
            Self::ComWorldcoin
            | Self::ComWorldcoinStaging
            | Self::ComWorldcoinSandbox
            | Self::OrgWorldId
            | Self::OrgWorldIdStaging
            | Self::OrgWorldIdSandbox => {
                // cspell:disable-next-line
                Some("nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8")
            }
            Self::ComWorldcoinDev | Self::OrgWorldIdDev => Some("6a6a1474b5cbbb2b1aa57e0bc3"),
            Self::OrgWorldcoinInsight
            | Self::OrgWorldcoinInsightStaging
            | Self::OrgWorldcoinInsightSandbox
            | Self::OrgWorldStagingId
            | Self::OrgWorldSandboxId => None,
        }
    }

    /// Expected app signing-certificate digest (base64) for Android hardware attestation (`POST /a`).
    #[must_use]
    pub const fn android_certificate_sha256_digest_base64(&self) -> Option<&'static str> {
        match self {
            Self::ComWorldcoin
            | Self::ComWorldcoinStaging
            | Self::ComWorldcoinSandbox
            | Self::OrgWorldId
            | Self::OrgWorldIdStaging
            | Self::OrgWorldIdSandbox => Some("nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8="),
            Self::ComWorldcoinDev | Self::OrgWorldIdDev => {
                Some("o0Fu39yqrsxeWSucqge7eOzG8xrsRAn0nKbTtN/x2+A=")
            }
            Self::OrgWorldcoinInsight
            | Self::OrgWorldcoinInsightStaging
            | Self::OrgWorldcoinInsightSandbox
            | Self::OrgWorldStagingId
            | Self::OrgWorldSandboxId => None,
        }
    }

    #[must_use]
    pub const fn apple_app_id(&self) -> Option<&str> {
        match self {
            Self::ComWorldcoin
            | Self::ComWorldcoinStaging
            | Self::ComWorldcoinDev
            | Self::ComWorldcoinSandbox
            | Self::OrgWorldIdStaging
            | Self::OrgWorldIdDev
            | Self::OrgWorldIdSandbox => None,
            // cspell:disable
            Self::OrgWorldcoinInsightStaging => Some("35RXKB6738.org.worldcoin.insight.staging"),
            Self::OrgWorldcoinInsightSandbox => Some("35RXKB6738.org.worldcoin.insight.sandbox"),
            Self::OrgWorldcoinInsight => Some("35RXKB6738.org.worldcoin.insight"),
            Self::OrgWorldId => Some("35RXKB6738.org.world.id"),
            Self::OrgWorldStagingId => Some("35RXKB6738.org.world.staging.id"),
            Self::OrgWorldSandboxId => Some("35RXKB6738.org.world.sandbox.id"),
            // cspell:enable
        }
    }

    /// The App IDs accepted for iOS App Attest for this bundle. Normally just the canonical
    /// [`Self::apple_app_id`]; staging additionally accepts the App ID of re-signed automation
    /// builds. `None` for non-Apple bundles (mirrors `apple_app_id`).
    ///
    /// TEMPORARY: the staging extra lets AWS Device Farm's wildcard re-sign (Apple Team
    /// `5VLXJ89ZV9`) pass attestation so UI automation can run on real devices. Production
    /// deployments reject staging bundles at the `enabled_bundle_identifiers` gate before
    /// attestation, so this never widens production. Remove when device-farm automation no
    /// longer needs it.
    #[must_use]
    pub fn apple_accepted_app_ids(&self) -> Option<Vec<&str>> {
        let mut ids = vec![self.apple_app_id()?];
        // cspell:disable-next-line
        if matches!(self, Self::OrgWorldStagingId) {
            // cspell:disable-next-line
            ids.push("5VLXJ89ZV9.org.world.staging.id");
        }
        Some(ids)
    }
}

impl Display for BundleIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ComWorldcoin => write!(f, "com.worldcoin"),
            Self::ComWorldcoinStaging => write!(f, "com.worldcoin.staging"),
            Self::ComWorldcoinDev => write!(f, "com.worldcoin.dev"),
            Self::ComWorldcoinSandbox => write!(f, "com.worldcoin.sandbox"),
            Self::OrgWorldIdStaging => write!(f, "org.world.id.staging"),
            Self::OrgWorldIdDev => write!(f, "org.world.id.dev"),
            Self::OrgWorldIdSandbox => write!(f, "org.world.id.sandbox"),
            Self::OrgWorldcoinInsight => write!(f, "org.worldcoin.insight"),
            Self::OrgWorldcoinInsightStaging => write!(f, "org.worldcoin.insight.staging"),
            Self::OrgWorldcoinInsightSandbox => write!(f, "org.worldcoin.insight.sandbox"),
            Self::OrgWorldId => write!(f, "org.world.id"),
            Self::OrgWorldStagingId => write!(f, "org.world.staging.id"),
            Self::OrgWorldSandboxId => write!(f, "org.world.sandbox.id"),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct TokenGenerationRequest {
    pub integrity_token: Option<String>,
    pub client_error: Option<String>,
    pub aud: String,
    pub bundle_identifier: BundleIdentifier,
    pub request_hash: String,
    pub apple_initial_attestation: Option<String>,
    pub apple_public_key: Option<String>,
    pub apple_assertion: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TokenGenerationResponse {
    pub attestation_gateway_token: String,
}

pub enum IntegrityVerificationInput {
    Android {
        integrity_token: String,
    },
    AppleInitialAttestation {
        apple_initial_attestation: String,
    },
    AppleAssertion {
        apple_assertion: String,
        apple_public_key: String,
    },
    /// Represents the state where a `client_error` is passed from the client, indicating a failure with upstream services.
    /// Under normal circumstances, this is simply logged for analytics and the request is rejected.
    ClientError {
        client_error: String,
    },
    Developer {
        developer_token: String,
    },
}

impl IntegrityVerificationInput {
    /// Returns the corresponding [`CheckType`] for this verification input, or
    /// `None` for `ClientError` (no integrity check is performed for those).
    ///
    /// Used to enrich tracing events along the verification path so log queries
    /// like `check_type:Developer` can isolate LP traffic without parsing the
    /// nested request payload.
    #[must_use]
    pub const fn check_type(&self) -> Option<CheckType> {
        match self {
            Self::Android { .. } => Some(CheckType::Android),
            Self::AppleInitialAttestation { .. } | Self::AppleAssertion { .. } => {
                Some(CheckType::Apple)
            }
            Self::Developer { .. } => Some(CheckType::Developer),
            Self::ClientError { .. } => None,
        }
    }

    /// Parses a `TokenGenerationRequest` into an `IntegrityVerificationInput` specifically for an Android or Apple integrity check.
    ///
    /// The optional `laissez_passer_token` is the bearer token extracted from the `Authorization`
    /// header. When present, it takes precedence over the platform-specific attestation flows
    /// and is routed to the Developer (laissez-passer) verification path.
    ///
    /// # Errors
    /// Will return a `RequestError` if the request is malformed or missing required fields.
    ///
    /// # Panics
    /// No panics expected.
    pub fn from_request(
        request: &TokenGenerationRequest,
        laissez_passer_token: Option<String>,
        platform: Option<Platform>,
    ) -> Result<Self, RequestError> {
        if let Some(client_error) = request.client_error.clone() {
            return Ok(Self::ClientError { client_error });
        }

        if let Some(developer_token) = laissez_passer_token {
            return Ok(Self::Developer { developer_token });
        }

        let platform = platform.ok_or_else(|| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Could not infer platform from attestation fields.".to_string()),
        })?;

        match platform {
            Platform::Android => {
                if request.integrity_token.is_none() {
                    return Err(RequestError {
                        code: ErrorCode::BadRequest,
                        details: Some(
                            "`integrity_token` is required for this bundle identifier.".to_string(),
                        ),
                    });
                }

                Ok(Self::Android {
                    integrity_token: request.integrity_token.clone().unwrap(), // Safe to unwrap because we've already validated this is not None above
                })
            }
            Platform::AppleIOS => {
                if request.apple_initial_attestation.is_some() {
                    if request.apple_assertion.is_some() || request.apple_public_key.is_some() {
                        return Err(RequestError {
                            code: ErrorCode::BadRequest,
                            details: Some(
                                "For initial attestations, `apple_assertion` and `apple_public_key` attributes are not allowed."
                                    .to_string(),
                            ),
                        });
                    }

                    return Ok(Self::AppleInitialAttestation {
                        apple_initial_attestation: request
                            .apple_initial_attestation
                            .clone()
                            .unwrap(),
                    });
                }

                if request.apple_assertion.is_none() || request.apple_public_key.is_none() {
                    return Err(RequestError {
                        code: ErrorCode::BadRequest,
                        details: Some(
                            "`apple_assertion` and `apple_public_key` are required for this bundle identifier when `apple_initial_attestation` is not provided."
                                .to_string(),
                        ),
                    });
                }

                Ok(Self::AppleAssertion {
                    apple_assertion: request.apple_assertion.clone().unwrap(),
                    apple_public_key: request.apple_public_key.clone().unwrap(),
                })
            }
        }
    }
}

/// Represents an exception that is attributable to the client and represents expected behavior for the API.
///
/// For example, when an expired integrity token is passed or when an invalid request is made.
/// `ClientException`s are not logged by default and result in a 4xx status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientException {
    pub code: ErrorCode,
    pub internal_debug_info: String,
}

impl Display for ClientException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Internal debug info: {:?}",
            self.code, self.internal_debug_info,
        )
    }
}

/// Represents an error response that can be returned directly to the client.
/// This struct can represent both server and client errors.
#[derive(Debug, OperationIo, PartialEq, Eq)]
pub struct RequestError {
    pub code: ErrorCode,
    pub details: Option<String>,
}

impl Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Details: {:?}",
            self.code, self.details,
        )
    }
}

impl IntoResponse for RequestError {
    fn into_response(self) -> axum::response::Response {
        #[derive(serde::Serialize)]
        struct ErrorObjectResponse {
            code: String,
            message: String,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ErrorResponse {
            allow_retry: bool,
            error: ErrorObjectResponse,
        }
        (
            self.code.into_http_status_code(),
            axum::Json(ErrorResponse {
                allow_retry: self.code.into_allow_retry(),
                error: ErrorObjectResponse {
                    code: self.code.to_string(),
                    message: self
                        .details
                        .unwrap_or_else(|| self.code.into_default_error_message().to_string()),
                },
            }),
        )
            .into_response()
    }
}

impl std::error::Error for RequestError {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorCode {
    BadRequest,
    DuplicateRequestHash,
    ExpiredToken,
    IntegrityFailed,
    InternalServerError,
    InvalidAttestationForApp,
    InvalidInitialAttestation,
    InvalidPublicKey,
    InvalidToken,
    InvalidDeveloperToken,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest => write!(f, "bad_request"),
            Self::DuplicateRequestHash => write!(f, "duplicate_request_hash"),
            Self::ExpiredToken => write!(f, "expired_token"),
            Self::IntegrityFailed => write!(f, "integrity_failed"),
            Self::InternalServerError => write!(f, "internal_server_error"),
            Self::InvalidAttestationForApp => write!(f, "invalid_attestation_for_app"),
            Self::InvalidInitialAttestation => write!(f, "invalid_initial_attestation"),
            Self::InvalidPublicKey => write!(f, "invalid_public_key"),
            Self::InvalidToken => write!(f, "invalid_token"),
            Self::InvalidDeveloperToken => write!(f, "invalid_developer_token"),
        }
    }
}

impl ErrorCode {
    const fn into_http_status_code(self) -> axum::http::StatusCode {
        match self {
            Self::InternalServerError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::DuplicateRequestHash => axum::http::StatusCode::CONFLICT,
            Self::BadRequest
            | Self::ExpiredToken
            | Self::IntegrityFailed
            | Self::InvalidAttestationForApp
            | Self::InvalidInitialAttestation
            | Self::InvalidPublicKey
            | Self::InvalidToken
            | Self::InvalidDeveloperToken => axum::http::StatusCode::BAD_REQUEST,
        }
    }

    const fn into_default_error_message(self) -> &'static str {
        match self {
            Self::BadRequest => "The request is malformed.",
            Self::DuplicateRequestHash => "The `request_hash` has already been used.",
            Self::ExpiredToken => "The integrity token has expired. Please generate a new one.",
            Self::IntegrityFailed => "Integrity checks have not passed.",
            Self::InternalServerError => "Internal server error. Please try again.",
            Self::InvalidAttestationForApp => {
                "The provided attestation is not valid for this app. Verify the provided bundle identifier is correct for this attestation object."
            }
            Self::InvalidInitialAttestation => {
                "This public key has already gone through initial attestation. Use assertion instead."
            }
            Self::InvalidPublicKey => "Public key has not been attested.",
            Self::InvalidToken => "The provided token or attestation is invalid or malformed.",
            Self::InvalidDeveloperToken => "The provided developer token is invalid or malformed.",
        }
    }

    /// Determines whether the request is retryable (**as-is**) or not.
    const fn into_allow_retry(self) -> bool {
        match self {
            Self::InternalServerError => true,
            Self::BadRequest
            | Self::ExpiredToken
            | Self::IntegrityFailed
            | Self::InvalidAttestationForApp
            | Self::InvalidInitialAttestation
            | Self::InvalidPublicKey
            | Self::InvalidToken
            | Self::InvalidDeveloperToken
            | Self::DuplicateRequestHash => false,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum OutEnum {
    Pass,
    Fail,
}

impl Display for OutEnum {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum CheckType {
    /// Represents a developer verification check, typically used for development/testing purposes
    Developer,
    Android,
    Apple,
}

impl Display for CheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Android | Self::Apple => write!(f, "osv"),
            Self::Developer => write!(f, "dev"),
        }
    }
}

#[derive(Debug)]
pub struct VerificationOutput {
    pub success: bool,
    pub parsed_play_integrity_token: Option<PlayIntegrityToken>,
    pub client_exception: Option<ClientException>,
    pub app_version: Option<String>,
    pub developer_token: Option<DeveloperTokenClaims>,
}

/// `DataReport` is used to serialize the output logged to Kinesis for analytics and debugging purposes.
/// The `request_hash` has a retention period of 30 days.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataReport {
    pub pass: bool,
    pub out: OutEnum,
    pub client_error: Option<String>,
    pub request_hash: String,
    pub timestamp: SystemTime,
    pub bundle_identifier: BundleIdentifier,
    pub aud: String,
    pub internal_debug_info: Option<String>,
    pub play_integrity: Option<PlayIntegrityToken>,
    pub app_version: Option<String>,
    // apple_device_check: None,
    pub check_type: Option<CheckType>,
    pub dev_check_sub: Option<String>,
    pub extra: Option<HashMap<String, String>>,
}

impl DataReport {
    #[must_use]
    pub fn from_client_error(
        client_error: String,
        request_hash: String,
        bundle_identifier: BundleIdentifier,
        aud: String,
        internal_debug_info: Option<String>,
    ) -> Self {
        Self {
            pass: false,
            out: OutEnum::Fail,
            client_error: Some(client_error),
            request_hash,
            timestamp: SystemTime::now(),
            bundle_identifier,
            aud,
            internal_debug_info,
            play_integrity: None,
            app_version: None,
            check_type: None,
            dev_check_sub: None,
            extra: None,
        }
    }

    /// Formats the `DataReport` as a JSON object and serializes it to a byte vector.
    ///
    /// This method generates a random identifier to act as partition key for the Kinesis stream.
    /// This is used because the `request_hash` is deleted after some time.
    ///
    /// # Errors
    /// Will return an `eyre::Error` if the serialization fails.
    pub fn as_vec(&self) -> eyre::Result<Vec<u8>> {
        let mut payload = serde_json::to_value(self)?;
        let obj = payload
            .as_object_mut()
            .ok_or_else(|| eyre::eyre!("Error serializing DataReport as JSON object"))?;

        let id = Uuid::new_v4().simple().to_string();
        obj.insert(
            "id".to_string(),
            serde_json::Value::String(format!("report_{id}")),
        );

        serde_json::to_vec(&payload).map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct OutputTokenPayload {
    pub issuer: String,
    pub aud: String,
    pub request_hash: String,
    pub bundle_identifier: BundleIdentifier,
    pub pass: bool,
    pub out: OutEnum,
    pub error: Option<String>,
    pub app_version: Option<String>,
    pub check_type: Option<CheckType>,
    pub extra: Option<HashMap<String, String>>,
}

#[allow(clippy::needless_pass_by_value)]
fn handle_jose_error(e: JoseError) -> RequestError {
    tracing::error!(
        "Error generating `JWTPayload` for `OutputTokenPayload`: {:?}",
        e
    );
    RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn handle_redis_error(e: RedisError) -> RequestError {
    tracing::error!("Redis error: {e}");
    RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    }
}

impl OutputTokenPayload {
    /// Generates a JWT payload for the output token.
    ///
    /// # Errors
    /// Will return a `JoseError` if the payload generation fails
    pub fn generate(&self) -> Result<JwtPayload, RequestError> {
        let mut payload = JwtPayload::new();
        payload.set_issued_at(&SystemTime::now());
        payload.set_issuer(&self.issuer);
        payload.set_expires_at(&(SystemTime::now() + OUTPUT_TOKEN_EXPIRATION));

        // Claims
        payload
            .set_claim("aud", Some(josekit::Value::String(self.aud.clone())))
            .map_err(handle_jose_error)?;
        payload
            .set_claim(
                "jti",
                Some(josekit::Value::String(self.request_hash.clone())),
            )
            .map_err(handle_jose_error)?;
        payload
            .set_claim(
                "bundle_identifier",
                Some(josekit::Value::String(self.bundle_identifier.to_string())),
            )
            .map_err(handle_jose_error)?;
        payload
            .set_claim("pass", Some(josekit::Value::Bool(self.pass)))
            .map_err(handle_jose_error)?;
        payload
            .set_claim("out", Some(josekit::Value::String(self.out.to_string())))
            .map_err(handle_jose_error)?;
        if let Some(error) = &self.error {
            payload
                .set_claim("error", Some(josekit::Value::String(error.clone())))
                .map_err(handle_jose_error)?;
        }

        if let Some(app_version) = &self.app_version {
            payload
                .set_claim(
                    "app_version",
                    Some(josekit::Value::String(app_version.clone())),
                )
                .map_err(handle_jose_error)?;
        }

        if let Some(check_type) = &self.check_type {
            payload
                .set_claim(
                    "check_type",
                    Some(josekit::Value::String(check_type.to_string())),
                )
                .map_err(handle_jose_error)?;
        }

        if let Some(extra) = &self.extra {
            let obj: josekit::Map<String, josekit::Value> = extra
                .iter()
                .map(|(k, v)| (k.clone(), josekit::Value::String(v.clone())))
                .collect();
            payload
                .set_claim("extra", Some(josekit::Value::Object(obj)))
                .map_err(handle_jose_error)?;
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn test_handle_jose_error() {
        let error = JoseError::InvalidClaim(anyhow::anyhow!("Invalid claim"));

        let result = handle_jose_error(error);

        assert_eq!(result.code, ErrorCode::InternalServerError);

        assert!(logs_contain(
            "Error generating `JWTPayload` for `OutputTokenPayload`:"
        ));
    }

    #[test]
    fn test_output_token_payload_generation() {
        let now = SystemTime::now();

        let payload = OutputTokenPayload {
            issuer: "attestation.worldcoin.org".to_string(),
            aud: "my-aud.com".to_string(),
            request_hash: "this_is_not_a_hash_with_enough_entropy".to_string(),
            bundle_identifier: BundleIdentifier::ComWorldcoinStaging,
            pass: true,
            out: OutEnum::Pass,
            error: None,
            app_version: Some("1.25.0".to_string()),
            check_type: Some(CheckType::Developer),
            extra: None,
        };

        let jwt_payload = payload.generate().unwrap();

        // Assert default claims
        assert_eq!(jwt_payload.issuer(), Some("attestation.worldcoin.org"));

        // Assert `exp` & `iat` within a few seconds of `now`
        assert!(jwt_payload.issued_at().unwrap() < (now + std::time::Duration::from_secs(5)));

        assert!(
            jwt_payload.issued_at().unwrap()
                < (now +
                // expiration time
                OUTPUT_TOKEN_EXPIRATION +
                // tolerance time
                std::time::Duration::from_secs(5))
        );

        // Assert remainder of claims
        assert_eq!(
            jwt_payload.claim("aud"),
            Some(&josekit::Value::String("my-aud.com".to_string()))
        );
        assert_eq!(
            jwt_payload.claim("jti"),
            Some(&josekit::Value::String(
                "this_is_not_a_hash_with_enough_entropy".to_string()
            ))
        );
        assert_eq!(jwt_payload.claim("pass"), Some(&josekit::Value::Bool(true)));
        assert_eq!(
            jwt_payload.claim("out"),
            Some(&josekit::Value::String("pass".to_string()))
        );
        assert_eq!(jwt_payload.claim("error"), None);
        assert_eq!(
            jwt_payload.claim("app_version"),
            Some(&josekit::Value::String("1.25.0".to_string()))
        );
        assert_eq!(
            jwt_payload.claim("check_type"),
            Some(&josekit::Value::String("dev".to_string()))
        );
    }

    #[test]
    fn test_data_report_does_not_serialize_nonce() {
        let token_payload_str = r#"
        {
            "requestDetails": {
                "requestPackageName": "com.worldcoin.staging",
                "nonce": "i_am_a_sample_request_hash",
                "timestampMillis": "1745276275999"
            },
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": "com.worldcoin.staging",
                "certificateSha256Digest": [
                    "nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8"
                ],
                "versionCode": "25700"
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": [
                    "MEETS_DEVICE_INTEGRITY"
                ]
            },
            "accountDetails": {
                "appLicensingVerdict": "LICENSED"
            },
            "environmentDetails": {
                "appAccessRiskVerdict": {
                    "appsDetected": [
                        "KNOWN_INSTALLED",
                        "UNKNOWN_INSTALLED",
                        "UNKNOWN_CAPTURING"
                    ]
                }
            }
        }"#;

        let token = PlayIntegrityToken::from_json(token_payload_str).unwrap();

        let data_report = DataReport {
            pass: true,
            out: OutEnum::Pass,
            client_error: None,
            request_hash: "i_am_a_sample_request_hash".to_string(),
            timestamp: SystemTime::now(),
            bundle_identifier: BundleIdentifier::ComWorldcoinStaging,
            aud: "example.worldcoin.org".to_string(),
            internal_debug_info: None,
            play_integrity: Some(token),
            app_version: Some("1.25.0".to_string()),
            check_type: Some(CheckType::Android),
            dev_check_sub: None,
            extra: None,
        };
        let serialized =
            serde_json::to_string(&data_report).expect("failed to serialize `DataReport` as json");

        let raw_deserialized: serde_json::Value =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(
            raw_deserialized["playIntegrity"]["requestDetails"]["nonce"],
            serde_json::Value::Null
        );
        assert_eq!(
            raw_deserialized["playIntegrity"]["requestDetails"]["requestPackageName"],
            serde_json::Value::String("com.worldcoin.staging".to_string())
        );
    }

    #[test]
    fn org_world_id_deserializes_from_wire_string() {
        let bundle: BundleIdentifier = serde_json::from_str("\"org.world.id\"").unwrap();
        assert!(matches!(bundle, BundleIdentifier::OrgWorldId));
    }

    #[test]
    fn org_world_id_android_cert_digest() {
        let bundle = BundleIdentifier::OrgWorldId;
        assert_eq!(
            bundle.android_certificate_sha256_digest(),
            // cspell:disable-next-line
            Some("nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8")
        );
        assert_eq!(
            bundle.android_certificate_sha256_digest_base64(),
            Some("nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8=")
        );
    }

    #[test]
    fn org_world_id_requires_play_store_prod_checks() {
        assert!(BundleIdentifier::OrgWorldId.requires_play_store_prod_checks());
        assert!(!BundleIdentifier::OrgWorldIdStaging.requires_play_store_prod_checks());
    }

    fn test_keys(tag: &str) -> AndroidResponseKeys {
        AndroidResponseKeys {
            outer_jwe_private_key: format!("{tag}-outer"),
            inner_jws_public_key: format!("{tag}-inner"),
        }
    }

    fn config_with_android_keys(
        world_app: Option<AndroidResponseKeys>,
        world_id: Option<AndroidResponseKeys>,
    ) -> GlobalConfig {
        GlobalConfig {
            android_default_keys: test_keys("default"),
            android_world_app_keys: world_app,
            android_world_id_keys: world_id,
            apple_keys_dynamo_table_name: String::new(),
            developer_inner_jwks_url: None,
            enabled_bundle_identifiers: Vec::new(),
            log_client_errors: false,
            kinesis_stream_arn: None,
            apple_root_ca_pem: Vec::new(),
            aud_whitelist: Vec::new(),
            jwt_issuer: String::new(),
            developer_portal_base_url: None,
            aud_authorization_cache_ttl_secs: 0,
        }
    }

    #[test]
    fn android_app_maps_bundles_to_families() {
        assert_eq!(
            BundleIdentifier::ComWorldcoin.android_app(),
            Some(AndroidApp::WorldApp)
        );
        assert_eq!(
            BundleIdentifier::ComWorldcoinStaging.android_app(),
            Some(AndroidApp::WorldApp)
        );
        assert_eq!(
            BundleIdentifier::ComWorldcoinDev.android_app(),
            Some(AndroidApp::WorldApp)
        );
        assert_eq!(
            BundleIdentifier::OrgWorldId.android_app(),
            Some(AndroidApp::WorldId)
        );
        assert_eq!(
            BundleIdentifier::OrgWorldIdStaging.android_app(),
            Some(AndroidApp::WorldId)
        );
        assert_eq!(
            BundleIdentifier::OrgWorldIdDev.android_app(),
            Some(AndroidApp::WorldId)
        );
        // iOS bundles have no Android Play Integrity flow
        assert_eq!(BundleIdentifier::OrgWorldcoinInsight.android_app(), None);
        assert_eq!(
            BundleIdentifier::OrgWorldcoinInsightStaging.android_app(),
            None
        );
        assert_eq!(BundleIdentifier::OrgWorldStagingId.android_app(), None);
    }

    #[test]
    fn apple_accepted_app_ids_always_contain_canonical() {
        // Whatever else is accepted, a bundle's canonical App ID must always be — otherwise
        // real store-signed apps would fail attestation.
        for bundle in [
            BundleIdentifier::OrgWorldId,
            BundleIdentifier::OrgWorldStagingId,
            BundleIdentifier::OrgWorldSandboxId,
            BundleIdentifier::OrgWorldcoinInsight,
            BundleIdentifier::OrgWorldcoinInsightStaging,
            BundleIdentifier::OrgWorldcoinInsightSandbox,
        ] {
            let accepted = bundle.apple_accepted_app_ids().unwrap();
            assert!(accepted.contains(&bundle.apple_app_id().unwrap()));
        }
    }

    #[test]
    fn production_bundles_accept_only_their_canonical_app_id() {
        // The invariant that keeps re-signed builds out of production: a production bundle must
        // accept exactly its one canonical App ID — never an extra. (Non-prod bundles may carry
        // an extra; the staging one does today, asserted below.)
        for bundle in [
            BundleIdentifier::OrgWorldId,
            BundleIdentifier::OrgWorldcoinInsight,
            BundleIdentifier::ComWorldcoin,
        ] {
            let app_ids = bundle
                .apple_accepted_app_ids()
                .map(|ids| ids.len())
                .unwrap_or(1);
            assert_eq!(
                app_ids, 1,
                "{bundle} is a production bundle and must accept only its canonical App ID"
            );
        }
        assert_eq!(
            BundleIdentifier::OrgWorldStagingId
                .apple_accepted_app_ids()
                .unwrap(),
            // cspell:disable-next-line
            vec![
                "35RXKB6738.org.world.staging.id",
                "5VLXJ89ZV9.org.world.staging.id"
            ],
        );
    }

    #[test]
    fn android_response_keys_uses_namespaced_when_set() {
        let config =
            config_with_android_keys(Some(test_keys("world_app")), Some(test_keys("world_id")));
        assert_eq!(
            config
                .android_response_keys(&BundleIdentifier::ComWorldcoin)
                .outer_jwe_private_key,
            "world_app-outer"
        );
        assert_eq!(
            config
                .android_response_keys(&BundleIdentifier::OrgWorldId)
                .outer_jwe_private_key,
            "world_id-outer"
        );
    }

    #[test]
    fn android_response_keys_falls_back_to_default_when_unset() {
        let config = config_with_android_keys(None, None);
        // World App without a namespaced key -> default.
        assert_eq!(
            config
                .android_response_keys(&BundleIdentifier::ComWorldcoin)
                .outer_jwe_private_key,
            "default-outer"
        );
        // World ID without a namespaced key (e.g. staging) -> default, no panic/error.
        assert_eq!(
            config
                .android_response_keys(&BundleIdentifier::OrgWorldId)
                .outer_jwe_private_key,
            "default-outer"
        );
        // iOS / unmapped bundle -> default.
        assert_eq!(
            config
                .android_response_keys(&BundleIdentifier::OrgWorldcoinInsight)
                .outer_jwe_private_key,
            "default-outer"
        );
    }
}
