use crate::android::PlayIntegrityToken;
use aide::OperationIo;
use axum::response::IntoResponse;
use josekit::{jwt::JwtPayload, JoseError};
use redis::RedisError;
use schemars::JsonSchema;
use std::{env, fmt::Display, time::SystemTime};
use uuid::Uuid;

static OUTPUT_TOKEN_EXPIRATION: std::time::Duration = std::time::Duration::from_secs(60 * 10);

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub android_outer_jwe_private_key: String,
    pub android_inner_jws_public_key: String,
    pub apple_keys_dynamo_table_name: String,
    pub tools_for_humanity_inner_jws_public_key: String,
    pub enabled_bundle_identifiers: Vec<BundleIdentifier>,
    /// Determines whether to log the client errors as warnings for debugging purposes (should generally only be enabled in development or staging)
    pub log_client_errors: bool,
    pub kinesis_stream_arn: Option<String>,
}

impl GlobalConfig {
    /// Loads global config from environment variables
    ///
    /// # Panics
    /// If required environment variables are not set
    pub fn from_env() -> Self {
        let android_outer_jwe_private_key = env::var("ANDROID_OUTER_JWE_PRIVATE_KEY")
            .expect("env var `ANDROID_OUTER_JWE_PRIVATE_KEY` is required");

        let android_inner_jws_public_key = env::var("ANDROID_INNER_JWS_PUBLIC_KEY")
            .expect("env var `ANDROID_INNER_JWS_PUBLIC_KEY` is required");

        let apple_keys_dynamo_table_name = env::var("APPLE_KEYS_DYNAMO_TABLE_NAME")
            .expect("env var `APPLE_KEYS_DYNAMO_TABLE_NAME` is required");

        let tools_for_humanity_inner_jws_public_key =
            env::var("TOOLS_FOR_HUMANITY_INNER_JWS_PUBLIC_KEY")
                .expect("env var `TOOLS_FOR_HUMANITY_INNER_JWS_PUBLIC_KEY` is required");

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

        tracing::info!(
            "Running with enabled bundle identifiers: {:?}",
            enabled_bundle_identifiers
        );

        Self {
            android_outer_jwe_private_key,
            android_inner_jws_public_key,
            apple_keys_dynamo_table_name,
            tools_for_humanity_inner_jws_public_key,
            enabled_bundle_identifiers,
            log_client_errors,
            kinesis_stream_arn,
        }
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

#[derive(Debug)]
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

#[allow(clippy::enum_variant_names)] // Only World App is supported right now (postfix)
#[derive(Debug, serde::Serialize, serde::Deserialize, JsonSchema, PartialEq, Eq, Clone)]
pub enum BundleIdentifier {
    // World App
    #[serde(rename = "com.worldcoin")]
    AndroidProdWorldApp,
    #[serde(rename = "com.worldcoin.staging")]
    AndroidStageWorldApp,
    #[serde(rename = "com.worldcoin.dev")]
    AndroidDevWorldApp,
    #[serde(rename = "org.worldcoin.insight")]
    IOSProdWorldApp,
    #[serde(rename = "org.worldcoin.insight.staging")]
    IOSStageWorldApp,
}

impl BundleIdentifier {
    #[must_use]
    pub const fn platform(&self) -> Platform {
        match self {
            Self::AndroidProdWorldApp | Self::AndroidStageWorldApp | Self::AndroidDevWorldApp => {
                Platform::Android
            }
            Self::IOSProdWorldApp | Self::IOSStageWorldApp => Platform::AppleIOS,
        }
    }

    #[must_use]
    pub const fn certificate_sha256_digest(&self) -> Option<&str> {
        match self {
            Self::AndroidProdWorldApp | Self::AndroidStageWorldApp => {
                // cspell:disable-next-line
                Some("nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8")
            }
            Self::AndroidDevWorldApp => Some("6a6a1474b5cbbb2b1aa57e0bc3"),
            Self::IOSProdWorldApp | Self::IOSStageWorldApp => None,
        }
    }

    #[must_use]
    pub const fn apple_app_id(&self) -> Option<&str> {
        match self {
            Self::AndroidProdWorldApp | Self::AndroidStageWorldApp | Self::AndroidDevWorldApp => {
                None
            }
            // cspell:disable
            Self::IOSStageWorldApp => Some("35RXKB6738.org.worldcoin.insight.staging"),
            Self::IOSProdWorldApp => Some("35RXKB6738.org.worldcoin.insight"),
            // cspell:enable
        }
    }
}

impl Display for BundleIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::AndroidProdWorldApp => write!(f, "com.worldcoin"),
            Self::AndroidStageWorldApp => write!(f, "com.worldcoin.staging"),
            Self::AndroidDevWorldApp => write!(f, "com.worldcoin.dev"),
            Self::IOSProdWorldApp => write!(f, "org.worldcoin.insight"),
            Self::IOSStageWorldApp => write!(f, "org.worldcoin.insight.staging"),
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
    pub tools_for_humanity_token: Option<String>,
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
}

impl IntegrityVerificationInput {
    /// Parses a `TokenGenerationRequest` into an `IntegrityVerificationInput` specifically for an Android or Apple integrity check.
    ///
    /// # Errors
    /// Will return a `RequestError` if the request is malformed or missing required fields.
    ///
    /// # Panics
    /// No panics expected.
    pub fn from_request(request: &TokenGenerationRequest) -> Result<Self, RequestError> {
        if let Some(client_error) = request.client_error.clone() {
            return Ok(Self::ClientError { client_error });
        }

        match request.bundle_identifier.platform() {
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
            | Self::InvalidToken => axum::http::StatusCode::BAD_REQUEST,
        }
    }

    const fn into_default_error_message(self) -> &'static str {
        match self {
            Self::BadRequest => "The request is malformed.",
            Self::DuplicateRequestHash => "The `request_hash` has already been used.",
            Self::ExpiredToken => "The integrity token has expired. Please generate a new one.",
            Self::IntegrityFailed => "Integrity checks have not passed.",
            Self::InternalServerError => "Internal server error. Please try again.",
            Self::InvalidAttestationForApp => "The provided attestation is not valid for this app. Verify the provided bundle identifier is correct for this attestation object.",
            Self::InvalidInitialAttestation => "This public key has already gone through initial attestation. Use assertion instead.",
            Self::InvalidPublicKey => "Public key has not been attested.",
            Self::InvalidToken => "The provided token or attestation is invalid or malformed.",
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

#[derive(Debug)]
pub struct VerificationOutput {
    pub success: bool,
    pub parsed_play_integrity_token: Option<PlayIntegrityToken>,
    pub client_exception: Option<ClientException>,
    pub app_version: Option<String>,
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
    pub aud: String,
    pub request_hash: String,
    pub pass: bool,
    pub out: OutEnum,
    pub error: Option<String>,
    pub app_version: Option<String>,
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
        payload.set_issuer("attestation.worldcoin.org");
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
            aud: "my-aud.com".to_string(),
            request_hash: "this_is_not_a_hash_with_enough_entropy".to_string(),
            pass: true,
            out: OutEnum::Pass,
            error: None,
            app_version: Some("1.25.0".to_string()),
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
            bundle_identifier: BundleIdentifier::AndroidStageWorldApp,
            aud: "example.worldcoin.org".to_string(),
            internal_debug_info: None,
            play_integrity: Some(token),
            app_version: Some("1.25.0".to_string()),
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
}
