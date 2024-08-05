use crate::android::PlayIntegrityToken;
use aide::OperationIo;
use axum::response::IntoResponse;
use josekit::{jwt::JwtPayload, JoseError};
use redis::RedisError;
use schemars::JsonSchema;
use std::{fmt::Display, time::SystemTime};

static OUTPUT_TOKEN_EXPIRATION: std::time::Duration = std::time::Duration::from_secs(60 * 10);

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub output_token_kms_key_arn: String,
    pub android_outer_jwe_private_key: String,
}

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
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TokenGenerationResponse {
    pub attestation_gateway_token: String,
}

/// Represents an error that is attributable to the client and represents expected behavior for the API.
/// For example, when an expired integrity token is passed.
/// `ClientError`s are not logged by default and result in a 4xx status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    pub code: ErrorCode,
    pub internal_debug_info: String,
}

impl Display for ClientError {
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
        struct ErrorResponse {
            code: String,
            details: String,
        }
        (
            self.code.as_http_status_code(),
            axum::Json(ErrorResponse {
                code: self.code.to_string(),
                details: self
                    .details
                    .unwrap_or_else(|| self.code.as_default_error_message().to_string()),
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
            Self::InvalidToken => write!(f, "invalid_token"),
        }
    }
}

impl ErrorCode {
    const fn as_http_status_code(self) -> axum::http::StatusCode {
        match self {
            Self::InternalServerError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::DuplicateRequestHash => axum::http::StatusCode::CONFLICT,
            Self::BadRequest | Self::ExpiredToken | Self::IntegrityFailed | Self::InvalidToken => {
                axum::http::StatusCode::BAD_REQUEST
            }
        }
    }

    const fn as_default_error_message(self) -> &'static str {
        match self {
            Self::BadRequest => "The request is malformed.",
            Self::DuplicateRequestHash => "The `request_hash` has already been used.",
            Self::ExpiredToken => "The integrity token has expired. Please generate a new one.",
            Self::IntegrityFailed => "Integrity checks have not passed.",
            Self::InternalServerError => "Internal server error. Please try again.",
            Self::InvalidToken => "The provided token is invalid or malformed.",
        }
    }
}

#[derive(Debug, serde::Serialize)]
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
    pub client_error: Option<ClientError>,
}

/// `DataReport` is used to serialize the output logged to Kinesis for analytics and debugging purposes.
/// The `request_hash` has a retention period of 30 days.
#[derive(Debug, serde::Serialize)]
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
    // apple_device_check: None,
}

#[derive(Debug)]
pub struct OutputTokenPayload {
    pub aud: String,
    pub request_hash: String,
    pub pass: bool,
    pub out: OutEnum,
    pub error: Option<String>,
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
    }
}
