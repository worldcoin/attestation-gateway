use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    time::{Duration, SystemTime},
};

use crate::utils::{BundleIdentifier, ClientError, ErrorCode};

// FIXME const ALLOWED_TIMESTAMP_WINDOW: u64 = 10 * 600;
const ALLOWED_TIMESTAMP_WINDOW: u64 = 10_000_000;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetails {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_system_time_from_millis")]
    pub timestamp_millis: SystemTime,
    pub request_package_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIntegrity {
    pub package_name: String,
    pub version_code: String,
    pub certificate_sha_256_digest: Vec<String>,
    pub app_recognition_verdict: AppIntegrityVerdict,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentDeviceActivity {
    pub device_activity_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrity {
    pub device_recognition_verdict: Vec<String>,
    pub recent_device_activity: Option<RecentDeviceActivity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDetails {
    pub app_licensing_verdict: AppLicensingVerdict,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppAccessRiskVerdict {
    pub apps_detected: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlayProtectVerdict {
    NoIssues,
    NoData,
    PossibleRisk,
    MediumRisk,
    HighRisk,
    Unevaluated,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentDetails {
    pub app_access_risk_verdict: AppAccessRiskVerdict,
    #[serde(rename = "playProtectVerdict")]
    pub play_protect_verdict: Option<PlayProtectVerdict>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppIntegrityVerdict {
    Unevaluated,
    PlayRecognized,
    UnrecognizedVersion,
}

impl Display for AppIntegrityVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Unevaluated => write!(f, "UNEVALUATED"),
            Self::PlayRecognized => write!(f, "PLAY_RECOGNIZED"),
            Self::UnrecognizedVersion => write!(f, "UNRECOGNIZED_VERSION"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppLicensingVerdict {
    Licensed,
    Unlicensed,
    Unevaluated,
}

impl Display for AppLicensingVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Licensed => write!(f, "LICENSED"),
            Self::Unlicensed => write!(f, "UNLICENSED"),
            Self::Unevaluated => write!(f, "UNEVALUATED"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayIntegrityToken {
    pub app_integrity: AppIntegrity,
    pub account_details: AccountDetails,
    pub request_details: RequestDetails,
    pub device_integrity: DeviceIntegrity,
    pub environment_details: Option<EnvironmentDetails>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum StringOrInt {
    String(String),
    Number(u64),
}

/// Deserialize a `SystemTime` from a timestamp in milliseconds.
///
/// # Errors
///
/// This function will return an error if the timestamp is not a valid integer or string.
pub fn deserialize_system_time_from_millis<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SystemTime, D::Error> {
    let timestamp_millis = match StringOrInt::deserialize(deserializer)? {
        StringOrInt::String(s) => s.parse().map_err(serde::de::Error::custom),
        StringOrInt::Number(i) => Ok(i),
    }?;

    Ok(SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp_millis))
}

impl PlayIntegrityToken {
    /// Initializes a `PlayIntegrityToken` struct from a JSON payload.
    ///
    /// # Errors
    /// Will return a `serde_json` error if parsing fails.
    pub fn from_json(integrity_token_json_payload: &str) -> eyre::Result<Self> {
        Ok(serde_json::from_str::<Self>(integrity_token_json_payload)?)
    }

    ///  Validates all relevant claims are validated to determine if the token passes the business rules for integrity.
    ///
    /// # Errors
    /// - Returns a `ClientError` if business rules fail for the payload of the integrity token.
    /// - Returns an `eyre::Error` if there are any unexpected issues verifying the token.
    pub fn validate_all_claims(
        &self,
        bundle_identifier: &BundleIdentifier,
        request_hash: &str,
    ) -> eyre::Result<()> {
        // Step 1: Request details checks
        self.validate_request_details(bundle_identifier, request_hash)?;

        // Step 2: App integrity checks
        self.validate_app_integrity(bundle_identifier)?;

        // Step 3: Device integrity checks
        self.validate_device_integrity()?;

        // Step 4: Account details checks
        self.validate_account_details(bundle_identifier)?;

        // Step 5: Environment details
        self.validate_environment_details()?;

        Ok(())
    }

    fn validate_request_details(
        &self,
        bundle_identifier: &BundleIdentifier,
        request_hash: &str,
    ) -> eyre::Result<()> {
        if self.request_details.request_package_name != bundle_identifier.to_string() {
            return Err(
                eyre::eyre!(ClientError {
                    code: ErrorCode::IntegrityFailed,
                    internal_debug_info: "Provided `bundle_identifier` does not match request_details.request_package_name".to_string(),
                })
            );
        }

        let duration = SystemTime::now().duration_since(self.request_details.timestamp_millis)?;

        if duration.as_secs() > ALLOWED_TIMESTAMP_WINDOW {
            return Err(eyre::eyre!(ClientError {
                code: ErrorCode::ExpiredToken,
                internal_debug_info:
                    "The timestamp_millis of the token is older than the TOKEN_MAX_AGE".to_string(),
            }));
        }

        if self.request_details.nonce != request_hash {
            return Err(eyre::eyre!(ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "Provided `request_hash` does not match request_details.nonce"
                    .to_string(),
            }));
        }

        Ok(())
    }

    fn validate_app_integrity(&self, bundle_identifier: &BundleIdentifier) -> eyre::Result<()> {
        if self.app_integrity.package_name != bundle_identifier.to_string() {
            return Err(eyre::eyre!(ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info:
                    "Provided `bundle_identifier` does not match app_integrity.package_name"
                        .to_string(),
            }));
        }

        if bundle_identifier == &BundleIdentifier::AndroidProdWorldApp {
            // Only in Production: App should come from Play Store
            if self.app_integrity.app_recognition_verdict != AppIntegrityVerdict::PlayRecognized {
                return Err(eyre::eyre!(ClientError {
                    code: ErrorCode::IntegrityFailed,
                    internal_debug_info: "AppIntegrityVerdict does not match PlayRecognized"
                        .to_string(),
                }));
            }
        }

        if let Some(digest) = bundle_identifier.certificate_sha256_digest() {
            if !self
                .app_integrity
                .certificate_sha_256_digest
                .contains(&digest.to_string())
            {
                return Err(eyre::eyre!(ClientError {
                    code: ErrorCode::IntegrityFailed,
                    internal_debug_info:
                        "certificate_sha_256_digest does not match the expected value".to_string(),
                }));
            }
        } else {
            return Err(eyre::eyre!("certificate_sha_256_digest is None"));
        }

        Ok(())
    }

    fn validate_device_integrity(&self) -> eyre::Result<()> {
        if !self
            .device_integrity
            .device_recognition_verdict
            .contains(&"MEETS_DEVICE_INTEGRITY".to_string())
        {
            return Err(eyre::eyre!(ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info:
                    "device_recognition_verdict does not contain MEETS_DEVICE_INTEGRITY".to_string(),
            }));
        }
        Ok(())
    }

    fn validate_account_details(&self, bundle_identifier: &BundleIdentifier) -> eyre::Result<()> {
        if bundle_identifier == &BundleIdentifier::AndroidProdWorldApp {
            // Only in Production: App should come from Play Store
            if self.account_details.app_licensing_verdict != AppLicensingVerdict::Licensed {
                return Err(eyre::eyre!(ClientError {
                    code: ErrorCode::IntegrityFailed,
                    internal_debug_info: "AppLicensingVerdict does not match LICENSED".to_string(),
                }));
            }
        }
        Ok(())
    }

    fn validate_environment_details(&self) -> eyre::Result<()> {
        if let Some(value) = &self.environment_details {
            if value.play_protect_verdict == Some(PlayProtectVerdict::HighRisk) {
                return Err(eyre::eyre!(ClientError {
                    code: ErrorCode::IntegrityFailed,
                    internal_debug_info: "PlayProtectVerdict reported as HighRisk".to_string(),
                }));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn create_test_token() -> PlayIntegrityToken {
        PlayIntegrityToken {
            app_integrity: AppIntegrity {
                package_name: "com.worldcoin.staging".to_string(),
                version_code: "25700".to_string(),
                certificate_sha_256_digest: vec![
                    // cspell:disable-next-line
                    "nSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8".to_string(),
                ],
                app_recognition_verdict: AppIntegrityVerdict::PlayRecognized,
            },
            account_details: AccountDetails {
                app_licensing_verdict: AppLicensingVerdict::Licensed,
            },
            request_details: RequestDetails {
                nonce: "valid_nonce".to_string(),
                timestamp_millis: SystemTime::now(),
                request_package_name: "com.worldcoin.staging".to_string(),
            },
            device_integrity: DeviceIntegrity {
                device_recognition_verdict: vec!["MEETS_DEVICE_INTEGRITY".to_string()],
                recent_device_activity: None,
            },
            environment_details: Some(EnvironmentDetails {
                app_access_risk_verdict: AppAccessRiskVerdict {
                    apps_detected: vec![],
                },
                play_protect_verdict: Some(PlayProtectVerdict::NoIssues),
            }),
        }
    }

    #[test]
    fn parse_and_validate_a_valid_token() {
        let token = create_test_token();
        token
            .validate_all_claims(&BundleIdentifier::AndroidStageWorldApp, "valid_nonce")
            .unwrap();
    }

    #[test]
    fn test_validate_all_claims() {
        // cspell:disable
        let token_payload_str = r#"
        {
            "requestDetails": {
                "requestPackageName": "com.worldcoin.staging",
                "nonce": "aGVsbG8gd29scmQgdGhlcmU",
                "timestampMillis": "1720506932737"
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
        // cspell:enable

        let token = PlayIntegrityToken::from_json(token_payload_str).unwrap();

        let result = token.validate_all_claims(
            &BundleIdentifier::AndroidStageWorldApp,
            "invalid_nonce", // <-- This nonce is invalid, it will not match request_details.nonce
        );

        let client_error = result
            .expect_err("Expected an error, but got success")
            .downcast::<ClientError>()
            .expect("Unexpected non-client error");

        assert_eq!(client_error.code, ErrorCode::IntegrityFailed);
        assert_eq!(
            client_error.internal_debug_info,
            "Provided `request_hash` does not match request_details.nonce"
        );
    }

    #[test]
    fn creating_a_play_integrity_with_invalid_payload_fails() {
        let token_payload_with_missing_attributes = r#"
        {
            "requestDetails": {
                "requestPackageName": "com.worldcoin.staging",
                "nonce": "123",
                "timestampMillis": "1720506932737"
            }
        }"#;

        let error_report =
            PlayIntegrityToken::from_json(token_payload_with_missing_attributes).unwrap_err();

        assert_eq!(
            "missing field `appIntegrity` at line 8 column 9",
            error_report.to_string()
        );

        // note the `unwrap_err` here, as the payload is not valid JSON
        let _ = PlayIntegrityToken::from_json("not_even_valid_json").unwrap_err();
    }

    #[test]
    fn test_validate_request_details() {
        let token = create_test_token();

        assert!(token
            .validate_request_details(&BundleIdentifier::AndroidStageWorldApp, "valid_nonce")
            .is_ok());

        // Test invalid package name
        let error = token
            .validate_request_details(&BundleIdentifier::AndroidProdWorldApp, "valid_nonce")
            .unwrap_err();

        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "Provided `bundle_identifier` does not match request_details.request_package_name".to_string(),
            }
        );

        // Test expired token
        let mut expired_token = create_test_token();
        expired_token.request_details.timestamp_millis = UNIX_EPOCH + Duration::from_secs(0);
        let error = expired_token
            .validate_request_details(&BundleIdentifier::AndroidStageWorldApp, "valid_nonce")
            .unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::ExpiredToken,
                internal_debug_info:
                    "The timestamp_millis of the token is older than the TOKEN_MAX_AGE".to_string()
            }
        );

        // Test invalid nonce
        let error = token
            .validate_request_details(&BundleIdentifier::AndroidStageWorldApp, "invalid_nonce")
            .unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "Provided `request_hash` does not match request_details.nonce"
                    .to_string()
            }
        );
    }

    #[test]
    fn test_validate_app_integrity() {
        let token = create_test_token();

        // Test valid app integrity
        assert!(token
            .validate_app_integrity(&BundleIdentifier::AndroidStageWorldApp)
            .is_ok());

        // Test invalid package name (passing a different bundle identifier)
        let error = token
            .validate_app_integrity(&BundleIdentifier::AndroidProdWorldApp)
            .unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info:
                    "Provided `bundle_identifier` does not match app_integrity.package_name"
                        .to_string()
            }
        );

        // Test invalid certificate sha256
        let mut invalid_token = create_test_token();
        invalid_token.app_integrity.certificate_sha_256_digest =
            vec!["different_sha_256".to_string()];
        let error = invalid_token
            .validate_app_integrity(&BundleIdentifier::AndroidStageWorldApp)
            .unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "certificate_sha_256_digest does not match the expected value"
                    .to_string()
            }
        );
    }

    #[test]
    fn test_validate_device_integrity() {
        let token = create_test_token();

        // Test valid device integrity
        assert!(token.validate_device_integrity().is_ok());

        // Test device which is running on a device with signs of attack
        let mut invalid_token = create_test_token();
        invalid_token.device_integrity.device_recognition_verdict = vec![];
        let error = invalid_token.validate_device_integrity().unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info:
                    "device_recognition_verdict does not contain MEETS_DEVICE_INTEGRITY".to_string()
            }
        );
    }

    #[test]
    fn test_validate_account_details() {
        let token = create_test_token();
        let bundle_identifier = BundleIdentifier::AndroidProdWorldApp;

        // Test valid account details
        assert!(token.validate_account_details(&bundle_identifier).is_ok());

        // Test unlicensed app
        let mut invalid_token = create_test_token();
        invalid_token.account_details.app_licensing_verdict = AppLicensingVerdict::Unlicensed;
        let error = invalid_token
            .validate_account_details(&bundle_identifier)
            .unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "AppLicensingVerdict does not match LICENSED".to_string(),
            }
        );
    }

    #[test]
    fn test_validate_environment_details() {
        let token = create_test_token();

        // Test valid environment details
        assert!(token.validate_environment_details().is_ok());

        // Test high-risk environment
        let mut invalid_token = create_test_token();
        invalid_token.environment_details = Some(EnvironmentDetails {
            app_access_risk_verdict: AppAccessRiskVerdict {
                apps_detected: vec![],
            },
            play_protect_verdict: Some(PlayProtectVerdict::HighRisk),
        });
        let error = invalid_token.validate_environment_details().unwrap_err();
        assert_eq!(
            error.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::IntegrityFailed,
                internal_debug_info: "PlayProtectVerdict reported as HighRisk".to_string(),
            }
        );

        // Test with no environment details (this is still a valid token)
        let mut valid_token = create_test_token();
        valid_token.environment_details = None;
        assert!(valid_token.validate_environment_details().is_ok());
    }
}
