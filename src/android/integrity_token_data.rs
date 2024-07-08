use crate::utils::deserialize_system_time_from_millis;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, time::SystemTime};

use crate::utils::{BundleIdentifier, ErrorCode, RequestError};

// TODO const ALLOWED_TIMESTAMP_WINDOW: u64 = 10 * 600;
const ALLOWED_TIMESTAMP_WINDOW: u64 = 10_000_000_000_000;

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
pub enum PlayProtectVerdict {
    #[serde(rename = "NO_ISSUES")]
    NoIssues,
    #[serde(rename = "NO_DATA")]
    NoData,
    #[serde(rename = "POSSIBLE_RISK")]
    PossibleRisk,
    #[serde(rename = "MEDIUM_RISK")]
    MediumRisk,
    #[serde(rename = "HIGH_RISK")]
    HighRisk,
    #[serde(rename = "UNEVALUATED")]
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

impl PlayIntegrityToken {
    pub fn validate_request_details(
        &self,
        bundle_identifier: &BundleIdentifier,
        request_hash: &str,
    ) -> Result<(), RequestError> {
        if self.request_details.request_package_name != bundle_identifier.to_string() {
            return Err(RequestError {
                code: ErrorCode::InvalidBundleIdentifier,
                internal_details: Some(
                    "Provided `bundle_identifier` does not match request_details.request_package_name"
                        .to_string(),
                ),
            });
        }

        let duration = SystemTime::now()
            .duration_since(self.request_details.timestamp_millis)
            .map_err(|_| RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some(
                    "Could not calculate timestamp_millis difference".to_string(),
                ),
            })?;

        if duration.as_secs() > ALLOWED_TIMESTAMP_WINDOW {
            return Err(RequestError {
                code: ErrorCode::ExpiredToken,
                internal_details: Some(
                    "The timestamp_millis of the token is older than the TOKEN_MAX_AGE".to_string(),
                ),
            });
        }

        if self.request_details.nonce != request_hash {
            return Err(RequestError {
                code: ErrorCode::IntegrityFailed,
                internal_details: Some(
                    "Provided `request_hash` does not match request_details.nonce".to_string(),
                ),
            });
        }

        Ok(())
    }

    pub fn validate_app_integrity(
        &self,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<(), RequestError> {
        if self.app_integrity.package_name != bundle_identifier.to_string() {
            return Err(RequestError {
                code: ErrorCode::InvalidBundleIdentifier,
                internal_details: Some(
                    "Provided `bundle_identifier` does not match app_integrity.package_name"
                        .to_string(),
                ),
            });
        }

        if bundle_identifier == &BundleIdentifier::AndroidProdWorldApp {
            // Only in Production: App should come from Play Store
            if self.app_integrity.app_recognition_verdict != AppIntegrityVerdict::PlayRecognized {
                return Err(RequestError {
                    code: ErrorCode::IntegrityFailed,
                    internal_details: Some(
                        "AppIntegrityVerdict does not match PlayRecognized".to_string(),
                    ),
                });
            }
        }

        if let Some(digest) = bundle_identifier.certificate_sha256_digest() {
            if !self
                .app_integrity
                .certificate_sha_256_digest
                .contains(&digest.to_string())
            {
                return Err(RequestError {
                    code: ErrorCode::IntegrityFailed,
                    internal_details: Some(
                        "certificate_sha_256_digest does not match the expected value".to_string(),
                    ),
                });
            }
        } else {
            return Err(RequestError {
                code: ErrorCode::InternalServerError,
                internal_details: Some("certificate_sha_256_digest is None".to_string()),
            });
        }

        Ok(())
    }

    pub fn validate_device_integrity(&self) -> Result<(), RequestError> {
        if !self
            .device_integrity
            .device_recognition_verdict
            .contains(&"MEETS_DEVICE_INTEGRITY".to_string())
        {
            return Err(RequestError {
                code: ErrorCode::IntegrityFailed,
                internal_details: Some(
                    "device_recognition_verdict does not contain MEETS_DEVICE_INTEGRITY"
                        .to_string(),
                ),
            });
        }
        Ok(())
    }

    pub fn validate_account_details(
        &self,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<(), RequestError> {
        if bundle_identifier == &BundleIdentifier::AndroidProdWorldApp {
            // Only in Production: App should come from Play Store
            if self.account_details.app_licensing_verdict != AppLicensingVerdict::Licensed {
                return Err(RequestError {
                    code: ErrorCode::IntegrityFailed,
                    internal_details: Some(
                        "AppLicensingVerdict does not match Licensed".to_string(),
                    ),
                });
            }
        }
        Ok(())
    }

    pub fn validate_environment_details(&self) -> Result<(), RequestError> {
        if let Some(value) = &self.environment_details {
            if value.play_protect_verdict == Some(PlayProtectVerdict::HighRisk) {
                return Err(RequestError {
                    code: ErrorCode::IntegrityFailed,
                    internal_details: Some("PlayProtectVerdict reported as HighRisk".to_string()),
                });
            }
        }

        Ok(())
    }
}
