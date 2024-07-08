use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetails {
    pub nonce: String,
    pub timestamp_millis: String,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentDetails {
    pub app_access_risk_verdict: AppAccessRiskVerdict,
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

#[derive(Debug, Serialize, Deserialize)]
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
