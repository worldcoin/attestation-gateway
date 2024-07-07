use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestDetails {
    #[serde(rename = "requestPackageName")]
    pub request_package_name: String,

    pub nonce: String,

    #[serde(rename = "timestampMillis")]
    pub timestamp_millis: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppIntegrity {
    #[serde(rename = "appRecognitionVerdict")]
    pub app_recognition_verdict: AppIntegrityVerdict,

    #[serde(rename = "packageName")]
    pub package_name: String,

    #[serde(rename = "certificateSha256Digest")]
    pub certificate_sha_256_digest: Vec<String>,

    #[serde(rename = "versionCode")]
    pub version_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecentDeviceActivity {
    #[serde(rename = "deviceActivityLevel")]
    pub device_activity_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceIntegrity {
    #[serde(rename = "deviceRecognitionVerdict")]
    pub device_recognition_verdict: Vec<String>,

    #[serde(rename = "recentDeviceActivity")]
    pub recent_device_activity: Option<RecentDeviceActivity>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountDetails {
    #[serde(rename = "appLicensingVerdict")]
    pub app_licensing_verdict: AppLicensingVerdict,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppAccessRiskVerdict {
    #[serde(rename = "appsDetected")]
    pub apps_detected: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentDetails {
    #[serde(rename = "appAccessRiskVerdict")]
    pub app_access_risk_verdict: AppAccessRiskVerdict,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AppIntegrityVerdict {
    #[serde(rename = "PLAY_RECOGNIZED")]
    PlayRecognized,
    #[serde(rename = "UNRECOGNIZED_VERSION")]
    UnrecognizedVersion,
    #[serde(rename = "UNEVALUATED")]
    Unevaluated,
}

impl Display for AppIntegrityVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::PlayRecognized => write!(f, "PLAY_RECOGNIZED"),
            Self::UnrecognizedVersion => write!(f, "UNRECOGNIZED_VERSION"),
            Self::Unevaluated => write!(f, "UNEVALUATED"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AppLicensingVerdict {
    #[serde(rename = "LICENSED")]
    Licensed,
    #[serde(rename = "UNLICENSED")]
    Unlicensed,
    #[serde(rename = "UNEVALUATED")]
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
pub struct PlayIntegrityToken {
    #[serde(rename = "requestDetails")]
    pub request_details: RequestDetails,

    #[serde(rename = "appIntegrity")]
    pub app_integrity: AppIntegrity,

    #[serde(rename = "deviceIntegrity")]
    pub device_integrity: DeviceIntegrity,

    #[serde(rename = "accountDetails")]
    pub account_details: AccountDetails,

    #[serde(rename = "environmentDetails")]
    pub environment_details: Option<EnvironmentDetails>,
}
