use schemars::JsonSchema;
use std::fmt::Display;

#[derive(Debug)]
pub enum Platform {
    IOS,
    Android,
}

impl Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Platform::IOS => write!(f, "ios"),
            Platform::Android => write!(f, "android"),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleIdentifier {
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
    pub fn platform(&self) -> Platform {
        match self {
            Self::AndroidProdWorldApp | Self::AndroidStageWorldApp | Self::AndroidDevWorldApp => {
                Platform::Android
            }
            Self::IOSProdWorldApp | Self::IOSStageWorldApp => Platform::IOS,
        }
    }
}

#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct TokenGenerationRequest {
    pub integrity_token: String,
    pub client_error: Option<String>,
    pub aud: String,
    pub bundle_identifier: BundleIdentifier,
    pub request_hash: String,
    pub apple_initial_attestation: Option<String>,
    pub apple_public_key: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct TokenGenerationResponse {
    pub attestation_gateway_token: String,
}
