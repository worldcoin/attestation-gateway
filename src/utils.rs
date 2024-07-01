use schemars::JsonSchema;
use std::fmt::Display;

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
#[derive(Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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
    pub const fn platform(&self) -> Platform {
        match self {
            Self::AndroidProdWorldApp | Self::AndroidStageWorldApp | Self::AndroidDevWorldApp => {
                Platform::Android
            }
            Self::IOSProdWorldApp | Self::IOSStageWorldApp => Platform::AppleIOS,
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
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
