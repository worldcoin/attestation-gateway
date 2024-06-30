use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer};
use std::{fmt::Display, str::FromStr};

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

#[derive(Debug, JsonSchema)]
pub enum BundleIdentifier {
    AndroidProdWorldApp,
    AndroidStageWorldApp,
    AndroidDevWorldApp,
    IOSProdWorldApp,
    IOSStageWorldApp,
}

impl Display for BundleIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BundleIdentifier::AndroidProdWorldApp => write!(f, "com.worldcoin"),
            BundleIdentifier::AndroidStageWorldApp => write!(f, "com.worldcoin.staging"),
            BundleIdentifier::AndroidDevWorldApp => write!(f, "com.worldcoin.dev"),
            BundleIdentifier::IOSProdWorldApp => write!(f, "org.worldcoin.insight"),
            BundleIdentifier::IOSStageWorldApp => write!(f, "org.worldcoin.insight.staging"),
        }
    }
}

impl FromStr for BundleIdentifier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "com.worldcoin" => Ok(Self::AndroidProdWorldApp),
            "com.worldcoin.staging" => Ok(Self::AndroidStageWorldApp),
            "com.worldcoin.dev" => Ok(Self::AndroidDevWorldApp),
            "org.worldcoin.insight" => Ok(Self::IOSProdWorldApp),
            "org.worldcoin.insight.staging" => Ok(Self::IOSStageWorldApp),
            _ => Err(format!("Invalid bundle identifier: {s}")),
        }
    }
}

impl<'de> Deserialize<'de> for BundleIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        BundleIdentifier::from_str(s).map_err(de::Error::custom)
    }
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
