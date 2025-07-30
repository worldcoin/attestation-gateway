use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    time::{Duration, SystemTime},
};

use crate::utils::{BundleIdentifier, ClientException, ErrorCode};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsForHumanityInnerToken {
    pub exp: u64,
    pub principal: String,
    pub public_key: String,
}

impl ToolsForHumanityInnerToken {
    pub fn from_json(integrity_token_json_payload: &str) -> eyre::Result<Self> {
        let parsed_json = serde_json::from_str::<Self>(integrity_token_json_payload);

        Ok(parsed_json?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsForHumanityOuterToken {
    pub exp: u64,
    pub request_hash: String,
    pub certificate: String,
}

impl ToolsForHumanityOuterToken {
    pub fn from_json(integrity_token_json_payload: &str) -> eyre::Result<Self> {
        let parsed_json = serde_json::from_str::<Self>(integrity_token_json_payload);

        Ok(parsed_json?)
    }
}
