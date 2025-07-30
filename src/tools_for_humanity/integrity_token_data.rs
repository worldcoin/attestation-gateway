use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsForHumanityInnerToken {
    pub exp: u64,
    pub principal: String,
    pub public_key: String,
}

impl ToolsForHumanityInnerToken {
    pub fn from_json(inner_token_payload: &str) -> eyre::Result<Self> {
        let parsed_json = serde_json::from_str::<Self>(inner_token_payload);

        if parsed_json.is_err() {
            // Parsing failures for integrity tokens is unexpected because tokens are igned,
            // hence not a client request. The unparsed payload is logged to help debug and fix.
            tracing::warn!(unparsed_inner_token_payload = ?inner_token_payload, "JSON parsing failed for Tools for Humanity Inner token.");
        }

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
    pub fn from_json(outer_token_payload: &str) -> eyre::Result<Self> {
        let parsed_json = serde_json::from_str::<Self>(outer_token_payload);

        if parsed_json.is_err() {
            // Parsing failures for integrity tokens is unexpected because tokens are igned,
            // hence not a client request. The unparsed payload is logged to help debug and fix.
            tracing::warn!(unparsed_outer_token_payload = ?outer_token_payload, "JSON parsing failed for Tools for Humanity Outer token.");
        }

        Ok(parsed_json?)
    }
}
