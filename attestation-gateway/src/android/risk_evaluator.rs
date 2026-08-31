use std::{collections::HashMap, time::SystemTime};

use crate::{android::cert_chain::CertChain, nonces::TokenDetails, utils::BundleIdentifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidRiskDecision {
    Allow,
    Reject,
}

pub struct AndroidAttestationInput<'a> {
    pub raw_cert_chain: &'a [String],
    pub nonce: &'a str,
    pub requested_exp: Option<i64>,
    pub app_version: &'a str,
    pub bundle_identifier: &'a BundleIdentifier,
    pub device_model: Option<&'a str>,
    pub request_headers: &'a HashMap<String, String>,
    pub token_details: &'a TokenDetails,
}

pub struct AndroidRiskContext<'a> {
    pub raw_cert_chain: &'a [String],
    pub parsed_cert_chain: &'a CertChain,
    pub nonce: &'a str,
    pub requested_exp: Option<i64>,
    pub app_version: &'a str,
    pub bundle_identifier: &'a BundleIdentifier,
    pub device_model: Option<&'a str>,
    pub request_headers: &'a HashMap<String, String>,
    pub token_details: &'a TokenDetails,
    pub evaluated_at: SystemTime,
}

pub trait AndroidRiskEvaluator: Send + Sync {
    #[must_use]
    fn evaluate(&self, context: &AndroidRiskContext<'_>) -> AndroidRiskDecision;
}

#[derive(Debug, Default)]
pub struct AllowAllAndroidRiskEvaluator;

impl AndroidRiskEvaluator for AllowAllAndroidRiskEvaluator {
    fn evaluate(&self, _context: &AndroidRiskContext<'_>) -> AndroidRiskDecision {
        AndroidRiskDecision::Allow
    }
}
