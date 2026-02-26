#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use p256::ecdsa::Signature;
use reqwest::header::{HeaderMap, HeaderValue};
use thiserror::Error;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVersion {
    V1 = 1,
}

impl IntegrityVersion {
    fn parse(s: &str) -> Result<Self, IntegrityError> {
        match s {
            "1" => Ok(Self::V1),
            other => Err(IntegrityError::InvalidVersion(
                other.to_owned(),
            )),
        }
    }
}

impl std::fmt::Display for IntegrityVersion {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),

    #[error("header contains non-visible ASCII: {0}")]
    InvalidHeaderEncoding(&'static str),

    #[error(
        "malformed integrity-signature header: \
         expected v=<timestamp>,t=<version>,s=<hex_signature>"
    )]
    MalformedSignatureHeader,

    #[error("unsupported integrity version: {0}")]
    InvalidVersion(String),

    #[error("timestamp is not a valid i64")]
    InvalidTimestamp,

    #[error("signature hex or DER encoding is invalid")]
    InvalidSignature,

    #[error("invalid token")]
    InvalidToken,

    #[error("unexpected error: {0}")]
    UnexpectedError(&'static str),
}

#[derive(Debug, Clone)]
pub struct IntegrityMeta {
    pub version: IntegrityVersion,
    pub token: String,
    pub signature: Signature,
    pub timestamp: i64,
}

impl IntegrityMeta {
    #[must_use]
    pub const fn new(
        token: String,
        signature: Signature,
        timestamp: i64,
    ) -> Self {
        Self {
            version: IntegrityVersion::V1,
            token,
            signature,
            timestamp,
        }
    }

    /// Parses `IntegrityMeta` from HTTP headers.
    ///
    /// Expects:
    /// - `integrity-token` — the JWT token string
    /// - `integrity-signature` —
    ///   `v=<timestamp>,t=<version>,s=<hex_der_sig>`
    ///
    /// # Errors
    /// Returns `IntegrityError` when a required header is missing
    /// or any field fails to parse.
    pub fn from_headers(
        headers: &HeaderMap,
    ) -> Result<Self, IntegrityError> {
        let token = headers
            .get("integrity-token")
            .ok_or(IntegrityError::MissingHeader(
                "integrity-token",
            ))?
            .to_str()
            .map_err(|_| {
                IntegrityError::InvalidHeaderEncoding(
                    "integrity-token",
                )
            })?
            .to_owned();

        let sig_header = headers
            .get("integrity-signature")
            .ok_or(IntegrityError::MissingHeader(
                "integrity-signature",
            ))?
            .to_str()
            .map_err(|_| {
                IntegrityError::InvalidHeaderEncoding(
                    "integrity-signature",
                )
            })?;

        let (version, timestamp, signature) =
            parse_signature_header(sig_header)?;

        Ok(Self {
            version,
            token,
            signature,
            timestamp,
        })
    }

    /// Converts the structure to a header map for transmission.
    ///
    /// # Errors
    /// Generally not expected as long as the JWT (`token`) is
    /// valid.
    pub fn to_header_map(
        &self,
    ) -> Result<HeaderMap, IntegrityError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "integrity-token",
            HeaderValue::from_str(&self.token)
                .map_err(|_| IntegrityError::InvalidToken)?,
        );
        let signature_value = format!(
            "v={},t={},s={}",
            self.timestamp,
            self.version,
            hex::encode(self.signature.to_der())
        );
        headers.insert(
            "integrity-signature",
            HeaderValue::from_str(&signature_value).map_err(
                |_| {
                    IntegrityError::UnexpectedError(
                        "signature value not a valid header value",
                    )
                },
            )?,
        );
        Ok(headers)
    }
}

/// Parses the `integrity-signature` header value.
///
/// Format: `v=<timestamp>,t=<version>,s=<hex_der_signature>`
fn parse_signature_header(
    header: &str,
) -> Result<(IntegrityVersion, i64, Signature), IntegrityError> {
    let mut version_raw = None;
    let mut timestamp_raw = None;
    let mut signature_raw = None;

    for part in header.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or(IntegrityError::MalformedSignatureHeader)?;

        match key {
            "v" => timestamp_raw = Some(value),
            "t" => version_raw = Some(value),
            "s" => signature_raw = Some(value),
            _ => {}
        }
    }

    let timestamp: i64 = timestamp_raw
        .ok_or(IntegrityError::MalformedSignatureHeader)?
        .parse()
        .map_err(|_| IntegrityError::InvalidTimestamp)?;

    let version = IntegrityVersion::parse(
        version_raw
            .ok_or(IntegrityError::MalformedSignatureHeader)?,
    )?;

    let sig_bytes = hex::decode(
        signature_raw
            .ok_or(IntegrityError::MalformedSignatureHeader)?,
    )
    .map_err(|_| IntegrityError::InvalidSignature)?;

    let signature = Signature::from_der(&sig_bytes)
        .map_err(|_| IntegrityError::InvalidSignature)?;

    Ok((version, timestamp, signature))
}
