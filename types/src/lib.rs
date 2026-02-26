#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use http::{HeaderMap, HeaderValue};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Version identifier for the integrity metadata
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVersion {
    V1 = 1,
}

impl IntegrityVersion {
    fn parse(s: &str) -> Result<Self, IntegrityError> {
        match s {
            "1" => Ok(Self::V1),
            other => Err(IntegrityError::InvalidVersion(other.to_owned())),
        }
    }
}

impl std::fmt::Display for IntegrityVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

/// Payload object containing all relevant metadata to assert the integrity of the
/// mobile client.
#[derive(Debug, Clone)]
pub struct IntegrityMeta {
    /// Version identifier of the [`IntegrityMeta`] format.
    pub version: IntegrityVersion,
    /// The JWT from the Attestation Gateway that serves as a certificate to authenticate the signing key.
    pub token: String,
    /// The signature for the specific request being asserted. Signed by the mobile device's secure element.
    pub signature: Signature,
    /// The timestamp of the signature.
    pub timestamp: i64,
}

impl IntegrityMeta {
    /// Computes the digest that should be signed by the mobile device's secure element, and subsequently verified.
    #[must_use]
    pub fn compute_signature_digest(timestamp: i64, request_payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&[0x1F]); // Delimiter byte to separate fields (unit separator)
        data.extend_from_slice(request_payload);

        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    #[must_use]
    pub const fn new(token: String, signature: Signature, timestamp: i64) -> Self {
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
    /// # Warning
    /// This function does not perform any cryptographic verification of the signature, it
    /// only parses the inputs and validates formats.
    ///
    /// # Errors
    /// Returns `IntegrityError` when a required header is missing
    /// or any field fails to parse.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, IntegrityError> {
        let token = headers
            .get("integrity-token")
            .ok_or(IntegrityError::MissingHeader("integrity-token"))?
            .to_str()
            .map_err(|_| IntegrityError::InvalidHeaderEncoding("integrity-token"))?
            .to_owned();

        let sig_header = headers
            .get("integrity-signature")
            .ok_or(IntegrityError::MissingHeader("integrity-signature"))?
            .to_str()
            .map_err(|_| IntegrityError::InvalidHeaderEncoding("integrity-signature"))?;

        let (version, timestamp, signature) = Self::parse_signature_header(sig_header)?;

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
    pub fn to_header_map(&self) -> Result<HeaderMap, IntegrityError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "integrity-token",
            HeaderValue::from_str(&self.token).map_err(|_| IntegrityError::InvalidToken)?,
        );
        let signature_value = format!(
            "v={},t={},s={}",
            self.timestamp,
            self.version,
            hex::encode(self.signature.to_der())
        );
        headers.insert(
            "integrity-signature",
            HeaderValue::from_str(&signature_value).map_err(|_| {
                IntegrityError::UnexpectedError("signature value not a valid header value")
            })?,
        );
        Ok(headers)
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
                "v" => timestamp_raw = Some(value.trim()),
                "t" => version_raw = Some(value.trim()),
                "s" => signature_raw = Some(value.trim()),
                _ => {}
            }
        }

        let timestamp: i64 = timestamp_raw
            .ok_or(IntegrityError::MalformedSignatureHeader)?
            .parse()
            .map_err(|_| IntegrityError::InvalidTimestamp)?;

        let version =
            IntegrityVersion::parse(version_raw.ok_or(IntegrityError::MalformedSignatureHeader)?)?;

        let sig_bytes = hex::decode(signature_raw.ok_or(IntegrityError::MalformedSignatureHeader)?)
            .map_err(|_| IntegrityError::InvalidSignature)?;

        let signature =
            Signature::from_der(&sig_bytes).map_err(|_| IntegrityError::InvalidSignature)?;

        Ok((version, timestamp, signature))
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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn test_signature() -> Signature {
        let key = SigningKey::from_slice(&[0x42; 32]).expect("valid key");
        key.sign(b"test payload")
    }

    fn test_meta() -> IntegrityMeta {
        IntegrityMeta::new(
            "eyJhbGciOiJFUzI1NiJ9.test".into(),
            test_signature(),
            1_700_000_000,
        )
    }

    fn valid_headers() -> HeaderMap {
        test_meta().to_header_map().expect("valid headers")
    }

    #[test]
    fn roundtrip_to_from_headers() {
        let original = test_meta();
        let headers = original.to_header_map().expect("serialize");
        let parsed = IntegrityMeta::from_headers(&headers).expect("parse");

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.token, original.token);
        assert_eq!(parsed.signature, original.signature);
        assert_eq!(parsed.timestamp, original.timestamp);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let meta = test_meta();
        let sig_value = format!(
            "v={},t={},s={},x=unknown",
            meta.timestamp,
            meta.version,
            hex::encode(meta.signature.to_der())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "integrity-token",
            HeaderValue::from_str(&meta.token).expect("valid"),
        );
        headers.insert(
            "integrity-signature",
            HeaderValue::from_str(&sig_value).expect("valid"),
        );

        let parsed = IntegrityMeta::from_headers(&headers).expect("parse");
        assert_eq!(parsed.signature, meta.signature);
    }

    #[test]
    fn version_v1_display() {
        assert_eq!(IntegrityVersion::V1.to_string(), "1");
    }

    #[test]
    fn missing_token_header() {
        let mut headers = valid_headers();
        headers.remove("integrity-token");

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MissingHeader(name) = err else {
            panic!("expected MissingHeader, got {err:?}");
        };
        assert_eq!(name, "integrity-token");
    }

    #[test]
    fn missing_signature_header() {
        let mut headers = valid_headers();
        headers.remove("integrity-signature");

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MissingHeader(name) = err else {
            panic!("expected MissingHeader, got {err:?}");
        };
        assert_eq!(name, "integrity-signature");
    }

    #[test]
    fn empty_headers() {
        let err = IntegrityMeta::from_headers(&HeaderMap::new()).unwrap_err();
        let IntegrityError::MissingHeader(_) = err else {
            panic!("expected MissingHeader, got {err:?}");
        };
    }

    #[test]
    fn signature_header_no_equals() {
        let mut headers = valid_headers();
        headers.insert("integrity-signature", HeaderValue::from_static("garbage"));

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MalformedSignatureHeader = err else {
            panic!("expected MalformedSignatureHeader, got {err:?}");
        };
    }

    #[test]
    fn signature_header_missing_v_field() {
        let mut headers = valid_headers();
        headers.insert("integrity-signature", HeaderValue::from_static("t=1,s=00"));

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MalformedSignatureHeader = err else {
            panic!("expected MalformedSignatureHeader, got {err:?}");
        };
    }

    #[test]
    fn signature_header_missing_t_field() {
        let mut headers = valid_headers();
        headers.insert(
            "integrity-signature",
            HeaderValue::from_static("v=100,s=00"),
        );

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MalformedSignatureHeader = err else {
            panic!("expected MalformedSignatureHeader, got {err:?}");
        };
    }

    #[test]
    fn signature_header_missing_s_field() {
        let mut headers = valid_headers();
        headers.insert("integrity-signature", HeaderValue::from_static("v=100,t=1"));

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::MalformedSignatureHeader = err else {
            panic!("expected MalformedSignatureHeader, got {err:?}");
        };
    }

    #[test]
    fn invalid_timestamp_not_numeric() {
        let mut headers = valid_headers();
        headers.insert(
            "integrity-signature",
            HeaderValue::from_static("v=abc,t=1,s=00"),
        );

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::InvalidTimestamp = err else {
            panic!("expected InvalidTimestamp, got {err:?}");
        };
    }

    #[test]
    fn invalid_version() {
        let mut headers = valid_headers();
        headers.insert(
            "integrity-signature",
            HeaderValue::from_static("v=100,t=99,s=00"),
        );

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::InvalidVersion(v) = err else {
            panic!("expected InvalidVersion, got {err:?}");
        };
        assert_eq!(v, "99");
    }

    #[test]
    fn invalid_signature_bad_hex() {
        let mut headers = valid_headers();
        headers.insert(
            "integrity-signature",
            HeaderValue::from_static("v=100,t=1,s=zzzz"),
        );

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::InvalidSignature = err else {
            panic!("expected InvalidSignature, got {err:?}");
        };
    }

    #[test]
    fn invalid_signature_bad_der() {
        let mut headers = valid_headers();
        // Valid hex, but not a valid DER-encoded ECDSA signature
        headers.insert(
            "integrity-signature",
            HeaderValue::from_static("v=100,t=1,s=deadbeef"),
        );

        let err = IntegrityMeta::from_headers(&headers).unwrap_err();
        let IntegrityError::InvalidSignature = err else {
            panic!("expected InvalidSignature, got {err:?}");
        };
    }
}
