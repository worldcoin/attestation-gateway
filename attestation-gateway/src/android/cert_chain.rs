use openssl::x509::X509;
use serde::Serialize;
use thiserror::Error;

use crate::android::{
    intermediate_cert::{IntermediateCert, IntermediateCertError},
    revocation_list::RevocationList,
    root_cert::{RootCert, RootCertError},
    session_cert::{SessionCert, SessionCertError},
};

const NID_SERIAL_NUMBER: i32 = 105;

#[derive(Debug, Error)]
pub enum CertSerialError {
    #[error("serial number error")]
    SerialNumber,

    #[error("issued to decoding error")]
    IssuedToDecoding,
}

/// ASN.1 serial number in the two string forms used as keys in Google's attestation status JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertSerial {
    /// Certificate issued to contains serial number too
    pub issued_to: Vec<String>,
    /// Decimal digits (e.g. `"6681152659205225093"`).
    pub decimal: String,
    /// Lowercase hex without `0x`, zero-padded to whole bytes as OpenSSL emits it
    /// (e.g. `"c35747a084470c3135aeefe2b8d40cd6"`).
    pub hex: String,
}

impl CertSerial {
    pub fn from_x509(cert: &X509) -> Result<Self, CertSerialError> {
        let bn = cert
            .serial_number()
            .to_bn()
            .map_err(|_| CertSerialError::SerialNumber)?;

        let decimal = bn
            .to_dec_str()
            .map_err(|_| CertSerialError::SerialNumber)?
            .to_string();

        let hex = bn
            .to_hex_str()
            .map_err(|_| CertSerialError::SerialNumber)?
            .to_string()
            .to_lowercase();

        let issued_to = cert
            .subject_name()
            .entries()
            .filter(|e| e.object().nid().as_raw() == NID_SERIAL_NUMBER)
            .map(|e| e.data().to_string())
            .collect::<Result<Vec<String>, openssl::error::ErrorStack>>()
            .map_err(|_| CertSerialError::IssuedToDecoding)?;

        Ok(Self {
            issued_to,
            decimal,
            hex,
        })
    }

    /// [`Self::hex`] with leading zeros stripped.
    ///
    /// Google keys the attestation status list with Java `BigInteger.toString(16)`, which is
    /// minimal length, while OpenSSL's `BN_bn2hex` pads to whole bytes. Without stripping, a
    /// serial whose top nibble is zero is looked up as `09414602...` against a feed entry of
    /// `9414602...`, the lookup misses and a revoked certificate is accepted.
    fn hex_minimal(&self) -> &str {
        let stripped = self.hex.trim_start_matches('0');

        if stripped.is_empty() {
            &self.hex
        } else {
            stripped
        }
    }

    /// `true` if any representation appears in [`AndroidRevocationList`].
    #[must_use]
    pub fn is_revoked(&self, list: &RevocationList) -> bool {
        if list.is_revoked(&self.decimal) {
            return true;
        }

        if list.is_revoked(&self.hex) {
            return true;
        }

        if list.is_revoked(self.hex_minimal()) {
            return true;
        }

        for issued_to in self.issued_to.iter() {
            if list.is_revoked(issued_to) {
                return true;
            }
        }

        false
    }
}

impl CertSerialError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::SerialNumber => "serial_number".to_string(),
            Self::IssuedToDecoding => "issued_to_decoding".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum CertChainError {
    #[error("device certificate: {0}")]
    SessionCert(#[source] SessionCertError),

    #[error("intermediate certificate: {0}")]
    IntermediateCert(#[source] IntermediateCertError),

    #[error("root certificate: {0}")]
    RootCert(#[source] RootCertError),

    #[error("invalid chain length")]
    ChainLength,
}

#[derive(Serialize)]
pub struct CertChain {
    session_cert: SessionCert,
    device_cert: IntermediateCert,
    intermediate_certs: Vec<IntermediateCert>,
    root_cert: RootCert,
}

impl CertChain {
    pub fn from_x509(cert_chain: &[X509]) -> Result<Self, CertChainError> {
        if cert_chain.len() < 3 {
            return Err(CertChainError::ChainLength);
        }

        let (session_cert, tail_certs) = cert_chain.split_first().unwrap();
        let (device_cert, tail_certs) = tail_certs.split_first().unwrap();
        let (root_cert, intermediate_certs) = tail_certs.split_last().unwrap();

        let session_cert =
            SessionCert::from_x509(session_cert).map_err(CertChainError::SessionCert)?;

        let device_cert =
            IntermediateCert::from_x509(device_cert).map_err(CertChainError::IntermediateCert)?;

        let intermediate_certs = intermediate_certs
            .iter()
            .map(IntermediateCert::from_x509)
            .collect::<Result<Vec<IntermediateCert>, IntermediateCertError>>()
            .map_err(CertChainError::IntermediateCert)?;

        let root_cert = RootCert::new(root_cert).map_err(CertChainError::RootCert)?;

        Ok(Self {
            session_cert,
            device_cert,
            intermediate_certs,
            root_cert,
        })
    }

    #[must_use]
    pub fn any_serial_revoked(&self, list: &RevocationList) -> bool {
        self.session_cert().serial().is_revoked(list)
            || self.device_cert().serial().is_revoked(list)
            || self
                .intermediate_certs()
                .iter()
                .any(|c| c.serial().is_revoked(list))
            || self.root_cert().serial().is_revoked(list)
    }

    pub const fn session_cert(&self) -> &SessionCert {
        &self.session_cert
    }

    pub const fn device_cert(&self) -> &IntermediateCert {
        &self.device_cert
    }

    pub fn intermediate_certs(&self) -> &[IntermediateCert] {
        &self.intermediate_certs
    }

    pub const fn root_cert(&self) -> &RootCert {
        &self.root_cert
    }

    /// StrongBox factory and remotely provisioned chains identify StrongBox in the
    /// subject of the attestation certificate or the final intermediate certificate.
    #[must_use]
    pub fn has_strong_box_chain_shape(&self) -> bool {
        self.device_cert().subject_contains_strong_box()
            || self
                .intermediate_certs()
                .last()
                .is_some_and(IntermediateCert::subject_contains_strong_box)
    }
}

impl CertChainError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::SessionCert(e) => {
                format!("device_certificate_{}", e.reason_tag())
            }
            Self::IntermediateCert(e) => {
                format!("intermediate_certificate_{}", e.reason_tag())
            }
            Self::RootCert(e) => {
                format!("root_certificate_{}", e.reason_tag())
            }
            Self::ChainLength => "chain_length".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::SessionCert(e) => e.is_internal_error(),
            Self::IntermediateCert(e) => e.is_internal_error(),
            Self::RootCert(e) => e.is_internal_error(),
            Self::ChainLength => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Serial as OpenSSL renders it: lowercase hex, padded to whole bytes.
    fn serial(hex: &str) -> CertSerial {
        CertSerial {
            issued_to: Vec::new(),
            decimal: "1".to_string(),
            hex: hex.to_string(),
        }
    }

    fn feed(entry: &str) -> RevocationList {
        RevocationList::from_revoked_ids(HashSet::from([entry.to_string()]))
    }

    #[test]
    fn matches_feed_entry_with_leading_zero_stripped() {
        let cert_serial = serial("09414602a0ce3f77d9ac05af532785ef");

        assert!(cert_serial.is_revoked(&feed("9414602a0ce3f77d9ac05af532785ef")));
    }

    #[test]
    fn matches_feed_entry_that_is_already_byte_aligned() {
        let cert_serial = serial("c35747a084470c3135aeefe2b8d40cd6");

        assert!(cert_serial.is_revoked(&feed("c35747a084470c3135aeefe2b8d40cd6")));
    }

    #[test]
    fn matches_feed_entry_that_kept_the_padding() {
        let cert_serial = serial("09414602a0ce3f77d9ac05af532785ef");

        assert!(cert_serial.is_revoked(&feed("09414602a0ce3f77d9ac05af532785ef")));
    }

    #[test]
    fn does_not_match_an_unrelated_serial() {
        let cert_serial = serial("09414602a0ce3f77d9ac05af532785ef");

        assert!(!cert_serial.is_revoked(&feed("c35747a084470c3135aeefe2b8d40cd6")));
    }

    #[test]
    fn all_zero_serial_does_not_look_up_an_empty_key() {
        let cert_serial = serial("00");

        assert!(!cert_serial.is_revoked(&feed("")));
    }
}
