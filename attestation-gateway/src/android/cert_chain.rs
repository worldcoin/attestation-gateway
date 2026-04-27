use openssl::x509::X509;

use thiserror::Error;

use crate::android::{
    device_certificate::{DeviceCertificate, DeviceCertificateError},
    revocation_list::RevocationList,
    root_certificate::{RootCertificate, RootCertificateError},
};

const NID_SERIAL_NUMBER: i32 = 105;

#[derive(Debug, Error)]
pub enum CertChainError {
    #[error("device certificate: {0}")]
    DeviceCertificate(#[source] DeviceCertificateError),

    #[error("root certificate: {0}")]
    RootCertificate(#[source] RootCertificateError),

    #[error("invalid chain length")]
    ChainLength,

    #[error("issued to decoding error")]
    IssuedToDecoding,

    #[error("serial number error")]
    SerialNumber,
}

/// ASN.1 serial number in the two string forms used as keys in Google's attestation status JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSerial {
    /// Certificate issued to contains serial number too
    pub issued_to: Vec<String>,
    /// Decimal digits (e.g. `"6681152659205225093"`).
    pub decimal: String,
    /// Lowercase hex without `0x` (e.g. `"c35747a084470c3135aeefe2b8d40cd6"`).
    pub hex: String,
}

impl CertSerial {
    /// `true` if either representation appears in [`AndroidRevocationList`].
    #[must_use]
    pub fn is_revoked(&self, list: &RevocationList) -> bool {
        if list.is_revoked(&self.decimal) {
            return true;
        }

        if list.is_revoked(&self.hex) {
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

pub struct CertChain {
    device_certificate: DeviceCertificate,
    root_certificate: RootCertificate,
    serials: Vec<CertSerial>,
}

impl CertChain {
    pub fn from_x509(cert_chain: &[X509]) -> Result<Self, CertChainError> {
        if cert_chain.len() < 3 {
            return Err(CertChainError::ChainLength);
        }

        let leaf_cert = cert_chain.first().unwrap();
        let root_ca_cert = cert_chain.last().unwrap();

        let device_certificate =
            DeviceCertificate::from_x509(leaf_cert).map_err(CertChainError::DeviceCertificate)?;

        let root_certificate =
            RootCertificate::new(root_ca_cert).map_err(CertChainError::RootCertificate)?;

        let serials = cert_chain
            .iter()
            .map(certificate_serial)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            device_certificate,
            root_certificate,
            serials,
        })
    }

    /// Serial numbers for each certificate in the validated chain, **leaf first, root last** (same
    /// order as the client-sent chain). Use [`CertificateSerial::is_revoked`] against
    /// [`AndroidRevocationList`] (Google's feed keys are decimal or lowercase hex).
    pub fn serials(&self) -> &[CertSerial] {
        &self.serials
    }

    pub const fn device_certificate(&self) -> &DeviceCertificate {
        &self.device_certificate
    }

    pub const fn root_certificate(&self) -> &RootCertificate {
        &self.root_certificate
    }
}

fn certificate_serial(cert: &X509) -> Result<CertSerial, CertChainError> {
    let bn = cert
        .serial_number()
        .to_bn()
        .map_err(|_| CertChainError::SerialNumber)?;

    let decimal = bn
        .to_dec_str()
        .map_err(|_| CertChainError::SerialNumber)?
        .to_string();

    let hex = bn
        .to_hex_str()
        .map_err(|_| CertChainError::SerialNumber)?
        .to_string()
        .to_lowercase();

    let issued_to = cert
        .subject_name()
        .entries()
        .filter(|e| e.object().nid().as_raw() == NID_SERIAL_NUMBER)
        .map(|e| e.data().as_utf8().map(|v| String::from(&**v)))
        .collect::<Result<Vec<String>, openssl::error::ErrorStack>>()
        .map_err(|_| CertChainError::IssuedToDecoding)?;

    Ok(CertSerial {
        issued_to,
        decimal,
        hex,
    })
}

impl CertChainError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DeviceCertificate(e) => {
                format!("device_certificate_{}", e.reason_tag())
            }
            Self::RootCertificate(e) => {
                format!("root_certificate_{}", e.reason_tag())
            }
            Self::ChainLength => "chain_length".to_string(),
            Self::IssuedToDecoding => "issued_to_decoding".to_string(),
            Self::SerialNumber => "serial_number".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DeviceCertificate(e) => e.is_internal_error(),
            Self::RootCertificate(e) => e.is_internal_error(),
            Self::ChainLength | Self::IssuedToDecoding | Self::SerialNumber => false,
        }
    }
}
