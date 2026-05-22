use openssl::x509::X509;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::android::cert_chain::{CertSerial, CertSerialError};

#[derive(Debug, Error)]
pub enum RootCertError {
    #[error("der encoding error")]
    DerEncoding,

    #[error("der decoding error")]
    DerDecoding,

    #[error("serial: {0}")]
    Serial(#[source] CertSerialError),
}

#[derive(Debug)]
pub struct RootCert {
    pub public_key: Vec<u8>,
    serial: CertSerial,
}

impl RootCert {
    pub fn new(cert: &X509) -> Result<Self, RootCertError> {
        let serial = CertSerial::from_x509(cert).map_err(RootCertError::Serial)?;
        let cert = cert.to_der().map_err(|_| RootCertError::DerEncoding)?;

        let (_, cert) = X509Certificate::from_der(&cert).map_err(|_| RootCertError::DerDecoding)?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());

        Ok(Self {
            public_key,
            serial,
        })
    }

    pub const fn serial(&self) -> &CertSerial {
        &self.serial
    }
}

impl RootCertError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DerEncoding => "der_encoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
            Self::Serial(e) => format!("serial_{}", e.reason_tag()),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DerEncoding | Self::DerDecoding => true,
            Self::Serial(_) => false,
        }
    }
}
