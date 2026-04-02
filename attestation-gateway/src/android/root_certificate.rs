use openssl::x509::X509;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Error)]
pub enum RootCertificateError {
    #[error("der encoding error")]
    DerEncoding,

    #[error("der decoding error")]
    DerDecoding,
}

#[derive(Debug)]
pub struct RootCertificate {
    pub public_key: Vec<u8>,
}

impl RootCertificate {
    pub fn new(cert: &X509) -> Result<Self, RootCertificateError> {
        let cert = cert
            .to_der()
            .map_err(|_| RootCertificateError::DerEncoding)?;

        let (_, cert) =
            X509Certificate::from_der(&cert).map_err(|_| RootCertificateError::DerDecoding)?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());

        Ok(Self { public_key })
    }
}

impl RootCertificateError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DerEncoding => "der_encoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DerEncoding | Self::DerDecoding => true,
        }
    }
}
