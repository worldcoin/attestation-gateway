use openssl::x509::X509;
use thiserror::Error;
use x509_parser::{
    error::X509Error,
    prelude::{FromDer, X509Certificate},
};

#[derive(Debug, Error)]
pub enum AndroidCaRegistryError {
    #[error("pem parsing error")]
    PemParsing,

    #[error("der parsing error")]
    DerParsing,

    #[error("der encoding error")]
    DerEncoding,
}

#[derive(Debug, Clone)]
pub struct AndroidCaRegistry {
    public_keys: Vec<Vec<u8>>,
}

impl AndroidCaRegistry {
    pub fn from_default_pem() -> Result<Self, AndroidCaRegistryError> {
        Self::from_pem(&[
            include_bytes!("attestation_root_ca1.pem").to_vec(),
            include_bytes!("attestation_root_ca2.pem").to_vec(),
        ])
    }

    pub fn from_pem(pem_certs: &[Vec<u8>]) -> Result<Self, AndroidCaRegistryError> {
        let ca_certs = pem_certs
            .iter()
            .map(|pem| X509::from_pem(pem))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCaRegistryError::PemParsing)?;

        Self::from_x509(&ca_certs)
    }

    pub fn from_x509(x509_certs: &[X509]) -> Result<Self, AndroidCaRegistryError> {
        let der_ca_certs = x509_certs
            .iter()
            .map(|cert| cert.to_der())
            .collect::<Result<Vec<Vec<u8>>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCaRegistryError::DerEncoding)?;

        Self::from_der(&der_ca_certs)
    }

    pub fn from_der(der_certs: &[Vec<u8>]) -> Result<Self, AndroidCaRegistryError> {
        let ca_public_keys = der_certs
            .iter()
            .map(|der| {
                let (_, cert) = X509Certificate::from_der(der)?;
                Ok(Vec::from(cert.public_key().subject_public_key.data.clone()))
            })
            .collect::<Result<Vec<Vec<u8>>, X509Error>>()
            .map_err(|_| AndroidCaRegistryError::DerParsing)?;

        Ok(Self {
            public_keys: ca_public_keys,
        })
    }

    #[must_use]
    pub fn has_public_key(&self, public_key: &[u8]) -> bool {
        self.public_keys
            .iter()
            .any(|key| key.as_slice() == public_key)
    }
}

impl AndroidCaRegistryError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::PemParsing => "pem_parsing".to_string(),
            Self::DerParsing => "der_parsing".to_string(),
            Self::DerEncoding => "der_encoding".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::PemParsing | Self::DerParsing | Self::DerEncoding => true,
        }
    }
}
