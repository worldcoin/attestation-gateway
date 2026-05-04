use der_parser::oid;
use openssl::x509::X509;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Error)]
pub enum IntermediateCertError {
    #[error("der encoding error")]
    DerEncoding,

    #[error("der decoding error")]
    DerDecoding,

    #[error("attestation present")]
    AttestationPresent,
}

pub struct IntermediateCert {
    public_key: Vec<u8>,
}

impl IntermediateCert {
    pub fn from_x509(cert: &X509) -> Result<Self, IntermediateCertError> {
        let der = cert
            .to_der()
            .map_err(|_| IntermediateCertError::DerEncoding)?;

        Self::from_der(&der)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, IntermediateCertError> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|_| IntermediateCertError::DerDecoding)?;

        let key_description = cert
            .get_extension_unique(&oid!(1.3.6.1.4.1.11129.2.1.17))
            .map_err(|_| IntermediateCertError::AttestationPresent)?;

        if key_description.is_some() {
            return Err(IntermediateCertError::AttestationPresent);
        }

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());

        Ok(Self { public_key })
    }
}

impl IntermediateCertError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DerEncoding => "der_encoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
            Self::AttestationPresent => "attestation_present".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DerEncoding | Self::DerDecoding => true,
            Self::AttestationPresent => false,
        }
    }
}
