use der_parser::oid;
use openssl::x509::X509;
use serde::Serialize;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::android::cert_chain::{CertSerial, CertSerialError};

#[derive(Debug, Error)]
pub enum IntermediateCertError {
    #[error("der encoding error")]
    DerEncoding,

    #[error("der decoding error")]
    DerDecoding,

    #[error("attestation present")]
    AttestationPresent,

    #[error("serial: {0}")]
    Serial(#[source] CertSerialError),
}

#[derive(Serialize)]
pub struct IntermediateCert {
    #[serde(with = "crate::android::serde_hex")]
    public_key: Vec<u8>,
    serial: CertSerial,
    #[serde(skip)]
    subject_contains_strong_box: bool,
}

impl IntermediateCert {
    pub fn from_x509(cert: &X509) -> Result<Self, IntermediateCertError> {
        let serial = CertSerial::from_x509(cert).map_err(IntermediateCertError::Serial)?;
        let subject_contains_strong_box = cert.subject_name().entries().any(|entry| {
            entry
                .data()
                .to_string()
                .is_ok_and(|value| value.to_ascii_lowercase().contains("strongbox"))
        });
        let der = cert
            .to_der()
            .map_err(|_| IntermediateCertError::DerEncoding)?;

        Self::from_der_with_serial(&der, serial, subject_contains_strong_box)
    }

    fn from_der_with_serial(
        der: &[u8],
        serial: CertSerial,
        subject_contains_strong_box: bool,
    ) -> Result<Self, IntermediateCertError> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|_| IntermediateCertError::DerDecoding)?;

        let key_description = cert
            .get_extension_unique(&oid!(1.3.6.1.4.1.11129.2.1.17))
            .map_err(|_| IntermediateCertError::AttestationPresent)?;

        if key_description.is_some() {
            return Err(IntermediateCertError::AttestationPresent);
        }

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());

        Ok(Self {
            public_key,
            serial,
            subject_contains_strong_box,
        })
    }

    pub const fn serial(&self) -> &CertSerial {
        &self.serial
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    pub const fn subject_contains_strong_box(&self) -> bool {
        self.subject_contains_strong_box
    }
}

impl IntermediateCertError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DerEncoding => "der_encoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
            Self::AttestationPresent => "attestation_present".to_string(),
            Self::Serial(e) => format!("serial_{}", e.reason_tag()),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DerEncoding | Self::DerDecoding => true,
            Self::AttestationPresent | Self::Serial(_) => false,
        }
    }
}
