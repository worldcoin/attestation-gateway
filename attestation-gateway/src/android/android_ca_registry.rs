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
    rkp_public_keys: Vec<Vec<u8>>,
}

impl AndroidCaRegistry {
    pub fn from_default_pem() -> Result<Self, AndroidCaRegistryError> {
        // ca1: Legacy RSA root (factory-provisioned keyboxes, vulnerable to leaks)
        let legacy_pems = vec![
            include_bytes!("attestation_root_ca1.pem").to_vec(),
        ];

        // ca2: Google "Key Attestation CA1" P-384 root (RKP-provisioned, April 2026+)
        // Devices that went through Remote Key Provisioning chain to this root.
        // Keybox bypass is impossible for chains rooted here because there is no
        // factory-provisioned batch key -- keys are provisioned per-device via RKP.
        let mut rkp_pems = vec![
            include_bytes!("attestation_root_ca2.pem").to_vec(),
        ];

        if let Ok(extra) = std::fs::read("attestation_root_rkp_extra.pem") {
            rkp_pems.push(extra);
        }

        Self::from_pem_with_rkp(&legacy_pems, &rkp_pems)
    }

    fn from_pem_with_rkp(
        legacy_pems: &[Vec<u8>],
        rkp_pems: &[Vec<u8>],
    ) -> Result<Self, AndroidCaRegistryError> {
        let all_pems: Vec<Vec<u8>> = legacy_pems.iter().chain(rkp_pems.iter()).cloned().collect();
        let all_certs = all_pems
            .iter()
            .map(|pem| X509::from_pem(pem))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCaRegistryError::PemParsing)?;

        let all_der = all_certs
            .iter()
            .map(|cert| cert.to_der())
            .collect::<Result<Vec<Vec<u8>>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCaRegistryError::DerEncoding)?;

        let all_public_keys = all_der
            .iter()
            .map(|der| {
                let (_, cert) = X509Certificate::from_der(der)?;
                Ok(Vec::from(cert.public_key().subject_public_key.data.clone()))
            })
            .collect::<Result<Vec<Vec<u8>>, X509Error>>()
            .map_err(|_| AndroidCaRegistryError::DerParsing)?;

        let rkp_count = rkp_pems.len();
        let legacy_count = legacy_pems.len();
        let rkp_public_keys = all_public_keys[legacy_count..legacy_count + rkp_count].to_vec();

        Ok(Self {
            public_keys: all_public_keys,
            rkp_public_keys,
        })
    }

    pub fn from_pem(pem_certs: &[Vec<u8>]) -> Result<Self, AndroidCaRegistryError> {
        Self::from_pem_with_rkp(pem_certs, &[])
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
            rkp_public_keys: vec![],
        })
    }

    #[must_use]
    pub fn has_public_key(&self, public_key: &[u8]) -> bool {
        self.public_keys
            .iter()
            .any(|key| key.as_slice() == public_key)
    }

    /// Returns `true` when the root public key belongs to the 2026 RKP provisioning root,
    /// meaning the device went through Remote Key Provisioning and the key cannot have
    /// been produced from a leaked legacy keybox.
    #[must_use]
    pub fn is_rkp_root(&self, public_key: &[u8]) -> bool {
        self.rkp_public_keys
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
