use crate::android::{
    android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
    android_cert_chain::{AndroidCertChain, AndroidCertChainError},
};

#[derive(Debug)]

pub enum AndroidAttestationError {
    CaRegistryParsing(AndroidCaRegistryError),
    CertChainParsing(AndroidCertChainError),
    InvalidCaRoot,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct AndroidAttestation {
    ca_registry: AndroidCaRegistry,
}

impl AndroidAttestation {
    pub fn new(ca_registry: AndroidCaRegistry) -> Self {
        Self { ca_registry }
    }

    pub fn from_default_pem() -> Result<Self, AndroidAttestationError> {
        let ca_registry = AndroidCaRegistry::from_default_pem()
            .map_err(|e| AndroidAttestationError::CaRegistryParsing(e))?;

        Ok(Self::new(ca_registry))
    }

    pub fn verify(
        self,
        base64_cert_chain: Vec<String>,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain)
            .map_err(|e| AndroidAttestationError::CertChainParsing(e))?;

        if !self
            .ca_registry
            .has_public_key(cert_chain.root_ca_public_key)
        {
            return Err(AndroidAttestationError::InvalidCaRoot);
        }

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.device_public_key,
        })
    }
}
