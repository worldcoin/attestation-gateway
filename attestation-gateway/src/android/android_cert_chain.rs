use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};

use crate::android::{
    device_certificate::{DeviceCertificate, DeviceCertificateError},
    root_certificate::{RootCertificate, RootCertificateError},
};

#[derive(Debug)]
pub enum AndroidCertChainError {
    InvalidBase64Encoding(DecodeError),
    InvalidDerEncoding(openssl::error::ErrorStack),
    InvalidChainLength,
    InvalidCert(openssl::error::ErrorStack),
    InvalidChain(openssl::x509::X509VerifyResult),
    DeviceCertificate(DeviceCertificateError),
    RootCertificate(RootCertificateError),
    InternalStackBuilder(openssl::error::ErrorStack),
    InternalParamBuilder(openssl::error::ErrorStack),
    InternalStoreBuilder(openssl::error::ErrorStack),
    InternalContextBuilder(openssl::error::ErrorStack),
    InternalChainVerification(openssl::error::ErrorStack),
}

pub struct AndroidCertChain {
    device_certificate: DeviceCertificate,
    root_certificate: RootCertificate,
}

impl AndroidCertChain {
    pub fn from_base64(
        base64_cert_chain: Vec<String>,
    ) -> eyre::Result<Self, AndroidCertChainError> {
        let der_cert_chain = base64_cert_chain
            .iter()
            .map(|c| Base64.decode(c))
            .collect::<Result<Vec<Vec<u8>>, DecodeError>>()
            .map_err(|e| AndroidCertChainError::InvalidBase64Encoding(e))?;

        return Self::from_der(der_cert_chain);
    }

    pub fn from_der(der_cert_chain: Vec<Vec<u8>>) -> eyre::Result<Self, AndroidCertChainError> {
        let cert_chain = der_cert_chain
            .iter()
            .map(|c| X509::from_der(c))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|e| AndroidCertChainError::InvalidDerEncoding(e))?;

        return Self::from_x509(cert_chain);
    }

    pub fn from_x509(cert_chain: Vec<X509>) -> eyre::Result<Self, AndroidCertChainError> {
        if cert_chain.len() < 2 {
            return Err(AndroidCertChainError::InvalidChainLength);
        }

        let device_cert = cert_chain.first().unwrap();
        let root_ca_cert = cert_chain.last().unwrap();

        let mut cert_stack =
            Stack::new().map_err(|e| AndroidCertChainError::InternalStackBuilder(e))?;
        for cert in cert_chain.iter().rev().skip(1) {
            cert_stack
                .push(cert.to_owned())
                .map_err(|e| AndroidCertChainError::InvalidCert(e))?;
        }

        let mut store_param =
            X509VerifyParam::new().map_err(|e| AndroidCertChainError::InternalParamBuilder(e))?;

        // Account for clock drift
        store_param.set_time(
            60 + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );

        let mut store_builder =
            X509StoreBuilder::new().map_err(|e| AndroidCertChainError::InternalStoreBuilder(e))?;

        store_builder
            .set_param(&store_param)
            .map_err(|e| AndroidCertChainError::InternalStoreBuilder(e))?;

        store_builder
            .add_cert(root_ca_cert.to_owned())
            .map_err(|e| AndroidCertChainError::InvalidCert(e))?;

        let store = store_builder.build();

        let mut context = X509StoreContext::new()
            .map_err(|e| AndroidCertChainError::InternalContextBuilder(e))?;

        let valid = context
            .init(
                &store,
                device_cert,
                &cert_stack,
                openssl::x509::X509StoreContextRef::verify_cert,
            )
            .map_err(|e| AndroidCertChainError::InternalChainVerification(e))?;

        if !valid {
            return Err(AndroidCertChainError::InvalidChain(context.error()));
        }

        let device_certificate = DeviceCertificate::from_x509(device_cert.to_owned())
            .map_err(|e| AndroidCertChainError::DeviceCertificate(e))?;

        let root_certificate = RootCertificate::new(root_ca_cert.to_owned())
            .map_err(|e| AndroidCertChainError::RootCertificate(e))?;

        Ok(Self {
            device_certificate,
            root_certificate,
        })
    }

    pub fn root_ca_public_key(&self) -> Vec<u8> {
        self.root_certificate.public_key.clone()
    }

    pub fn device_public_key(&self) -> Vec<u8> {
        self.device_certificate.public_key()
    }

    pub fn attestation_challenge(&self) -> String {
        self.device_certificate.attestation_challenge()
    }

    pub fn device_attestation_security_level(&self) -> u32 {
        self.device_certificate.attestation_security_level()
    }

    pub fn device_key_mint_security_level(&self) -> u32 {
        self.device_certificate.key_mint_security_level()
    }

    pub fn device_locked(&self) -> Option<bool> {
        self.device_certificate.device_locked()
    }

    pub fn device_verified_boot_state(&self) -> Option<u32> {
        self.device_certificate.verified_boot_state()
    }

    pub fn device_key_origin(&self) -> Option<u64> {
        self.device_certificate.key_origin()
    }

    pub fn device_attestation_signature_digests(&self) -> Option<&[Vec<u8>]> {
        self.device_certificate.attestation_signature_digests()
    }

    pub fn device_package_name(&self) -> Option<&str> {
        self.device_certificate.package_name()
    }

    pub fn device_os_patch_level(&self) -> Option<u64> {
        self.device_certificate.os_patch_level()
    }
}
