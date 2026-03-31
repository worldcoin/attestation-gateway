use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};

use thiserror::Error;

use crate::android::{
    android_revocation_list::AndroidRevocationList,
    device_certificate::{DeviceCertificate, DeviceCertificateError},
    root_certificate::{RootCertificate, RootCertificateError},
};

#[derive(Debug, Error)]
pub enum AndroidCertChainError {
    #[error("invalid base64 encoding")]
    InvalidBase64Encoding(#[source] DecodeError),
    #[error("invalid DER encoding")]
    InvalidDerEncoding(#[source] openssl::error::ErrorStack),
    #[error("certificate chain must contain at least two certificates")]
    InvalidChainLength,
    #[error("invalid certificate")]
    InvalidCert(#[source] openssl::error::ErrorStack),
    #[error("certificate chain verification failed: {0}")]
    InvalidChain(openssl::x509::X509VerifyResult),
    #[error("device certificate")]
    DeviceCertificate(#[source] DeviceCertificateError),
    #[error("root certificate")]
    RootCertificate(#[source] RootCertificateError),
    #[error("internal stack builder")]
    InternalStackBuilder(#[source] openssl::error::ErrorStack),
    #[error("internal verify param builder")]
    InternalParamBuilder(#[source] openssl::error::ErrorStack),
    #[error("internal store builder")]
    InternalStoreBuilder(#[source] openssl::error::ErrorStack),
    #[error("internal store context builder")]
    InternalContextBuilder(#[source] openssl::error::ErrorStack),
    #[error("internal chain verification")]
    InternalChainVerification(#[source] openssl::error::ErrorStack),
}

/// ASN.1 serial number in the two string forms used as keys in Google's attestation status JSON.
#[derive(Debug, Clone)]
pub struct CertificateSerial {
    /// Decimal digits (e.g. `"6681152659205225093"`).
    pub decimal: String,
    /// Lowercase hex without `0x` (e.g. `"c35747a084470c3135aeefe2b8d40cd6"`).
    pub hex: String,
}

impl CertificateSerial {
    /// `true` if either representation appears in [`AndroidRevocationList`].
    #[must_use]
    pub fn is_revoked(&self, list: &AndroidRevocationList) -> bool {
        list.is_revoked(&self.decimal) || list.is_revoked(&self.hex)
    }
}

pub struct AndroidCertChain {
    device_certificate: DeviceCertificate,
    root_certificate: RootCertificate,
    /// Per-certificate serials (leaf → root) for Android attestation status lookup.
    serials: Vec<CertificateSerial>,
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

        let serials = cert_chain
            .iter()
            .map(|c| certificate_serial(c))
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
    pub fn serials(&self) -> &[CertificateSerial] {
        &self.serials
    }

    pub fn device_certificate(&self) -> &DeviceCertificate {
        &self.device_certificate
    }

    pub fn root_certificate(&self) -> &RootCertificate {
        &self.root_certificate
    }
}

fn certificate_serial(cert: &X509) -> Result<CertificateSerial, AndroidCertChainError> {
    let bn = cert
        .serial_number()
        .to_bn()
        .map_err(|e| AndroidCertChainError::InvalidCert(e))?;

    let decimal = bn
        .to_dec_str()
        .map_err(|e| AndroidCertChainError::InvalidCert(e))?
        .to_string();

    let hex = bn
        .to_hex_str()
        .map_err(|e| AndroidCertChainError::InvalidCert(e))?
        .to_string()
        .to_lowercase();

    Ok(CertificateSerial { decimal, hex })
}
