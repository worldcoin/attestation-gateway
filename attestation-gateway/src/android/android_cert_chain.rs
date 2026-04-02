use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{
        X509, X509StoreContext, X509VerifyResult, store::X509StoreBuilder, verify::X509VerifyParam,
    },
};

use thiserror::Error;

use crate::android::{
    android_revocation_list::AndroidRevocationList,
    device_certificate::{DeviceCertificate, DeviceCertificateError},
    root_certificate::{RootCertificate, RootCertificateError},
};

#[derive(Debug, Error)]
pub enum AndroidCertChainError {
    #[error("device certificate: {0}")]
    DeviceCertificate(#[source] DeviceCertificateError),

    #[error("root certificate: {0}")]
    RootCertificate(#[source] RootCertificateError),

    #[error("invalid base64 encoding: {0}")]
    Base64Encoding(#[source] DecodeError),

    #[error("invalid der encoding")]
    DerEncoding,

    #[error("invalid chain length")]
    ChainLength,

    #[error("invalid chain: {0}")]
    ChainVerification(#[source] X509VerifyResult),

    #[error("stack builder error")]
    StackBuilder,

    #[error("stack push error")]
    StackPush,

    #[error("param builder error")]
    ParamBuilder,

    #[error("store builder error")]
    StoreBuilder,

    #[error("store add error")]
    StoreAdd,

    #[error("context builder error")]
    ContextBuilder,

    #[error("context verify error")]
    ContextVerify,
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
    pub fn from_base64(base64_cert_chain: &Vec<String>) -> Result<Self, AndroidCertChainError> {
        let der_cert_chain = base64_cert_chain
            .iter()
            .map(|c| Base64.decode(c))
            .collect::<Result<Vec<Vec<u8>>, DecodeError>>()
            .map_err(AndroidCertChainError::Base64Encoding)?;

        Self::from_der(&der_cert_chain)
    }

    pub fn from_der(der_cert_chain: &Vec<Vec<u8>>) -> Result<Self, AndroidCertChainError> {
        let cert_chain = der_cert_chain
            .iter()
            .map(|c| X509::from_der(c))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCertChainError::DerEncoding)?;

        Self::from_x509(&cert_chain)
    }

    pub fn from_x509(cert_chain: &Vec<X509>) -> Result<Self, AndroidCertChainError> {
        if cert_chain.len() < 2 {
            return Err(AndroidCertChainError::ChainLength);
        }

        let device_cert = cert_chain.first().unwrap();
        let root_ca_cert = cert_chain.last().unwrap();

        let mut cert_stack = Stack::new().map_err(|_| AndroidCertChainError::StackBuilder)?;
        for cert in cert_chain.iter().rev().skip(1) {
            cert_stack
                .push(cert.to_owned())
                .map_err(|_| AndroidCertChainError::StackPush)?;
        }

        let mut store_param =
            X509VerifyParam::new().map_err(|_| AndroidCertChainError::ParamBuilder)?;

        // Account for clock drift
        store_param.set_time(
            60 + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .cast_signed(),
        );

        let mut store_builder =
            X509StoreBuilder::new().map_err(|_| AndroidCertChainError::StoreBuilder)?;

        store_builder
            .set_param(&store_param)
            .map_err(|_| AndroidCertChainError::StoreBuilder)?;

        store_builder
            .add_cert(root_ca_cert.to_owned())
            .map_err(|_| AndroidCertChainError::StoreAdd)?;

        let store = store_builder.build();

        let mut context =
            X509StoreContext::new().map_err(|_| AndroidCertChainError::ContextBuilder)?;

        let valid = context
            .init(
                &store,
                device_cert,
                &cert_stack,
                openssl::x509::X509StoreContextRef::verify_cert,
            )
            .map_err(|_| AndroidCertChainError::ContextVerify)?;

        if !valid {
            return Err(AndroidCertChainError::ChainVerification(context.error()));
        }

        let device_certificate = DeviceCertificate::from_x509(&device_cert)
            .map_err(AndroidCertChainError::DeviceCertificate)?;

        let root_certificate =
            RootCertificate::new(root_ca_cert).map_err(AndroidCertChainError::RootCertificate)?;

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
    pub fn serials(&self) -> &[CertificateSerial] {
        &self.serials
    }

    pub const fn device_certificate(&self) -> &DeviceCertificate {
        &self.device_certificate
    }

    pub const fn root_certificate(&self) -> &RootCertificate {
        &self.root_certificate
    }
}

fn certificate_serial(cert: &X509) -> Result<CertificateSerial, AndroidCertChainError> {
    let bn = cert
        .serial_number()
        .to_bn()
        .map_err(|_| AndroidCertChainError::StackPush)?;

    let decimal = bn
        .to_dec_str()
        .map_err(|_| AndroidCertChainError::StackPush)?
        .to_string();

    let hex = bn
        .to_hex_str()
        .map_err(|_| AndroidCertChainError::StackPush)?
        .to_string()
        .to_lowercase();

    Ok(CertificateSerial { decimal, hex })
}

impl AndroidCertChainError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DeviceCertificate(e) => {
                format!("device_certificate_{}", e.reason_tag())
            }
            Self::RootCertificate(e) => {
                format!("root_certificate_{}", e.reason_tag())
            }
            Self::Base64Encoding(_) => "base64_encoding".to_string(),
            Self::DerEncoding => "der_encoding".to_string(),
            Self::ChainLength => "chain_length".to_string(),
            Self::ChainVerification(e) => {
                format!("chain_verification_{}", e.as_raw())
            }
            Self::StackBuilder => "stack_builder".to_string(),
            Self::StackPush => "stack_push".to_string(),
            Self::ParamBuilder => "param_builder".to_string(),
            Self::StoreBuilder => "store_builder".to_string(),
            Self::StoreAdd => "store_add".to_string(),
            Self::ContextBuilder => "context_builder".to_string(),
            Self::ContextVerify => "context_verify".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DeviceCertificate(e) => e.is_internal_error(),
            Self::RootCertificate(e) => e.is_internal_error(),
            Self::Base64Encoding(_)
            | Self::DerEncoding
            | Self::ChainLength
            | Self::ChainVerification(_) => false,
            Self::StackBuilder
            | Self::StackPush
            | Self::ParamBuilder
            | Self::StoreBuilder
            | Self::StoreAdd
            | Self::ContextBuilder
            | Self::ContextVerify => true,
        }
    }
}
