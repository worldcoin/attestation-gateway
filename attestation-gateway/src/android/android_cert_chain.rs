use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub enum AndroidCertChainError {
    InvalidBase64Encoding(DecodeError),
    InvalidDerEncoding(openssl::error::ErrorStack),
    InvalidChainLength,
    InvalidCert(openssl::error::ErrorStack),
    InvalidChain(openssl::x509::X509VerifyResult),
    InternalStackBuilder(openssl::error::ErrorStack),
    InternalParamBuilder(openssl::error::ErrorStack),
    InternalStoreBuilder(openssl::error::ErrorStack),
    InternalContextBuilder(openssl::error::ErrorStack),
    InternalChainVerification(openssl::error::ErrorStack),
    InternalPublicKeyExtract(Option<openssl::error::ErrorStack>),
}

#[derive(Debug)]
pub struct AndroidCertChain {
    pub device_public_key: Vec<u8>,
    pub root_ca_public_key: Vec<u8>,
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

        let device_public_key = get_x509_subject_public_key(device_cert)?;
        let root_ca_public_key = get_x509_subject_public_key(root_ca_cert)?;

        Ok(Self {
            device_public_key,
            root_ca_public_key,
        })
    }
}

fn get_x509_subject_public_key(cert: &X509) -> Result<Vec<u8>, AndroidCertChainError> {
    let cert = cert
        .to_der()
        .map_err(|e| AndroidCertChainError::InternalPublicKeyExtract(Some(e)))?;

    let (_, cert) = X509Certificate::from_der(&cert)
        .map_err(|_| AndroidCertChainError::InternalPublicKeyExtract(None))?;

    Ok(Vec::from(cert.public_key().subject_public_key.data.clone()))
}
