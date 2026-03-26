use openssl::x509::X509;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub enum RootCertificateError {
    InternalEncodeDer(openssl::error::ErrorStack),
    InternalDecodeDer,
}

#[derive(Debug)]
pub struct RootCertificate {
    pub public_key: Vec<u8>,
}

impl RootCertificate {
    pub fn new(cert: X509) -> Result<Self, RootCertificateError> {
        let cert = cert
            .to_der()
            .map_err(|e| RootCertificateError::InternalEncodeDer(e))?;

        let (_, cert) = X509Certificate::from_der(&cert)
            .map_err(|_| RootCertificateError::InternalDecodeDer)?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());

        Ok(Self { public_key })
    }
}
