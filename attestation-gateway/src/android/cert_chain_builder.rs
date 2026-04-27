use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{
        X509, X509StoreContext, X509VerifyResult,
        store::{X509Store, X509StoreBuilder},
        verify::{X509VerifyFlags, X509VerifyParam},
    },
};
use thiserror::Error;

use crate::android::cert_chain::{CertChain, CertChainError};

#[derive(Debug, Error)]
pub enum CertChainBuilderNewError {
    #[error("pem parsing error")]
    PemParsing,
}

#[derive(Debug, Error)]
pub enum CertChainBuilderBuildChainError {
    #[error("build trusted cert store error: {0}")]
    InternalBuildTrustedCertStore(#[source] CertChainBuilderBuildTrustedCertStoreError),

    #[error("stack builder error")]
    InternalStackBuilder,

    #[error("stack push error")]
    InternalStackPush,

    #[error("context builder error")]
    InternalContextBuilder,

    #[error("context verify error")]
    InternalContextVerify,

    #[error("base64 decoding error: {0}")]
    Base64Decoding(#[source] DecodeError),

    #[error("der decoding error")]
    DerDecoding,

    #[error("empty chain")]
    EmptyChain,

    #[error("verification error: {0}")]
    Verification(#[source] X509VerifyResult),

    #[error("cert chain error: {0}")]
    CertChain(#[source] CertChainError),
}

#[derive(Debug, Error)]
pub enum CertChainBuilderBuildTrustedCertStoreError {
    #[error("param builder error")]
    ParamBuilder,

    #[error("param set flags error")]
    ParamSetFlags,

    #[error("builder error")]
    Builder,

    #[error("add cert error")]
    AddCert,
}

#[derive(Debug, Clone)]
pub struct CertChainBuilder {
    trusted_certs: Vec<X509>,
}

impl CertChainBuilder {
    pub fn new_from_default_pem() -> Result<Self, CertChainBuilderNewError> {
        Self::new_from_pem(&[
            include_bytes!("attestation_root_ca1.pem").to_vec(),
            include_bytes!("attestation_root_ca2.pem").to_vec(),
        ])
    }

    pub fn new_from_pem(pem_certs: &[Vec<u8>]) -> Result<Self, CertChainBuilderNewError> {
        let root_certs = pem_certs
            .iter()
            .map(|pem| X509::from_pem(pem))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| CertChainBuilderNewError::PemParsing)?;

        Ok(Self {
            trusted_certs: root_certs,
        })
    }

    pub fn build_chain_from_base64(
        &self,
        base64_cert_chain: &[String],
    ) -> Result<CertChain, CertChainBuilderBuildChainError> {
        let der_cert_chain = base64_cert_chain
            .iter()
            .map(|c| Base64.decode(c))
            .collect::<Result<Vec<Vec<u8>>, DecodeError>>()
            .map_err(CertChainBuilderBuildChainError::Base64Decoding)?;

        self.build_chain_from_der(&der_cert_chain)
    }

    pub fn build_chain_from_der(
        &self,
        der_cert_chain: &[Vec<u8>],
    ) -> Result<CertChain, CertChainBuilderBuildChainError> {
        let x509_cert_chain = der_cert_chain
            .iter()
            .map(|c| X509::from_der(c))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| CertChainBuilderBuildChainError::DerDecoding)?;

        self.build_chain_from_x509(&x509_cert_chain)
    }

    pub fn build_chain_from_x509(
        &self,
        cert_chain: &[X509],
    ) -> Result<CertChain, CertChainBuilderBuildChainError> {
        let trusted_cert_store = self
            .build_trusted_cert_store()
            .map_err(CertChainBuilderBuildChainError::InternalBuildTrustedCertStore)?;

        let (leaf_cert, intermediate_certs) = cert_chain
            .split_first()
            .ok_or(CertChainBuilderBuildChainError::EmptyChain)?;

        let mut cert_stack =
            Stack::new().map_err(|_| CertChainBuilderBuildChainError::InternalStackBuilder)?;

        for cert in intermediate_certs.iter() {
            cert_stack
                .push(cert.to_owned())
                .map_err(|_| CertChainBuilderBuildChainError::InternalStackPush)?;
        }

        let mut context = X509StoreContext::new()
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextBuilder)?;

        let verified_cert_chain = context
            .init(&trusted_cert_store, leaf_cert, &cert_stack, |ctx| {
                if !ctx.verify_cert()? {
                    return Ok(None);
                }

                let verified_cert_chain = ctx
                    .chain()
                    .map(|stack| stack.iter().map(|c| c.to_owned()).collect::<Vec<X509>>());

                Ok(verified_cert_chain)
            })
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;

        match verified_cert_chain {
            Some(verified_cert_chain) => CertChain::from_x509(&verified_cert_chain)
                .map_err(CertChainBuilderBuildChainError::CertChain),
            None => Err(CertChainBuilderBuildChainError::Verification(
                context.error(),
            )),
        }
    }

    fn build_trusted_cert_store(
        &self,
    ) -> Result<X509Store, CertChainBuilderBuildTrustedCertStoreError> {
        let mut store_param = X509VerifyParam::new()
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::ParamBuilder)?;

        // Account for clock drift
        store_param.set_time(
            60 + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .cast_signed(),
        );

        // TODO: test below fails verification, get new certs from Pablo to check
        // store_param
        //     .set_flags(X509VerifyFlags::X509_STRICT)
        //     .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::ParamSetFlags)?;

        let mut store_builder = X509StoreBuilder::new()
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::Builder)?;

        store_builder
            .set_param(&store_param)
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::Builder)?;

        for trusted_cert in self.trusted_certs.iter() {
            store_builder
                .add_cert(trusted_cert.to_owned())
                .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::AddCert)?;
        }

        Ok(store_builder.build())
    }
}

impl CertChainBuilderBuildChainError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::InternalBuildTrustedCertStore(e) => {
                format!("build_trusted_cert_store_{}", e.reason_tag())
            }
            Self::InternalStackBuilder => "stack_builder".to_string(),
            Self::InternalStackPush => "stack_push".to_string(),
            Self::InternalContextBuilder => "context_builder".to_string(),
            Self::InternalContextVerify => "context_verify".to_string(),
            Self::Base64Decoding(_) => "base64_decoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
            Self::EmptyChain => "empty_chain".to_string(),
            Self::Verification(e) => format!("verification_{}", e.as_raw()),
            Self::CertChain(e) => format!("cert_chain_{}", e.reason_tag()),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::InternalBuildTrustedCertStore(_)
            | Self::InternalStackBuilder
            | Self::InternalStackPush
            | Self::InternalContextBuilder
            | Self::InternalContextVerify => true,
            Self::Base64Decoding(_)
            | Self::DerDecoding
            | Self::EmptyChain
            | Self::Verification(_) => false,
            Self::CertChain(e) => e.is_internal_error(),
        }
    }
}

impl CertChainBuilderBuildTrustedCertStoreError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::ParamBuilder => "param_builder".to_string(),
            Self::ParamSetFlags => "param_set_flags".to_string(),
            Self::Builder => "builder".to_string(),
            Self::AddCert => "add_cert".to_string(),
        }
    }
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_certificate_order1() {
        let cert_chain_builder = CertChainBuilder::new_from_default_pem().unwrap();
        let cert1 = "MIICtTCCAlqgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDFhMGI5NTJlZDU3NTk3NzA0MmZhY2Y0YTllZjhiZWJiMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATOaK7SdXelxBrY2Lw007j3iYWforwDzCJhfPf0CDuKxkjXpNNm1Gv1kTBg2+SZdqJiJT+mk3teNBN9qO0UADC4o4IBazCCAWcwDgYDVR0PAQH/BAQDAgeAMIIBUwYKKwYBBAHWeQIBEQSCAUMwggE/AgIBLAoBAQICASwKAQEELm49MzEyMzRkNGQ2MWFmZjkzMDNkNTM1Y2M0MzQzY2IzY2EsYXY9NC4wLjE3MDAEADBYv4U9CAIGAZ2V8f9Kv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz1LaDEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBoqEIMQYCAQICAQOiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DdwIFAL+FPgMCAQC/hUBMMEoEINrfKLR2YgdkoI97pfNa3LZ2A4FMqQ/Sqgze41Cq9jOBAQH/CgEABCDpEX7xUYmS0qsrrJuUnkv2oW+g7PD6EXhmUVsII09egb+FQQUCAwJJ8L+FQgUCAwMXbL+FTgUCAwMXbL+FTwUCAwMXbDAKBggqhkjOPQQDAgNJADBGAiEA1iynKSSDLMc9ZzDVg2E2tk3S6iemUDfoBL9iKzNL1I0CIQDT1c5JrYWaGHABO+gPhUzBDtHpebCsbSzxrPwB0liMWA==".to_string();
        let cert2 = "MIIB8zCCAXmgAwIBAgIQf6UuX5jz1kvUeVrclnoTSzAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDdiNGQyYTVkNWZlZDA1NmJmNzQ2Y2I5MTA0OTg5NzlkMB4XDTI0MDcxMjIxMjIxMloXDTM0MDcxMDIxMjIxMlowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyAxYTBiOTUyZWQ1NzU5NzcwNDJmYWNmNGE5ZWY4YmViYjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBaJUWqFCV2C0vY4T+ctGt1WbNADW7P8jPTzlWQdmEz2a8w4UtVV0/i2p35JNh05YS7NxTJA5fSFl6z8mYl58X2jYzBhMB0GA1UdDgQWBBSqPh2bIMxi+PZZGGb4SCZD1YoBPTAfBgNVHSMEGDAWgBQpQX2gXexPcdCVGxeSxuRDIpWslzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNoADBlAjEAgGDseOQwBOjecJlcXNFJk/NN3tG+eG1/RFRd+CiCrUcIyOpPxfKYbdSrcnsVCFxSAjBl8CJSpGY2Z891vF3GUdxVNP+MXM6LRiVDUIzJ9sFL7rJ16koZW//NYz852BQW2aw=".to_string();
        let cert3 = "MIIDkzCCAXugAwIBAgIQLWsPsr9I11TqphKlbJtWgDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTI0MDcxMjIxMjA1NFoXDTM0MDcxMDIxMjA1NFowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA3YjRkMmE1ZDVmZWQwNTZiZjc0NmNiOTEwNDk4OTc5ZDB2MBAGByqGSM49AgEGBSuBBAAiA2IABEznL3Uv+p94TRmMSh5ZNamHXYjG82WOo/V87teAJ6gQPRpAdFmg2Rb9O7o/L+mrEFHtzcDObojdnFnt53bDIXqFZhHgny4Cs+vymVKeLeHL4TIPTVgppUVCE96mphTuv6NjMGEwHQYDVR0OBBYEFClBfaBd7E9x0JUbF5LG5EMilayXMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQCgbCrE+O9PLZOIeox7dzzufxtGiWOn5FY8LfGT+tpONdqvOdm+ML3RHiNXuor85OjjWV8zeaWWJulnBjbQsmDUlGZPVnD5PqlGnwD/Tc/NifBBEhEqcspuiS7TRZTECG/gWCIUUlXwra4+xy7YyszmwE6pEEol35W8uYA5NqGd6olwk6kqxZyHKpfuugV0dhlGNZ1YH7k9HGH4PDPba7CZk5I4xO2SXbHwqYjBUjplaCCKJ1BY7il4zP8tkejehYpgVwFP2VxkbgnviTRawyzaRPa2t0Oq+tN6/hGk8ZcwhwsSOHiZe/lUCuepir006CzR7iKn+j07xT79UDaYt4YYSl3qhWRXEs6vL7zw8IGDKSbCvFQkCLW0uXZsqg2bsLS4PJJrD4K8pBQGMOppRoYocGgy0XGOy8KCGrM3jK14sLFnH+7W6K1qS0bXt/lLc36r+MZ76H9I2RtiY++4FUDFawHNeq1KvjAO6gdxdyGmkSJzFHPY7Hn7KDQgx2/XeSBQ44ZYh0cD9h+6lELTuLqyyMXr0LqPCQ8vruiLX6+5wV+eDouSfcJNjt7ICtAv0DA3z47lGBNF5GbX7BYk1FI93xu2R5j1+ZDlXO42FrRcL27Cew/YhUHTTS9qfBywf1NDfbx1JQgqOdhUeb5ALtXae7HOnkersCx+yJA4QsCqzg==".to_string();

        let cert_chain1 = cert_chain_builder
            .build_chain_from_base64(&[cert1.clone(), cert2.clone(), cert3.clone()])
            .unwrap();

        let cert_chain2 = cert_chain_builder
            .build_chain_from_base64(&[cert1.clone(), cert3.clone(), cert2.clone()])
            .unwrap();

        assert_eq!(cert_chain1.serials(), cert_chain2.serials());
    }
}
