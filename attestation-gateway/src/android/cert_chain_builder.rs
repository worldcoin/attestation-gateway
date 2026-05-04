use std::time::{SystemTime, UNIX_EPOCH};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    stack::Stack,
    x509::{
        X509, X509StoreContext, X509VerifyResult,
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyParam,
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

    #[error("verification error: {0} at depth {1}")]
    Verification(#[source] X509VerifyResult, u32),

    #[error("cert chain error: {0}")]
    CertChain(#[source] CertChainError),
}

#[derive(Debug, Error)]
pub enum CertChainBuilderBuildTrustedCertStoreError {
    #[error("param builder error")]
    ParamBuilder,

    #[allow(dead_code)]
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
                context.error_depth(),
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

        // TODO Throws "Missing Authority Key Identifier"
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
            Self::Verification(e, depth) => format!("verification_{}_{}", depth, e.as_raw()),
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
            | Self::Verification(_, _) => false,
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

        let cert1 = "MIICzDCCAnCgAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDkwZThkYTNjYWRmYzc4MjAxEjAQBgNVBAwMCVN0cm9uZ0JveDAiGA8yMDI2MDQyNzE3NDQzNVoYDzIwMzYwNDI3MTc0NDM0WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCiFp6QmDPOhqGzVxx5ca8SEdYRcoYEi7m/b9pATZFdbgc7uGwX9VdxQJMpTKU0JEUcg2LSlHmdWe0vtoTSf6m2jggGFMIIBgTAOBgNVHQ8BAf8EBAMCB4AwggFtBgorBgEEAdZ5AgERBIIBXTCCAVkCAQQKAQICASkKAQIELm49MzMyZDRkZTI4NWVhODBmMzU1NDQ1MDRlMjY4MzY2MDgsYXY9NC4wLjIxMDAEADByv4MRCAIGAedMacujv4MSCAIGAedMacujv4N9AgUAv4U9CAIGAZ3QCv/Qv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPRE0MSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGkoQUxAwIBAqIDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wDAYIKoZIzj0EAwIFAANIADBFAiEAgLRAd8YV570NdhKFQprG4v5dnkPv8BrgOyeH5M4fQ+ICIG0XrkMh1PKlRvLjRcQqo6kTeXafMW1xhGwKR4WQEtT0".to_string();
        let cert2 = "MIICMDCCAbegAwIBAgIKESM4JDRACGgBcTAKBggqhkjOPQQDAjAvMRkwFwYDVQQFExBjY2QxOGI5YjYwOGQ2NThlMRIwEAYDVQQMDAlTdHJvbmdCb3gwHhcNMTgwNTI1MjMyODUwWhcNMjgwNTIyMjMyODUwWjAvMRkwFwYDVQQFExA5MGU4ZGEzY2FkZmM3ODIwMRIwEAYDVQQMDAlTdHJvbmdCb3gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATkV0TCsZ+vcIoXK0BLe4q4sQ1veBPE228LqldQCQPCb6IBCpM7rHDgKmsaviWtsA0anJyUpXHTVix0mdIy9Xcno4G6MIG3MB0GA1UdDgQWBBRvsbUxnba4hRW+z8AMdxqP51TqljAfBgNVHSMEGDAWgBS8W8vVecaU3BmPm59nU8zr5mLf3jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzExMjMzODI0MzQ0MDA4NjgwMTcxMAoGCCqGSM49BAMCA2cAMGQCMFBzxlbrGJarX+e8d7UfD5M2Br3QxKUFAS1tfGxy9Lw72yfFn8v3jxNyCamglqpw8gIwYkzbZDvx/uU6vXIaB1y0PRGq5Jp5xIgKqUEJvsBuyMN8JdJsfzvHbkYyZUujU/SV".to_string();
        let cert3 = "MIID1zCCAb+gAwIBAgIKA4gmZ2BliZaFmDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDYyMDIyMTQwMloXDTI4MDYxNzIyMTQwMlowLzEZMBcGA1UEBRMQY2NkMThiOWI2MDhkNjU4ZTESMBAGA1UEDAwJU3Ryb25nQm94MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhO8/KkOtlIwEItY5zds+E2p/WG0wNet8fDHsooCiZi0MMzJZMGTlepRhYbnCBQlSi7TXjTzQQ8kAJmJFeHTlp7hBcpccDbCyicyvX5JjazVOiB3hwKzS0oKwSS9D3sUfo4G2MIGzMB0GA1UdDgQWBBS8W8vVecaU3BmPm59nU8zr5mLf3jAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzhGNjczNEM5RkE1MDQ3ODkwDQYJKoZIhvcNAQELBQADggIBAJOSNuBkQfic/SZf++OB6bXkbHmJpZaHxU/yVtnOZBrhAa4cLKIDg9A9A3nWtLw68x8VfI1s442+qHWfxGvVidhaCsLT+F2dpUme5VsgJSAK/6ZTLb5vhwskzS6G8YPUM/NzeFif7tkMu9cHkHlCFwJePPVWBg0iz51PFphdJGOG3e3CsRHG37Lk5RlvrVt3R5toRDrK5QV5V1RQ6OadRxHBxmmRC2owao8fU5yYkZ42bznwkyqCc0WsHmpqI0D/6jPaszAE7HlGPLMtGo/rVEaRjrjg9huEJMAHIsQAxhUDfZwAZ6tE4jEVf52o3AezZsvzDErcwWPB6ekUMBG9zuNLipcEhLKG9X4V0tJN+vwqvUWrzen9ZzvSoN6p5rQNjPFNvVtq0rVzPoPHjF6wN9r2qsQA8MVY31b3maOVq9n+WVOXxaZXtMmIKi8EgZAejeaq2ewAuxYaXoHsLI/9GPtF0k4mCbN6dffMwh/RJ8IWfZ3stwbyzcJ+sIrQ9IWX/Wsdi4vo3ZgRhf85pbGYM8SFYhnjUAbiyBHPYb0wltu+zwXMKXSuSCVhq3BnuTHS6sEkK5u9QBFY+U4AnP74MJ0tjP9S4YXm5/neTcE16yAdZlYY/8qZZoiukXl4TZTqlZA7/H5sdSx9ps+w/izJRS6CrFa72mB/tPtCd3jbMxVg".to_string();
        let cert4 = "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk".to_string();

        let cert_chain1 = cert_chain_builder
            .build_chain_from_base64(&[cert1.clone(), cert2.clone(), cert3.clone(), cert4.clone()])
            .unwrap();

        let cert_chain2 = cert_chain_builder
            .build_chain_from_base64(&[cert1.clone(), cert3.clone(), cert2.clone()])
            .unwrap();

        assert_eq!(cert_chain1.serials(), cert_chain2.serials());
    }
}
