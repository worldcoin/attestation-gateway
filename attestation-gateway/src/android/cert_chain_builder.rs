use std::{
    cmp::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    nid::Nid,
    stack::Stack,
    x509::{
        X509, X509StoreContext, X509VerifyResult,
        store::{X509Store, X509StoreBuilder},
        verify::{X509VerifyFlags, X509VerifyParam},
    },
};
use thiserror::Error;

use crate::android::cert_chain::{CertChain, CertChainError};

const LEGACY_GOOGLE_ROOT_SERIAL: &[u8] = b"f92009e853b6b045";

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

        let verified_cert_chain = match Self::verify_cert_chain(cert_chain, &trusted_cert_store) {
            Ok(verified_cert_chain) => verified_cert_chain,
            Err(CertChainBuilderBuildChainError::Verification(error, depth)) => {
                let verification_time = Asn1Time::from_unix(verification_time())
                    .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;

                if !legacy_factory_chain_dates_are_acceptable(cert_chain, &verification_time)
                    .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?
                {
                    return Err(CertChainBuilderBuildChainError::Verification(error, depth));
                }

                let legacy_cert_store = self
                    .build_legacy_cert_store_without_time_checks()
                    .map_err(CertChainBuilderBuildChainError::InternalBuildTrustedCertStore)?;

                match Self::verify_cert_chain(cert_chain, &legacy_cert_store) {
                    Ok(verified_cert_chain) => verified_cert_chain,
                    Err(CertChainBuilderBuildChainError::Verification(
                        legacy_error,
                        legacy_depth,
                    )) => {
                        if legacy_error.error_string() == "invalid CA certificate"
                            && legacy_depth == 1
                        {
                            if let Some(verified_cert_chain) =
                                self.verify_legacy_factory_chain(cert_chain)?
                            {
                                verified_cert_chain
                            } else {
                                return Err(CertChainBuilderBuildChainError::Verification(
                                    error, depth,
                                ));
                            }
                        } else {
                            return Err(CertChainBuilderBuildChainError::Verification(
                                error, depth,
                            ));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };

        CertChain::from_x509(&verified_cert_chain)
            .map_err(CertChainBuilderBuildChainError::CertChain)
    }

    fn verify_cert_chain(
        cert_chain: &[X509],
        trusted_cert_store: &X509Store,
    ) -> Result<Vec<X509>, CertChainBuilderBuildChainError> {
        let (leaf_cert, intermediate_certs) = cert_chain
            .split_first()
            .ok_or(CertChainBuilderBuildChainError::EmptyChain)?;

        let mut cert_stack =
            Stack::new().map_err(|_| CertChainBuilderBuildChainError::InternalStackBuilder)?;

        for cert in intermediate_certs {
            cert_stack
                .push(cert.to_owned())
                .map_err(|_| CertChainBuilderBuildChainError::InternalStackPush)?;
        }

        let mut context = X509StoreContext::new()
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextBuilder)?;

        let verified_cert_chain = context
            .init(trusted_cert_store, leaf_cert, &cert_stack, |ctx| {
                if !ctx.verify_cert()? {
                    return Ok(None);
                }

                Ok(ctx
                    .chain()
                    .map(|stack| stack.iter().map(|cert| cert.to_owned()).collect()))
            })
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;

        verified_cert_chain.ok_or_else(|| {
            CertChainBuilderBuildChainError::Verification(context.error(), context.error_depth())
        })
    }

    fn verify_legacy_factory_chain(
        &self,
        cert_chain: &[X509],
    ) -> Result<Option<Vec<X509>>, CertChainBuilderBuildChainError> {
        let [leaf, attestation, intermediate, supplied_root] = cert_chain else {
            return Ok(None);
        };

        let Some(trusted_root) = self
            .trusted_certs
            .iter()
            .find(|cert| is_legacy_google_root(cert))
        else {
            return Ok(None);
        };

        if supplied_root
            .subject_name()
            .try_cmp(trusted_root.subject_name())
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?
            != Ordering::Equal
        {
            return Ok(None);
        }

        let supplied_root_key = supplied_root
            .public_key()
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;
        let trusted_root_key = trusted_root
            .public_key()
            .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;

        if !supplied_root_key.public_eq(&trusted_root_key) {
            return Ok(None);
        }

        let verified_chain = [
            leaf.to_owned(),
            attestation.to_owned(),
            intermediate.to_owned(),
            trusted_root.to_owned(),
        ];

        for pair in verified_chain.windows(2) {
            let [cert, issuer] = pair else {
                unreachable!();
            };

            if cert
                .issuer_name()
                .try_cmp(issuer.subject_name())
                .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?
                != Ordering::Equal
            {
                return Ok(None);
            }

            let issuer_key = issuer
                .public_key()
                .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?;

            if !cert
                .verify(&issuer_key)
                .map_err(|_| CertChainBuilderBuildChainError::InternalContextVerify)?
            {
                return Ok(None);
            }
        }

        Ok(Some(Vec::from(verified_chain)))
    }

    fn build_trusted_cert_store(
        &self,
    ) -> Result<X509Store, CertChainBuilderBuildTrustedCertStoreError> {
        let mut store_param = X509VerifyParam::new()
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::ParamBuilder)?;

        // Account for clock drift
        store_param.set_time(verification_time());

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

    fn build_legacy_cert_store_without_time_checks(
        &self,
    ) -> Result<X509Store, CertChainBuilderBuildTrustedCertStoreError> {
        let mut store_param = X509VerifyParam::new()
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::ParamBuilder)?;

        // Google's verifier ignores target certificate validity and expired factory-provisioned
        // intermediates, but still rejects intermediates that are not yet valid. The latter is
        // checked before using NO_CHECK_TIME because OpenSSL cannot disable expiration checks only.
        store_param
            .set_flags(X509VerifyFlags::NO_CHECK_TIME)
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::ParamSetFlags)?;

        let mut store_builder = X509StoreBuilder::new()
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::Builder)?;

        store_builder
            .set_param(&store_param)
            .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::Builder)?;

        for trusted_cert in self
            .trusted_certs
            .iter()
            .filter(|cert| is_legacy_google_root(cert))
        {
            store_builder
                .add_cert(trusted_cert.to_owned())
                .map_err(|_| CertChainBuilderBuildTrustedCertStoreError::AddCert)?;
        }

        Ok(store_builder.build())
    }
}

fn is_legacy_google_root(cert: &X509) -> bool {
    cert.subject_name()
        .entries_by_nid(Nid::SERIALNUMBER)
        .any(|entry| entry.data().as_slice() == LEGACY_GOOGLE_ROOT_SERIAL)
}

fn verification_time() -> i64 {
    60 + SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

fn legacy_factory_chain_dates_are_acceptable(
    cert_chain: &[X509],
    verification_time: &Asn1TimeRef,
) -> Result<bool, openssl::error::ErrorStack> {
    let [_, attestation, intermediate, _] = cert_chain else {
        return Ok(false);
    };

    for cert in [attestation, intermediate] {
        if cert.not_before().compare(verification_time)? == Ordering::Greater {
            return Ok(false);
        }
    }

    Ok(true)
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
    fn identifies_only_legacy_google_root() {
        let cert_chain_builder = CertChainBuilder::new_from_default_pem().unwrap();

        assert!(is_legacy_google_root(&cert_chain_builder.trusted_certs[0]));
        assert!(!is_legacy_google_root(&cert_chain_builder.trusted_certs[1]));
    }

    #[test]
    fn accepts_expired_factory_chain_but_rejects_not_yet_valid_intermediates() {
        let cert_chain_builder = CertChainBuilder::new_from_default_pem().unwrap();
        let cert1 = "MIICvzCCAmSgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwNjdmOWJmMGFlNTQwNmMxMQwwCgYDVQQMDANURUUwHhcNNzAwMTAxMDAwMDAwWhcNNzAwMTAxMDAwMDAwWjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5ZUqZSIZumBF6OtNdq+Lzw4MANIrFLKCHsFeQrtNpmIGk1Uk7y0T/kFYEavMN6JfwP1WV7aBRdn9oi0Vp8ygajggGFMIIBgTALBgNVHQ8EBAMCB4AwggFPBgorBgEEAdZ5AgERBIIBPzCCATsCAQMKAQECAQQKAQEELm49NTY5NmZkM2MyYzBiMjg5MDYxNTdjOWMzMWNjMDE1YmUsYXY9NC4wLjMxMDAEADBov4MRCAIGAZ+OZmjAv4MSCAIGAZ+OZmjAv4U9CAIGAZ+OYdD4v4VFQAQ+MDwxFjAUBA1jb20ud29ybGRjb2luAgM9FRwxIgQgnSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8wgZChBTEDAgECogMCAQOjBAICAQClCDEGAgEAAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCBP/IgfqvstGvfdQM+6TKkEZLT1aJ739Ow6D+e3QUQGiAEBAQoBAAQgiaPWQESZuzc8T5GTBlm97rYM58em+2G7OABrJQS+qA6/hUEFAgMBhqC/hUIFAgMDFX8wHwYDVR0jBBgwFoAU263NqhXAwJF864A5G8IVYNKn7CwwCgYIKoZIzj0EAwIDSQAwRgIhAOkJ8QYZ05jFPT6lWFhQOmdncx7XYKk8bYge15W4KGXuAiEAruZlPuOmWJFIae0jwu4dDEWAlWfuhlbxcx+5C2P5sOE=".to_string();
        let cert2 = "MIICJTCCAaugAwIBAgIKEVIgIXIgclFiJjAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAyMzg3OGYwY2I5ZGU4NTFhMQwwCgYDVQQMDANURUUwHhcNMTgwNzIzMTk1NjU1WhcNMjgwNzIwMTk1NjU1WjApMRkwFwYDVQQFExAwNjdmOWJmMGFlNTQwNmMxMQwwCgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASaAUmuLgzPyDyXlo/n1Ko5GCxsV/kbDM6pHG1/mntYk13RzBvcGPD05e81dA6Bp5I9tF+x3ivFThgzOWxRjgm4o4G6MIG3MB0GA1UdDgQWBBTbrc2qFcDAkXzrgDkbwhVg0qfsLDAfBgNVHSMEGDAWgBSfvF93vtFSWG6q/KH55h85D0sAPTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzExNTIyMDIxNzIyMDcyNTE2MjI2MAoGCCqGSM49BAMCA2gAMGUCMH09uhX4RgQFw1nhCdEIQ0WhuGi094MKtr/QeWrpgUQ5tzTifvLwtPyvT1jeoLpsnAIxAPEZIs6B5ei2fK8aXhBlgqEkc4ssXg9M00WGYkNT9nPSoi2OjsuzJdfZ6Vj4lLCQLQ==".to_string();
        let cert3 = "MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaFnDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDcyMzE5NTMxMloXDTI4MDcyMDE5NTMxMlowKTEZMBcGA1UEBRMQMjM4NzhmMGNiOWRlODUxYTEMMAoGA1UEDAwDVEVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEw61Nd8Q51Y/OBOqzjG6a1D+qhtV3FagPuSaNJoDnxuf85fYurFG0IGQzRYVfMjzXAhfY20aWVip1W+uS6pPuBAu6HM+4T/XQAlqhQmv7t69WERv+g0GdNi9ncv7pD1n0o4G2MIGzMB0GA1UdDgQWBBSfvF93vtFSWG6q/KH55h85D0sAPTAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsL0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBAGDPfqeu514zKXz9OWpD2uo2Gcbf2ULo8ywSI7Bydl73Ux5gI/s480CZpBgQTN5+hHprv+m+PzSSg+Dg689ev5b+b9Qj2zTyo23YZglHWS9V1+JoVSxNCOmA3ql5wxuLRG76UOcAKs43WMjLvvERP8e/vpOKwTuAKYG0WknJT6E5pwPfZ2cvsOIAIe7d/kVZyJbOJcHT4+anY15u7HOu9zbhYUmeOSSfh0NbjZhubIAuwWoryhLBaWTDRmLVYE9XKJQIPn36LWuaUd+gt1jPYSL9gejkfYt4jvXlqWdovVV5yKhKAMEIV6cL876qUvkNey2nr/SeMHZDznjWwTv+9ztnsyth1T+PBJfIbAdDVDcnSBWAIrbFQ3/espcSdDaDoLL4zDj05ZLEUKmdJODpDvacMF4Szpm38MRMB25+I7/N2oFwPaCfxAf4o+CjuHjyzbc+Msow1fm7rZ8qwE1EcPQTDFnY1iLOkqhxpd6T1k4bYf5uZgCSYE/G4Vu8PlUxdaXAUsn4K5VvBUm1JTDtNwngIY3BJriudjAsUd9H2WE2EmaZnpSe+FUK0LmHSCHVA6t4NtE7bLUrhGrcjwsucP7EA4Vvf++HpiLym1uhL3/4qaDR0t780zc73hzUCwzrefHN0q65wX8/Xo9DKHliJO+mJG1zaO+eRYNsRWHJdUAg".to_string();
        let cert4 = "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk".to_string();

        let x509_chain = [&cert1, &cert2, &cert3, &cert4]
            .map(|cert| X509::from_der(&Base64.decode(cert).unwrap()).unwrap());

        assert!(
            !legacy_factory_chain_dates_are_acceptable(
                &x509_chain,
                Asn1Time::from_unix(0).unwrap().as_ref(),
            )
            .unwrap()
        );

        cert_chain_builder
            .build_chain_from_base64(&[cert1, cert2, cert3, cert4])
            .unwrap();
    }

    #[cfg(test)]
    fn invalid_ca_factory_chain() -> Vec<String> {
        [
            "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",
        ]
        .map(str::to_string)
        .to_vec()
    }

    #[test]
    fn accepts_legacy_factory_chain_with_non_ca_attestation_cert() {
        CertChainBuilder::new_from_default_pem()
            .unwrap()
            .build_chain_from_base64(&invalid_ca_factory_chain())
            .unwrap();
    }

    #[test]
    fn rejects_legacy_factory_chain_with_invalid_signature() {
        let mut cert_chain = invalid_ca_factory_chain();
        let mut leaf = Base64.decode(&cert_chain[0]).unwrap();
        *leaf.last_mut().unwrap() ^= 1;
        cert_chain[0] = Base64.encode(leaf);

        assert!(
            CertChainBuilder::new_from_default_pem()
                .unwrap()
                .build_chain_from_base64(&cert_chain)
                .is_err()
        );
    }

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

        assert!(cert_chain1.has_strong_box_chain_shape());
        assert!(cert_chain2.has_strong_box_chain_shape());

        assert_eq!(
            cert_chain1.session_cert().serial(),
            cert_chain2.session_cert().serial()
        );
        assert_eq!(
            cert_chain1.device_cert().serial(),
            cert_chain2.device_cert().serial()
        );
        assert_eq!(
            cert_chain1
                .intermediate_certs()
                .iter()
                .map(|cert| cert.serial())
                .collect::<Vec<_>>(),
            cert_chain2
                .intermediate_certs()
                .iter()
                .map(|cert| cert.serial())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            cert_chain1.root_cert().serial(),
            cert_chain2.root_cert().serial()
        );
    }

    #[test]
    fn test_cert_chain_json_serialization() {
        let cert_chain_builder = CertChainBuilder::new_from_default_pem().unwrap();

        let cert1 = "MIICzDCCAnCgAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDkwZThkYTNjYWRmYzc4MjAxEjAQBgNVBAwMCVN0cm9uZ0JveDAiGA8yMDI2MDQyNzE3NDQzNVoYDzIwMzYwNDI3MTc0NDM0WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCiFp6QmDPOhqGzVxx5ca8SEdYRcoYEi7m/b9pATZFdbgc7uGwX9VdxQJMpTKU0JEUcg2LSlHmdWe0vtoTSf6m2jggGFMIIBgTAOBgNVHQ8BAf8EBAMCB4AwggFtBgorBgEEAdZ5AgERBIIBXTCCAVkCAQQKAQICASkKAQIELm49MzMyZDRkZTI4NWVhODBmMzU1NDQ1MDRlMjY4MzY2MDgsYXY9NC4wLjIxMDAEADByv4MRCAIGAedMacujv4MSCAIGAedMacujv4N9AgUAv4U9CAIGAZ3QCv/Qv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPRE0MSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGkoQUxAwIBAqIDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wDAYIKoZIzj0EAwIFAANIADBFAiEAgLRAd8YV570NdhKFQprG4v5dnkPv8BrgOyeH5M4fQ+ICIG0XrkMh1PKlRvLjRcQqo6kTeXafMW1xhGwKR4WQEtT0".to_string();
        let cert2 = "MIICMDCCAbegAwIBAgIKESM4JDRACGgBcTAKBggqhkjOPQQDAjAvMRkwFwYDVQQFExBjY2QxOGI5YjYwOGQ2NThlMRIwEAYDVQQMDAlTdHJvbmdCb3gwHhcNMTgwNTI1MjMyODUwWhcNMjgwNTIyMjMyODUwWjAvMRkwFwYDVQQFExA5MGU4ZGEzY2FkZmM3ODIwMRIwEAYDVQQMDAlTdHJvbmdCb3gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATkV0TCsZ+vcIoXK0BLe4q4sQ1veBPE228LqldQCQPCb6IBCpM7rHDgKmsaviWtsA0anJyUpXHTVix0mdIy9Xcno4G6MIG3MB0GA1UdDgQWBBRvsbUxnba4hRW+z8AMdxqP51TqljAfBgNVHSMEGDAWgBS8W8vVecaU3BmPm59nU8zr5mLf3jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzExMjMzODI0MzQ0MDA4NjgwMTcxMAoGCCqGSM49BAMCA2cAMGQCMFBzxlbrGJarX+e8d7UfD5M2Br3QxKUFAS1tfGxy9Lw72yfFn8v3jxNyCamglqpw8gIwYkzbZDvx/uU6vXIaB1y0PRGq5Jp5xIgKqUEJvsBuyMN8JdJsfzvHbkYyZUujU/SV".to_string();
        let cert3 = "MIID1zCCAb+gAwIBAgIKA4gmZ2BliZaFmDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDYyMDIyMTQwMloXDTI4MDYxNzIyMTQwMlowLzEZMBcGA1UEBRMQY2NkMThiOWI2MDhkNjU4ZTESMBAGA1UEDAwJU3Ryb25nQm94MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhO8/KkOtlIwEItY5zds+E2p/WG0wNet8fDHsooCiZi0MMzJZMGTlepRhYbnCBQlSi7TXjTzQQ8kAJmJFeHTlp7hBcpccDbCyicyvX5JjazVOiB3hwKzS0oKwSS9D3sUfo4G2MIGzMB0GA1UdDgQWBBS8W8vVecaU3BmPm59nU8zr5mLf3jAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzhGNjczNEM5RkE1MDQ3ODkwDQYJKoZIhvcNAQELBQADggIBAJOSNuBkQfic/SZf++OB6bXkbHmJpZaHxU/yVtnOZBrhAa4cLKIDg9A9A3nWtLw68x8VfI1s442+qHWfxGvVidhaCsLT+F2dpUme5VsgJSAK/6ZTLb5vhwskzS6G8YPUM/NzeFif7tkMu9cHkHlCFwJePPVWBg0iz51PFphdJGOG3e3CsRHG37Lk5RlvrVt3R5toRDrK5QV5V1RQ6OadRxHBxmmRC2owao8fU5yYkZ42bznwkyqCc0WsHmpqI0D/6jPaszAE7HlGPLMtGo/rVEaRjrjg9huEJMAHIsQAxhUDfZwAZ6tE4jEVf52o3AezZsvzDErcwWPB6ekUMBG9zuNLipcEhLKG9X4V0tJN+vwqvUWrzen9ZzvSoN6p5rQNjPFNvVtq0rVzPoPHjF6wN9r2qsQA8MVY31b3maOVq9n+WVOXxaZXtMmIKi8EgZAejeaq2ewAuxYaXoHsLI/9GPtF0k4mCbN6dffMwh/RJ8IWfZ3stwbyzcJ+sIrQ9IWX/Wsdi4vo3ZgRhf85pbGYM8SFYhnjUAbiyBHPYb0wltu+zwXMKXSuSCVhq3BnuTHS6sEkK5u9QBFY+U4AnP74MJ0tjP9S4YXm5/neTcE16yAdZlYY/8qZZoiukXl4TZTqlZA7/H5sdSx9ps+w/izJRS6CrFa72mB/tPtCd3jbMxVg".to_string();
        let cert4 = "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk".to_string();

        let cert_chain = cert_chain_builder
            .build_chain_from_base64(&[cert1, cert2, cert3, cert4])
            .unwrap();

        let json = serde_json::to_value(&cert_chain).expect("cert chain should serialize to JSON");

        assert!(json.get("session_cert").is_some());
        assert!(json.pointer("/session_cert/serial/decimal").is_some());
        assert!(
            json.pointer("/session_cert/key_description/attestation_challenge")
                .is_some()
        );
        assert_eq!(
            json.pointer("/session_cert/key_description/attestation_security_level")
                .and_then(|v| v.as_str()),
            Some("StrongBox")
        );
        assert!(json.get("device_cert").is_some());
        assert!(json.get("intermediate_certs").is_some());
        assert!(json.get("root_cert").is_some());
    }
}
