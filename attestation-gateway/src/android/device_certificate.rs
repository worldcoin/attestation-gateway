use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use der_parser::asn1_rs::oid;
use openssl::x509::X509;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::android::key_description::KeyDescription;

#[derive(Debug)]
pub enum DeviceCertificateError {
    Base64Encoding(DecodeError),
    DerEncoding(openssl::error::ErrorStack),
    DerDecoding,
    AttestationExtraction,
    MissingAttestation,
    AttestationParsing(asn1::ParseError),
}

pub struct DeviceCertificate {
    pub public_key: Vec<u8>,
    pub security_level: u32,
    pub device_locked: bool,
    /// First package name from `attestation_application_id` (authorization tag 709), if present and UTF-8.
    pub package_name: Option<String>,
}

impl DeviceCertificate {
    pub fn from_base64(pem: String) -> Result<Self, DeviceCertificateError> {
        let cert = Base64
            .decode(pem)
            .map_err(|e| DeviceCertificateError::Base64Encoding(e))?;

        Self::from_der(cert)
    }

    pub fn from_x509(x509: X509) -> Result<Self, DeviceCertificateError> {
        let der = x509
            .to_der()
            .map_err(|e| DeviceCertificateError::DerEncoding(e))?;

        Self::from_der(der)
    }

    pub fn from_der(der: Vec<u8>) -> Result<Self, DeviceCertificateError> {
        let (_, cert) =
            X509Certificate::from_der(&der).map_err(|_| DeviceCertificateError::DerDecoding)?;

        let key_description = cert
            .get_extension_unique(&oid!(1.3.6.1.4.1.11129.2.1.17))
            .map_err(|_| DeviceCertificateError::AttestationExtraction)?
            .ok_or(DeviceCertificateError::MissingAttestation)?;

        let key_description = asn1::parse_single::<KeyDescription>(key_description.value)
            .map_err(|e| DeviceCertificateError::AttestationParsing(e))?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());
        let security_level = key_description.attestation_security_level.value();
        let device_locked = match &key_description.hardware_enforced.root_of_trust {
            Some(root_of_trust) => root_of_trust.device_locked,
            None => false,
        };

        let package_name =
            key_description
                .try_parse_attestation_application_id()
                .and_then(|app_id| {
                    app_id.package_infos.clone().next().and_then(|pkg| {
                        std::str::from_utf8(pkg.package_name).ok().map(String::from)
                    })
                });

        Ok(Self {
            public_key,
            security_level,
            device_locked,
            package_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pablo_cert1() {
        let cert = "MIICzDCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs2uoTuLKmoC+unpsOJSFI0LsJCVNBiyKiTqYDXkno+MMeYoEsoHFdecOeBmoCImbKf8bWsDAxSbGOj6JzSIsqaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDCCAXoGCisGAQQB1nkCAREEggFqMIIBZgIBAwoBAQIBBAoBAQRWYXBwLnN0YWdlLmZhY2Uud29ybGRjb2luLm9yZyE3NTRiYTQyM2FkZjNhNmQ1Y2IyZWMzNmRhOGVjZmQ0NCEyMDI2LTAyLTI2VDIxOjE3OjI0LjQ1N1oEADBav4N9AgUAv4U9CAIGAZyb0Wewv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ2wMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGhoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wCgYIKoZIzj0EAwIDRwAwRAIgRYC4+rYMqjEi7Jq6J+lRR19BmcvCzaUqwMm5butcSVUCIB8pISV0K5+guf99CAxpRGlhc52EZvC+9YiAT5UUuHUA".to_string();
        let cert = Base64.decode(cert).unwrap();
        let cert = X509::from_der(&cert).unwrap();
        let cert = DeviceCertificate::from_x509(cert).unwrap();

        assert!(cert.public_key.len() > 0);
        assert_eq!(cert.package_name.as_deref(), Some("com.worldcoin.dev"));
    }

    #[test]
    fn test_rooted_cert1() {
        let cert = "MIIC4TCCAoegAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIGY5YWQ1ZWZhMmQ1YzcyNTYzYjA1MmVlZTA5ODFjYzk0MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5Wp9aeOVrmo0xW8TXVUGEd19KplH1C0OXmim3uXOcGvoB9ROaMghQglZC0Xolq2L0c9ugVqYMcSl2gdvCoVq0o4IBkjCCAY4wggF6BgorBgEEAdZ5AgERBIIBajCCAWYCAgEsCgECAgIBLAoBAgQubj03ZjNiMDgwMzNmMmM5YTU4YjUwMGY2ODNkMzcwNDRiYyxhdj00LjAuMTUwMAQAMHe/gxEIAgYBnR+zLY+/gxIIAgYBnR+zLY+/gxUDAgEFv4U9CAIGAZ0ffD8Sv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz0O3DEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBqqEFMQMCAQKiAwIBA6MEAgIBAKUIMQYCAQACAQSqAwIBAb+DdwIFAL+DfQIFAL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCDv4VB1RNuPTAhMMGtJQ5jxm8m8QNWQvomIL/KdoacwQb+FQQUCAwJxAL+FQgUCAwMXab+FTgYCBAE1JQW/hU8GAgQBNSUFMA4GA1UdDwEBAQQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4G52FKSBbkPnKXY6NmH4Fci/aZj/e4UhKEFxiZAdJzICIA4voKPjSTj0g3dE0tfVPELNExfUYy4kBZ7hgv70Vc+4".to_string();
        let cert = Base64.decode(cert).unwrap();
        let cert = X509::from_der(&cert).unwrap();
        let cert = DeviceCertificate::from_x509(cert).unwrap();

        assert!(cert.public_key.len() > 0);
        assert!(cert.security_level == 2);
        assert!(cert.device_locked == false);
    }

    #[test]
    fn test_rooted_cert2() {
        let cert = "MIIC0TCCAnigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDZhMTc3MWVkMDhlZjdmZDEwYzkxZjg3OTQ0N2VmYzYzMB4XDTcwMDEwMTAwMDAwMFoXDTI2MDMyNDEzMjczMVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARd9vtCtv5j4/JSTByGmHdOVUru37iqFd/RG2W6uwiirMTrLuchwAouHLDdus84y8im9rLNhwYGhYmw8f8XcpRno4IBiTCCAYUwDgYDVR0PAQH/BAQDAgeAMIIBcQYKKwYBBAHWeQIBEQSCAWEwggFdAgEDCgEBAgEpCgEBBC5uPTZkODAxNjRlYzkxMzYyNjM2MzMyNmFlZDMyZTMyY2Q3LGF2PTQuMC4xNTAwBAAwdr+DEQgCBgGdIAdxnb+DEggCBgGdIAdxnb+DfQIFAL+FPQgCBgGdH9CDIL+FRUgERjBEMR4wHAQVY29tLndvcmxkY29pbi5zdGFnaW5nAgM9DtwxIgQgnSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8wgaShBTEDAgECogMCAQOjBAICAQClCDEGAgEEAgEAqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDCIkVxyc1ciSAKcxGx43qpz3UeLhl1Po03ArygC+HULAEB/woBAAQgjlUrRorDAGMIoeVUyIUelNbEKGCSRNEZeXJHGmAVGhG/hUEFAgMB+9C/hUIFAgMDFwe/hU4GAgQBNP69v4VPBgIEATT+vTAKBggqhkjOPQQDAgNHADBEAiA402rjq8p2ODT2lMsXnVfRoUmoyjq/sQUiuTrkFLtcHwIgPpAd/fYw4sR0qYGBvi0sockS6wBIOAvFQIkMFqfW8aM=".to_string();
        let cert = Base64.decode(cert).unwrap();
        let cert = X509::from_der(&cert).unwrap();
        let cert = DeviceCertificate::from_x509(cert).unwrap();

        assert!(cert.public_key.len() > 0);
        assert!(cert.security_level == 1);
        assert!(cert.device_locked);
    }
}
