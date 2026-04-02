use der_parser::asn1_rs::oid;
use openssl::x509::X509;
use x509_parser::prelude::{FromDer, X509Certificate};

use thiserror::Error;

use crate::android::key_description::{KeyDescription, KeyDescriptionError};

#[derive(Debug, Error)]
pub enum DeviceCertificateError {
    #[error("attestation parsing: {0}")]
    AttestationParsing(#[source] KeyDescriptionError),

    #[error("der encoding error")]
    DerEncoding,

    #[error("der decoding")]
    DerDecoding,

    #[error("attestation extraction")]
    AttestationExtraction,

    #[error("missing attestation")]
    MissingAttestation,
}

pub struct DeviceCertificate {
    public_key: Vec<u8>,
    key_description: KeyDescription,
}

impl DeviceCertificate {
    pub fn from_x509(x509: &X509) -> Result<Self, DeviceCertificateError> {
        let der = x509
            .to_der()
            .map_err(|_| DeviceCertificateError::DerEncoding)?;

        Self::from_der(&der)
    }

    pub fn from_der(der: &Vec<u8>) -> Result<Self, DeviceCertificateError> {
        let (_, cert) =
            X509Certificate::from_der(&der).map_err(|_| DeviceCertificateError::DerDecoding)?;

        let key_description = cert
            .get_extension_unique(&oid!(1.3.6.1.4.1.11129.2.1.17))
            .map_err(|_| DeviceCertificateError::AttestationExtraction)?
            .ok_or(DeviceCertificateError::MissingAttestation)?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());
        let key_description = KeyDescription::from_der(&key_description.value)
            .map_err(DeviceCertificateError::AttestationParsing)?;

        Ok(Self {
            public_key,
            key_description,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn attestation_challenge(&self) -> String {
        self.key_description.attestation_challenge.clone()
    }

    pub const fn attestation_security_level(&self) -> u32 {
        self.key_description.attestation_security_level
    }

    pub const fn key_mint_security_level(&self) -> u32 {
        self.key_description.key_mint_security_level
    }

    pub const fn os_patch_level(&self) -> Option<u32> {
        self.key_description.os_patch_level
    }

    pub const fn device_locked(&self) -> Option<bool> {
        self.key_description.device_locked
    }

    pub const fn verified_boot_state(&self) -> Option<u32> {
        self.key_description.verified_boot_state
    }

    pub const fn key_origin(&self) -> Option<u64> {
        self.key_description.key_origin
    }

    pub fn attestation_signature_digests(&self) -> Option<&[Vec<u8>]> {
        self.key_description
            .attestation_signature_digests
            .as_deref()
    }

    pub fn package_name(&self) -> Option<&str> {
        self.key_description.package_name.as_deref()
    }
}

impl DeviceCertificateError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::DerEncoding => "der_encoding".to_string(),
            Self::DerDecoding => "der_decoding".to_string(),
            Self::AttestationExtraction => "attestation_extraction".to_string(),
            Self::MissingAttestation => "missing_attestation".to_string(),
            Self::AttestationParsing(e) => {
                format!("attestation_parsing_{}", e.reason_tag())
            }
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::AttestationParsing(e) => e.is_internal_error(),
            Self::DerEncoding | Self::DerDecoding => true,
            Self::AttestationExtraction | Self::MissingAttestation => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD as Base64};
    use chrono::{DateTime, Datelike, Utc};
    use std::time::{Duration, SystemTime};

    use super::*;

    fn cert_from_test_b64(b64: &str) -> DeviceCertificate {
        let der = Base64.decode(b64).expect("test fixture base64");
        DeviceCertificate::from_der(&der).expect("test fixture cert DER")
    }

    #[test]
    fn test_cert1() {
        let cert = cert_from_test_b64(
            "MIICzDCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs2uoTuLKmoC+unpsOJSFI0LsJCVNBiyKiTqYDXkno+MMeYoEsoHFdecOeBmoCImbKf8bWsDAxSbGOj6JzSIsqaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDCCAXoGCisGAQQB1nkCAREEggFqMIIBZgIBAwoBAQIBBAoBAQRWYXBwLnN0YWdlLmZhY2Uud29ybGRjb2luLm9yZyE3NTRiYTQyM2FkZjNhNmQ1Y2IyZWMzNmRhOGVjZmQ0NCEyMDI2LTAyLTI2VDIxOjE3OjI0LjQ1N1oEADBav4N9AgUAv4U9CAIGAZyb0Wewv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ2wMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGhoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wCgYIKoZIzj0EAwIDRwAwRAIgRYC4+rYMqjEi7Jq6J+lRR19BmcvCzaUqwMm5butcSVUCIB8pISV0K5+guf99CAxpRGlhc52EZvC+9YiAT5UUuHUA",
        );

        assert!(cert.public_key().len() > 0);
        assert_eq!(cert.package_name(), Some("com.worldcoin.dev"));
    }

    #[test]
    fn test_cert2() {
        let cert = cert_from_test_b64(
            "MIIC4TCCAoegAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIGY5YWQ1ZWZhMmQ1YzcyNTYzYjA1MmVlZTA5ODFjYzk0MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5Wp9aeOVrmo0xW8TXVUGEd19KplH1C0OXmim3uXOcGvoB9ROaMghQglZC0Xolq2L0c9ugVqYMcSl2gdvCoVq0o4IBkjCCAY4wggF6BgorBgEEAdZ5AgERBIIBajCCAWYCAgEsCgECAgIBLAoBAgQubj03ZjNiMDgwMzNmMmM5YTU4YjUwMGY2ODNkMzcwNDRiYyxhdj00LjAuMTUwMAQAMHe/gxEIAgYBnR+zLY+/gxIIAgYBnR+zLY+/gxUDAgEFv4U9CAIGAZ0ffD8Sv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz0O3DEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBqqEFMQMCAQKiAwIBA6MEAgIBAKUIMQYCAQACAQSqAwIBAb+DdwIFAL+DfQIFAL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCDv4VB1RNuPTAhMMGtJQ5jxm8m8QNWQvomIL/KdoacwQb+FQQUCAwJxAL+FQgUCAwMXab+FTgYCBAE1JQW/hU8GAgQBNSUFMA4GA1UdDwEBAQQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4G52FKSBbkPnKXY6NmH4Fci/aZj/e4UhKEFxiZAdJzICIA4voKPjSTj0g3dE0tfVPELNExfUYy4kBZ7hgv70Vc+4",
        );

        assert!(cert.public_key().len() > 0);
        assert!(cert.attestation_security_level() == 2);
        assert_eq!(cert.device_locked(), Some(false));

        assert_eq!(
            cert.attestation_challenge(),
            "n=7f3b08033f2c9a58b500f683d37044bc,av=4.0.1500"
        );
    }

    #[test]
    fn test_cert3() {
        let cert = cert_from_test_b64(
            "MIIC0TCCAnigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDZhMTc3MWVkMDhlZjdmZDEwYzkxZjg3OTQ0N2VmYzYzMB4XDTcwMDEwMTAwMDAwMFoXDTI2MDMyNDEzMjczMVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARd9vtCtv5j4/JSTByGmHdOVUru37iqFd/RG2W6uwiirMTrLuchwAouHLDdus84y8im9rLNhwYGhYmw8f8XcpRno4IBiTCCAYUwDgYDVR0PAQH/BAQDAgeAMIIBcQYKKwYBBAHWeQIBEQSCAWEwggFdAgEDCgEBAgEpCgEBBC5uPTZkODAxNjRlYzkxMzYyNjM2MzMyNmFlZDMyZTMyY2Q3LGF2PTQuMC4xNTAwBAAwdr+DEQgCBgGdIAdxnb+DEggCBgGdIAdxnb+DfQIFAL+FPQgCBgGdH9CDIL+FRUgERjBEMR4wHAQVY29tLndvcmxkY29pbi5zdGFnaW5nAgM9DtwxIgQgnSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8wgaShBTEDAgECogMCAQOjBAICAQClCDEGAgEEAgEAqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDCIkVxyc1ciSAKcxGx43qpz3UeLhl1Po03ArygC+HULAEB/woBAAQgjlUrRorDAGMIoeVUyIUelNbEKGCSRNEZeXJHGmAVGhG/hUEFAgMB+9C/hUIFAgMDFwe/hU4GAgQBNP69v4VPBgIEATT+vTAKBggqhkjOPQQDAgNHADBEAiA402rjq8p2ODT2lMsXnVfRoUmoyjq/sQUiuTrkFLtcHwIgPpAd/fYw4sR0qYGBvi0sockS6wBIOAvFQIkMFqfW8aM=",
        );

        assert!(cert.public_key().len() > 0);
        assert!(cert.attestation_security_level() == 1);
        assert_eq!(cert.device_locked(), Some(true));
        assert_eq!(cert.os_patch_level(), Some(202503));

        let year_ago = DateTime::<Utc>::from(SystemTime::now() - Duration::from_hours(24 * 365));
        let min_os_patch_level = year_ago.year() as u64 * 100 + year_ago.month() as u64;
        assert_eq!(min_os_patch_level, 202503);
    }

    #[test]
    fn test_cert4() {
        let cert = cert_from_test_b64(
            "MIIC0zCCAnmgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDZkOTU5OGQzMTEwNmJjMzljNzNmYmIyMGQ5ODYzMjYyMB4XDTcwMDEwMTAwMDAwMFoXDTI2MDMyNDE2NDE0NlowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQsyiKCKz6cfg8RA0rTaahDe26/oYr01U3+rr8tG33hkwSNWrg4nHtUUS1BdOcwKfsT5xcxeeKRqSokSV6sIOYqo4IBijCCAYYwDwYDVR0PAQH/BAUDAweAADCCAXEGCisGAQQB1nkCAREEggFhMIIBXQIBBAoBAQIBKQoBAQQubj1jMWE1NWE4OTdmMzIwY2U0MDQyZmQyZTFjNWUyNTFkZSxhdj00LjAuMTUwMAQAMHa/gxEIAgYBnSC5SEi/gxIIAgYBnSC5SEi/g30CBQC/hT0IAgYBnSCCVp6/hUVIBEYwRDEeMBwEFWNvbS53b3JsZGNvaW4uc3RhZ2luZwIDPQ7cMSIEIJ0q1xJ/CZGSlxTAGVtDR4Q0UxzYt/GBNlwr1c2F40bvMIGkoQUxAwIBAqIDAgEDowQCAgEApQgxBgIBBAIBAKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgU5R0R27WvjverAO2F3+ysobDXYBsU7z+PJdVC01JS2YBAf8KAQAEIK29IS4x5RWYtfkL88V3lRoCr/wyh9KgFywa6fXNjvxlv4VBBQIDAiLgv4VCBQIDAxcQv4VOBgIEATT+wb+FTwYCBAE0FY4wCgYIKoZIzj0EAwIDSAAwRQIhAPQysvxbxakFcvOPdawb8vT3WbT41E2amu7OaKhI8ohZAiALxfXgqq/ttzw7o2V6DbjHwELeehBn9HimfQbW1mtEMA==",
        );

        assert!(cert.public_key().len() > 0);
        assert!(cert.attestation_security_level() == 1);
        assert_eq!(cert.device_locked(), Some(true));
    }

    #[test]
    fn test_cert5() {
        let cert = cert_from_test_b64(
            "MIICzDCCAnCgAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDkwZThkYTNjYWRmYzc4MjAxEjAQBgNVBAwMCVN0cm9uZ0JveDAiGA8yMDI2MDMzMTIyNTcyMloYDzIwMjYwMzMxMjMwMjIxWjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDmi1ln2wwjVMcKGc16gOHEt4EcxWs05S8N3w9F2SpqcRelwptbs8tXFLcL7/F/SdDMJyyAjzit3s9QfnMWF0XyjggGFMIIBgTAOBgNVHQ8BAf8EBAMCB4AwggFtBgorBgEEAdZ5AgERBIIBXTCCAVkCAQQKAQICASkKAQIELm49YzA4ODUzOGRiZDI5MDY5MzVhMmJiZjdlZGZiYWI5ZDksYXY9NC4wLjE3MDAEADByv4MRCAIGAZ1GIjmzv4MSCAIGAZ1GIjmzv4N9AgUAv4U9CAIGAZ1GHamnv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ+kMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGkoQUxAwIBAqIDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wDAYIKoZIzj0EAwIFAANIADBFAiAJlkz/YHoZ57QXdrALWaYC6iDSFcmDQuUgLmak8tbPdQIhAP4u/IWmIUhU1bnaw9GSDJrzuANWQyVSdvM8J3e1dwTg",
        );

        assert_eq!(cert.os_patch_level(), Some(202110));
    }

    #[test]
    fn test_cert6() {
        let cert = cert_from_test_b64(
            "MIIC3TCCAoOgAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIDM3ZTcyNWY4YmQyZjM3NDVlNGY4ZDQ5ZDI3YTA4NTY0MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATV8cbFM6o8spqil2myOoZOcvsYH/21LPY3isNtdF+HlkaeK1wSegCbvZ6dbwqFImYzDVg0ytJ4CdJ8d4QPWhHEo4IBjjCCAYowDgYDVR0PAQH/BAQDAgeAMIIBdgYKKwYBBAHWeQIBEQSCAWYwggFiAgIBLAoBAgICASwKAQIELm49MDY5ZjQwM2E1YzdmMWRhZjA2NDk0M2RmNTRhYjZjNWYsYXY9NC4wLjE3MDAEADBzv4MRCAIGAZ1GQFm2v4MSCAIGAZ1GQFm2v4MVAwIBBb+FPQgCBgGdRjvNm7+FRUQEQjBAMRowGAQRY29tLndvcmxkY29pbi5kZXYCAz0PpDEiBCCjQW7f3KquzF5ZK5yqB7t47MbzGuxECfScptO03/Hb4DCBqqEFMQMCAQKiAwIBA6MEAgIBAKUIMQYCAQACAQSqAwIBAb+DdwIFAL+DfQIFAL+FPgMCAQC/hUBMMEoEICRLqveND+5VWlYv3T9w72EDZJL7p60ZK4O7jUJ+OAsXAQH/CgEABCAzPZyXG5X9sB5Q9g++McauXyjEMQyKBPGY9pFkdbL6rb+FQQUCAwJxAL+FQgUCAwMXa7+FTgYCBAE1JdG/hU8GAgQBNSXRMAoGCCqGSM49BAMCA0gAMEUCICwLmWvsIR6CDhssiJ6ONnYmejo7auLThnMAeeuGign0AiEAjt0WHgoPTdJPhpEHtbIjzcgziiciZGMPNn2KJ0k6Obo=",
        );

        assert_eq!(cert.os_patch_level(), Some(202603));
    }
}
