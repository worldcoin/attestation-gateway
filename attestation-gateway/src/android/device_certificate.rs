use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use der_parser::asn1_rs::oid;
use openssl::x509::X509;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::android::key_description::{KeyDescription, KeyDescriptionError};

#[derive(Debug)]
pub enum DeviceCertificateError {
    Base64Encoding(DecodeError),
    DerEncoding(openssl::error::ErrorStack),
    DerDecoding,
    AttestationExtraction,
    MissingAttestation,
    AttestationParsing(KeyDescriptionError),
}

pub struct DeviceCertificate {
    public_key: Vec<u8>,
    key_description: KeyDescription,
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

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());
        let key_description = KeyDescription::from_der(key_description.value.to_vec())
            .map_err(|e| DeviceCertificateError::AttestationParsing(e))?;

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

    pub fn security_level(&self) -> u32 {
        self.key_description.security_level
    }

    pub fn device_locked(&self) -> bool {
        self.key_description.device_locked
    }

    pub fn package_name(&self) -> String {
        self.key_description.package_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert1() {
        let cert = "MIICzDCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs2uoTuLKmoC+unpsOJSFI0LsJCVNBiyKiTqYDXkno+MMeYoEsoHFdecOeBmoCImbKf8bWsDAxSbGOj6JzSIsqaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDCCAXoGCisGAQQB1nkCAREEggFqMIIBZgIBAwoBAQIBBAoBAQRWYXBwLnN0YWdlLmZhY2Uud29ybGRjb2luLm9yZyE3NTRiYTQyM2FkZjNhNmQ1Y2IyZWMzNmRhOGVjZmQ0NCEyMDI2LTAyLTI2VDIxOjE3OjI0LjQ1N1oEADBav4N9AgUAv4U9CAIGAZyb0Wewv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ2wMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGhoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wCgYIKoZIzj0EAwIDRwAwRAIgRYC4+rYMqjEi7Jq6J+lRR19BmcvCzaUqwMm5butcSVUCIB8pISV0K5+guf99CAxpRGlhc52EZvC+9YiAT5UUuHUA".to_string();
        let cert = DeviceCertificate::from_base64(cert).unwrap();

        assert!(cert.public_key().len() > 0);
        assert_eq!(cert.package_name(), "com.worldcoin.dev");
    }

    #[test]
    fn test_cert2() {
        let cert = "MIIC4TCCAoegAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIGY5YWQ1ZWZhMmQ1YzcyNTYzYjA1MmVlZTA5ODFjYzk0MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5Wp9aeOVrmo0xW8TXVUGEd19KplH1C0OXmim3uXOcGvoB9ROaMghQglZC0Xolq2L0c9ugVqYMcSl2gdvCoVq0o4IBkjCCAY4wggF6BgorBgEEAdZ5AgERBIIBajCCAWYCAgEsCgECAgIBLAoBAgQubj03ZjNiMDgwMzNmMmM5YTU4YjUwMGY2ODNkMzcwNDRiYyxhdj00LjAuMTUwMAQAMHe/gxEIAgYBnR+zLY+/gxIIAgYBnR+zLY+/gxUDAgEFv4U9CAIGAZ0ffD8Sv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz0O3DEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBqqEFMQMCAQKiAwIBA6MEAgIBAKUIMQYCAQACAQSqAwIBAb+DdwIFAL+DfQIFAL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCDv4VB1RNuPTAhMMGtJQ5jxm8m8QNWQvomIL/KdoacwQb+FQQUCAwJxAL+FQgUCAwMXab+FTgYCBAE1JQW/hU8GAgQBNSUFMA4GA1UdDwEBAQQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4G52FKSBbkPnKXY6NmH4Fci/aZj/e4UhKEFxiZAdJzICIA4voKPjSTj0g3dE0tfVPELNExfUYy4kBZ7hgv70Vc+4".to_string();
        let cert = DeviceCertificate::from_base64(cert).unwrap();

        assert!(cert.public_key().len() > 0);
        assert!(cert.security_level() == 2);
        assert!(cert.device_locked() == false);

        assert_eq!(
            cert.attestation_challenge(),
            "n=7f3b08033f2c9a58b500f683d37044bc,av=4.0.1500"
        );
    }

    #[test]
    fn test_cert3() {
        let cert = "MIIC0TCCAnigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDZhMTc3MWVkMDhlZjdmZDEwYzkxZjg3OTQ0N2VmYzYzMB4XDTcwMDEwMTAwMDAwMFoXDTI2MDMyNDEzMjczMVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARd9vtCtv5j4/JSTByGmHdOVUru37iqFd/RG2W6uwiirMTrLuchwAouHLDdus84y8im9rLNhwYGhYmw8f8XcpRno4IBiTCCAYUwDgYDVR0PAQH/BAQDAgeAMIIBcQYKKwYBBAHWeQIBEQSCAWEwggFdAgEDCgEBAgEpCgEBBC5uPTZkODAxNjRlYzkxMzYyNjM2MzMyNmFlZDMyZTMyY2Q3LGF2PTQuMC4xNTAwBAAwdr+DEQgCBgGdIAdxnb+DEggCBgGdIAdxnb+DfQIFAL+FPQgCBgGdH9CDIL+FRUgERjBEMR4wHAQVY29tLndvcmxkY29pbi5zdGFnaW5nAgM9DtwxIgQgnSrXEn8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8wgaShBTEDAgECogMCAQOjBAICAQClCDEGAgEEAgEAqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDCIkVxyc1ciSAKcxGx43qpz3UeLhl1Po03ArygC+HULAEB/woBAAQgjlUrRorDAGMIoeVUyIUelNbEKGCSRNEZeXJHGmAVGhG/hUEFAgMB+9C/hUIFAgMDFwe/hU4GAgQBNP69v4VPBgIEATT+vTAKBggqhkjOPQQDAgNHADBEAiA402rjq8p2ODT2lMsXnVfRoUmoyjq/sQUiuTrkFLtcHwIgPpAd/fYw4sR0qYGBvi0sockS6wBIOAvFQIkMFqfW8aM=".to_string();
        let cert = DeviceCertificate::from_base64(cert).unwrap();

        assert!(cert.public_key().len() > 0);
        assert!(cert.security_level() == 1);
        assert!(cert.device_locked());
    }

    #[test]
    fn test_cert4() {
        let cert = "MIIC0zCCAnmgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDZkOTU5OGQzMTEwNmJjMzljNzNmYmIyMGQ5ODYzMjYyMB4XDTcwMDEwMTAwMDAwMFoXDTI2MDMyNDE2NDE0NlowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQsyiKCKz6cfg8RA0rTaahDe26/oYr01U3+rr8tG33hkwSNWrg4nHtUUS1BdOcwKfsT5xcxeeKRqSokSV6sIOYqo4IBijCCAYYwDwYDVR0PAQH/BAUDAweAADCCAXEGCisGAQQB1nkCAREEggFhMIIBXQIBBAoBAQIBKQoBAQQubj1jMWE1NWE4OTdmMzIwY2U0MDQyZmQyZTFjNWUyNTFkZSxhdj00LjAuMTUwMAQAMHa/gxEIAgYBnSC5SEi/gxIIAgYBnSC5SEi/g30CBQC/hT0IAgYBnSCCVp6/hUVIBEYwRDEeMBwEFWNvbS53b3JsZGNvaW4uc3RhZ2luZwIDPQ7cMSIEIJ0q1xJ/CZGSlxTAGVtDR4Q0UxzYt/GBNlwr1c2F40bvMIGkoQUxAwIBAqIDAgEDowQCAgEApQgxBgIBBAIBAKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgU5R0R27WvjverAO2F3+ysobDXYBsU7z+PJdVC01JS2YBAf8KAQAEIK29IS4x5RWYtfkL88V3lRoCr/wyh9KgFywa6fXNjvxlv4VBBQIDAiLgv4VCBQIDAxcQv4VOBgIEATT+wb+FTwYCBAE0FY4wCgYIKoZIzj0EAwIDSAAwRQIhAPQysvxbxakFcvOPdawb8vT3WbT41E2amu7OaKhI8ohZAiALxfXgqq/ttzw7o2V6DbjHwELeehBn9HimfQbW1mtEMA==".to_string();
        let cert = DeviceCertificate::from_base64(cert).unwrap();

        assert!(cert.public_key().len() > 0);
        assert!(cert.security_level() == 1);
        assert!(cert.device_locked());
        assert_eq!(cert.package_name(), "com.worldcoin.dev");
    }
}
