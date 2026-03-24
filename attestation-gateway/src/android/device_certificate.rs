use der_parser::asn1_rs::oid;
use openssl::x509::X509;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Android KeyMint `KeyDescription` (`AuthorizationList` in certificate extension).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct KeyDescription<'a> {
    pub attestation_version: u64,
    pub attestation_security_level: asn1::Enumerated,
    pub key_mint_version: u64,
    pub key_mint_security_level: asn1::Enumerated,
    pub attestation_challenge: &'a [u8],
    pub unique_id: &'a [u8],
    pub software_enforced: AuthorizationList<'a>,
    pub hardware_enforced: AuthorizationList<'a>,
}

/// Authorization tags for key attestation (`AuthorizationList` in ASN.1).
///
/// Fields follow ASN.1 tag order (required for correct DER parsing).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AuthorizationList<'a> {
    #[explicit(1)]
    pub purpose: Option<asn1::SetOf<'a, u64>>,
    #[explicit(2)]
    pub algorithm: Option<u64>,
    #[explicit(3)]
    pub key_size: Option<u64>,
    #[explicit(4)]
    pub block_mode: Option<asn1::SetOf<'a, u64>>,
    #[explicit(5)]
    pub digest: Option<asn1::SetOf<'a, u64>>,
    #[explicit(6)]
    pub padding: Option<asn1::SetOf<'a, u64>>,
    #[explicit(7)]
    pub caller_nonce: Option<asn1::Null>,
    #[explicit(8)]
    pub min_mac_length: Option<u64>,
    #[explicit(10)]
    pub ec_curve: Option<u64>,
    #[explicit(200)]
    pub rsa_public_exponent: Option<u64>,
    #[explicit(203)]
    pub mgf_digest: Option<asn1::SetOf<'a, u64>>,
    #[explicit(303)]
    pub rollback_resistance: Option<asn1::Null>,
    #[explicit(305)]
    pub early_boot_only: Option<asn1::Null>,
    #[explicit(400)]
    pub active_date_time: Option<u64>,
    #[explicit(401)]
    pub origination_expire_date_time: Option<u64>,
    #[explicit(402)]
    pub usage_expire_date_time: Option<u64>,
    #[explicit(405)]
    pub usage_count_limit: Option<u64>,
    #[explicit(502)]
    pub user_secure_id: Option<u64>,
    #[explicit(503)]
    pub no_auth_required: Option<asn1::Null>,
    #[explicit(504)]
    pub user_auth_type: Option<u64>,
    #[explicit(505)]
    pub auth_timeout: Option<u64>,
    #[explicit(506)]
    pub allow_while_on_body: Option<asn1::Null>,
    #[explicit(507)]
    pub trusted_user_presence_req: Option<asn1::Null>,
    #[explicit(508)]
    pub trusted_confirmation_req: Option<asn1::Null>,
    #[explicit(509)]
    pub unlocked_device_req: Option<asn1::Null>,
    #[explicit(701)]
    pub creation_date_time: Option<u64>,
    #[explicit(702)]
    pub origin: Option<u64>,
    #[explicit(704)]
    pub root_of_trust: Option<RootOfTrust<'a>>,
    #[explicit(705)]
    pub os_version: Option<u64>,
    #[explicit(706)]
    pub os_patch_level: Option<u64>,
    #[explicit(709)]
    pub attestation_application_id: Option<&'a [u8]>,
    #[explicit(710)]
    pub attestation_id_brand: Option<&'a [u8]>,
    #[explicit(711)]
    pub attestation_id_device: Option<&'a [u8]>,
    #[explicit(712)]
    pub attestation_id_product: Option<&'a [u8]>,
    #[explicit(713)]
    pub attestation_id_serial: Option<&'a [u8]>,
    #[explicit(714)]
    pub attestation_id_imei: Option<&'a [u8]>,
    #[explicit(715)]
    pub attestation_id_meid: Option<&'a [u8]>,
    #[explicit(716)]
    pub attestation_id_manufacturer: Option<&'a [u8]>,
    #[explicit(717)]
    pub attestation_id_model: Option<&'a [u8]>,
    #[explicit(718)]
    pub vendor_patch_level: Option<u64>,
    #[explicit(719)]
    pub boot_patch_level: Option<u64>,
    #[explicit(720)]
    pub device_unique_attestation: Option<asn1::Null>,
    #[explicit(723)]
    pub attestation_id_second_imei: Option<&'a [u8]>,
    #[explicit(724)]
    pub module_hash: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
pub struct RootOfTrust<'a> {
    pub verified_boot_key: &'a [u8],
    pub device_locked: bool,
    pub verified_boot_state: asn1::Enumerated,
    pub verified_boot_hash: &'a [u8],
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, Clone, PartialEq, Eq)]
pub struct Module<'a> {
    pub package_name: &'a [u8],
    pub version: u64,
}

/// ASN.1 `Modules ::= SET OF Module`.
pub type Modules<'a> = asn1::SetOf<'a, Module<'a>>;

#[derive(Debug)]
pub enum DeviceCertificateError {
    InternalEncodeDer(openssl::error::ErrorStack),
    InternalDecodeDer,
    MissingAttestationExtension,
    InvalidAttestationExtension,
}

pub struct DeviceCertificate {
    pub public_key: Vec<u8>,
    pub security_level: u32,
    pub device_locked: bool,
}

impl DeviceCertificate {
    pub fn new(x509: X509) -> Result<Self, DeviceCertificateError> {
        let der = x509
            .to_der()
            .map_err(|e| DeviceCertificateError::InternalEncodeDer(e))?;

        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|_| DeviceCertificateError::InternalDecodeDer)?;

        let key_description = cert
            .get_extension_unique(&oid!(1.3.6.1.4.1.11129.2.1.17))
            .map_err(|_| DeviceCertificateError::InvalidAttestationExtension)?
            .ok_or(DeviceCertificateError::MissingAttestationExtension)?;

        let key_description = asn1::parse_single::<KeyDescription>(key_description.value)
            .map_err(|_| DeviceCertificateError::InvalidAttestationExtension)?;

        let public_key = Vec::from(cert.public_key().subject_public_key.data.clone());
        let security_level = key_description.attestation_security_level.value();
        let device_locked = match &key_description.hardware_enforced.root_of_trust {
            Some(root_of_trust) => root_of_trust.device_locked,
            None => false,
        };

        Ok(Self {
            public_key,
            security_level,
            device_locked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as Base64};

    #[test]
    fn test_pablo_cert1() {
        let cert = "MIICzDCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs2uoTuLKmoC+unpsOJSFI0LsJCVNBiyKiTqYDXkno+MMeYoEsoHFdecOeBmoCImbKf8bWsDAxSbGOj6JzSIsqaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDCCAXoGCisGAQQB1nkCAREEggFqMIIBZgIBAwoBAQIBBAoBAQRWYXBwLnN0YWdlLmZhY2Uud29ybGRjb2luLm9yZyE3NTRiYTQyM2FkZjNhNmQ1Y2IyZWMzNmRhOGVjZmQ0NCEyMDI2LTAyLTI2VDIxOjE3OjI0LjQ1N1oEADBav4N9AgUAv4U9CAIGAZyb0Wewv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ2wMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGhoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wCgYIKoZIzj0EAwIDRwAwRAIgRYC4+rYMqjEi7Jq6J+lRR19BmcvCzaUqwMm5butcSVUCIB8pISV0K5+guf99CAxpRGlhc52EZvC+9YiAT5UUuHUA".to_string();
        let cert = Base64.decode(cert).unwrap();
        let cert = X509::from_der(&cert).unwrap();
        let cert = DeviceCertificate::new(cert).unwrap();

        assert!(cert.public_key.len() > 0);
    }

    #[test]
    fn test_rooted_cert1() {
        let cert = "MIIC4TCCAoegAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIGY5YWQ1ZWZhMmQ1YzcyNTYzYjA1MmVlZTA5ODFjYzk0MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5Wp9aeOVrmo0xW8TXVUGEd19KplH1C0OXmim3uXOcGvoB9ROaMghQglZC0Xolq2L0c9ugVqYMcSl2gdvCoVq0o4IBkjCCAY4wggF6BgorBgEEAdZ5AgERBIIBajCCAWYCAgEsCgECAgIBLAoBAgQubj03ZjNiMDgwMzNmMmM5YTU4YjUwMGY2ODNkMzcwNDRiYyxhdj00LjAuMTUwMAQAMHe/gxEIAgYBnR+zLY+/gxIIAgYBnR+zLY+/gxUDAgEFv4U9CAIGAZ0ffD8Sv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz0O3DEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBqqEFMQMCAQKiAwIBA6MEAgIBAKUIMQYCAQACAQSqAwIBAb+DdwIFAL+DfQIFAL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCDv4VB1RNuPTAhMMGtJQ5jxm8m8QNWQvomIL/KdoacwQb+FQQUCAwJxAL+FQgUCAwMXab+FTgYCBAE1JQW/hU8GAgQBNSUFMA4GA1UdDwEBAQQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4G52FKSBbkPnKXY6NmH4Fci/aZj/e4UhKEFxiZAdJzICIA4voKPjSTj0g3dE0tfVPELNExfUYy4kBZ7hgv70Vc+4".to_string();
        let cert = Base64.decode(cert).unwrap();
        let cert = X509::from_der(&cert).unwrap();
        let cert = DeviceCertificate::new(cert).unwrap();

        assert!(cert.public_key.len() > 0);
    }
}
