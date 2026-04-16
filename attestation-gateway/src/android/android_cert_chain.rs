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

const NID_SERIAL_NUMBER: i32 = 105;

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

    #[error("issued to decoding error")]
    IssuedToDecoding,
}

/// ASN.1 serial number in the two string forms used as keys in Google's attestation status JSON.
#[derive(Debug, Clone)]
pub struct CertificateSerial {
    /// Certificate issued to contains serial number too
    pub issued_to: Vec<String>,
    /// Decimal digits (e.g. `"6681152659205225093"`).
    pub decimal: String,
    /// Lowercase hex without `0x` (e.g. `"c35747a084470c3135aeefe2b8d40cd6"`).
    pub hex: String,
}

impl CertificateSerial {
    /// `true` if either representation appears in [`AndroidRevocationList`].
    #[must_use]
    pub fn is_revoked(&self, list: &AndroidRevocationList) -> bool {
        if list.is_revoked(&self.decimal) {
            return true;
        }

        if list.is_revoked(&self.hex) {
            return true;
        }

        for issued_to in self.issued_to.iter() {
            if list.is_revoked(issued_to) {
                return true;
            }
        }

        false
    }
}

pub struct AndroidCertChain {
    device_certificate: DeviceCertificate,
    root_certificate: RootCertificate,
    /// Per-certificate serials (leaf → root) for Android attestation status lookup.
    serials: Vec<CertificateSerial>,
}

impl AndroidCertChain {
    pub fn from_base64(base64_cert_chain: &[String]) -> Result<Self, AndroidCertChainError> {
        let der_cert_chain = base64_cert_chain
            .iter()
            .map(|c| Base64.decode(c))
            .collect::<Result<Vec<Vec<u8>>, DecodeError>>()
            .map_err(AndroidCertChainError::Base64Encoding)?;

        Self::from_der(&der_cert_chain)
    }

    pub fn from_der(der_cert_chain: &[Vec<u8>]) -> Result<Self, AndroidCertChainError> {
        let cert_chain = der_cert_chain
            .iter()
            .map(|c| X509::from_der(c))
            .collect::<Result<Vec<X509>, openssl::error::ErrorStack>>()
            .map_err(|_| AndroidCertChainError::DerEncoding)?;

        Self::from_x509(&cert_chain)
    }

    pub fn from_x509(cert_chain: &[X509]) -> Result<Self, AndroidCertChainError> {
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

        let device_certificate = DeviceCertificate::from_x509(device_cert)
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

    let issued_to = cert
        .subject_name()
        .entries()
        .filter(|e| e.object().nid().as_raw() == NID_SERIAL_NUMBER)
        .map(|e| e.data().as_utf8().map(|v| String::from(&**v)))
        .collect::<Result<Vec<String>, openssl::error::ErrorStack>>()
        .map_err(|_| AndroidCertChainError::IssuedToDecoding)?;

    Ok(CertificateSerial {
        issued_to,
        decimal,
        hex,
    })
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
            Self::IssuedToDecoding => "issued_to_decoding".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::DeviceCertificate(e) => e.is_internal_error(),
            Self::RootCertificate(e) => e.is_internal_error(),
            Self::Base64Encoding(_)
            | Self::DerEncoding
            | Self::ChainLength
            | Self::ChainVerification(_)
            | Self::IssuedToDecoding => false,
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

mod tests {
    use super::*;

    #[test]
    fn test_certificate_serials() {
        let cert_chain = AndroidCertChain::from_base64(&[
            "MIICtTCCAlqgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDFhMGI5NTJlZDU3NTk3NzA0MmZhY2Y0YTllZjhiZWJiMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATOaK7SdXelxBrY2Lw007j3iYWforwDzCJhfPf0CDuKxkjXpNNm1Gv1kTBg2+SZdqJiJT+mk3teNBN9qO0UADC4o4IBazCCAWcwDgYDVR0PAQH/BAQDAgeAMIIBUwYKKwYBBAHWeQIBEQSCAUMwggE/AgIBLAoBAQICASwKAQEELm49MzEyMzRkNGQ2MWFmZjkzMDNkNTM1Y2M0MzQzY2IzY2EsYXY9NC4wLjE3MDAEADBYv4U9CAIGAZ2V8f9Kv4VFSARGMEQxHjAcBBVjb20ud29ybGRjb2luLnN0YWdpbmcCAz1LaDEiBCCdKtcSfwmRkpcUwBlbQ0eENFMc2LfxgTZcK9XNheNG7zCBoqEIMQYCAQICAQOiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DdwIFAL+FPgMCAQC/hUBMMEoEINrfKLR2YgdkoI97pfNa3LZ2A4FMqQ/Sqgze41Cq9jOBAQH/CgEABCDpEX7xUYmS0qsrrJuUnkv2oW+g7PD6EXhmUVsII09egb+FQQUCAwJJ8L+FQgUCAwMXbL+FTgUCAwMXbL+FTwUCAwMXbDAKBggqhkjOPQQDAgNJADBGAiEA1iynKSSDLMc9ZzDVg2E2tk3S6iemUDfoBL9iKzNL1I0CIQDT1c5JrYWaGHABO+gPhUzBDtHpebCsbSzxrPwB0liMWA==".to_string(),
            "MIIB8zCCAXmgAwIBAgIQf6UuX5jz1kvUeVrclnoTSzAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDdiNGQyYTVkNWZlZDA1NmJmNzQ2Y2I5MTA0OTg5NzlkMB4XDTI0MDcxMjIxMjIxMloXDTM0MDcxMDIxMjIxMlowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyAxYTBiOTUyZWQ1NzU5NzcwNDJmYWNmNGE5ZWY4YmViYjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBaJUWqFCV2C0vY4T+ctGt1WbNADW7P8jPTzlWQdmEz2a8w4UtVV0/i2p35JNh05YS7NxTJA5fSFl6z8mYl58X2jYzBhMB0GA1UdDgQWBBSqPh2bIMxi+PZZGGb4SCZD1YoBPTAfBgNVHSMEGDAWgBQpQX2gXexPcdCVGxeSxuRDIpWslzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNoADBlAjEAgGDseOQwBOjecJlcXNFJk/NN3tG+eG1/RFRd+CiCrUcIyOpPxfKYbdSrcnsVCFxSAjBl8CJSpGY2Z891vF3GUdxVNP+MXM6LRiVDUIzJ9sFL7rJ16koZW//NYz852BQW2aw=".to_string(),
            "MIIDkzCCAXugAwIBAgIQLWsPsr9I11TqphKlbJtWgDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTI0MDcxMjIxMjA1NFoXDTM0MDcxMDIxMjA1NFowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA3YjRkMmE1ZDVmZWQwNTZiZjc0NmNiOTEwNDk4OTc5ZDB2MBAGByqGSM49AgEGBSuBBAAiA2IABEznL3Uv+p94TRmMSh5ZNamHXYjG82WOo/V87teAJ6gQPRpAdFmg2Rb9O7o/L+mrEFHtzcDObojdnFnt53bDIXqFZhHgny4Cs+vymVKeLeHL4TIPTVgppUVCE96mphTuv6NjMGEwHQYDVR0OBBYEFClBfaBd7E9x0JUbF5LG5EMilayXMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQCgbCrE+O9PLZOIeox7dzzufxtGiWOn5FY8LfGT+tpONdqvOdm+ML3RHiNXuor85OjjWV8zeaWWJulnBjbQsmDUlGZPVnD5PqlGnwD/Tc/NifBBEhEqcspuiS7TRZTECG/gWCIUUlXwra4+xy7YyszmwE6pEEol35W8uYA5NqGd6olwk6kqxZyHKpfuugV0dhlGNZ1YH7k9HGH4PDPba7CZk5I4xO2SXbHwqYjBUjplaCCKJ1BY7il4zP8tkejehYpgVwFP2VxkbgnviTRawyzaRPa2t0Oq+tN6/hGk8ZcwhwsSOHiZe/lUCuepir006CzR7iKn+j07xT79UDaYt4YYSl3qhWRXEs6vL7zw8IGDKSbCvFQkCLW0uXZsqg2bsLS4PJJrD4K8pBQGMOppRoYocGgy0XGOy8KCGrM3jK14sLFnH+7W6K1qS0bXt/lLc36r+MZ76H9I2RtiY++4FUDFawHNeq1KvjAO6gdxdyGmkSJzFHPY7Hn7KDQgx2/XeSBQ44ZYh0cD9h+6lELTuLqyyMXr0LqPCQ8vruiLX6+5wV+eDouSfcJNjt7ICtAv0DA3z47lGBNF5GbX7BYk1FI93xu2R5j1+ZDlXO42FrRcL27Cew/YhUHTTS9qfBywf1NDfbx1JQgqOdhUeb5ALtXae7HOnkersCx+yJA4QsCqzg==".to_string(),
            "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgwNzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGICW/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2GtkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkxoSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mFmr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPzlHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVwn6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1EuzbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHovaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHnw1IdYIg2Wxg7yHcQZemFQg==".to_string(),
            "MIIE3zCCAsegAwIBAgIQcmHwBmqmW97Kqycq6CZDwzANBgkqhkiG9w0BAQsFADA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDdiNGQyYTVkNWZlZDA1NmJmNzQ2Y2I5MTA0OTg5NzlkMB4XDTI0MDcxMjIxMjIxMVoXDTM0MDcxMDIxMjIxMVowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyAxYTBiOTUyZWQ1NzU5NzcwNDJmYWNmNGE5ZWY4YmViYjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKtrPvRn8u/M28vqpTZIyLmMXpKrK1uf8b0GL2StCinr9JpeqU2vsYSSGnqBwyQ21P/sX0ohcx8iw+8keCnF3AdQnXS76Y+xChg9a7U9/KkE49wJBaiaBG9ZCKDxs5MVpuSKH6gGBvEjsKoosDLCiU0vWDkcq5cTog73I+NFFG4mvBT9m+xoYTnk/eclDSGmIcLYsYrVp3330W4s5T1DtSInLO56eZWVhfq2UxBq0kUYk79xsEFHARsikZGOS1XMG9/UFKGPPVR+npr2w4Zm6zgbznHOUXDi9+JHAq+02MkIsq1aGG7h5QDemRPpTe/COAkYJttg6Bmn3+onCZnVmipUrcd2YGTakNVxGmnlgV6EnqeIQQvWj9czr0ZsY2Y6VLx3mZ6udUPexM18qXg3IBtdlmISAeYefDgaPDK180SkQt945SazsCafqMZRVlW9cyXnVDdbCvCrNi4oZcw9liSsEwDUp2EoE7T7rTR2nZs4CQieXfdYKjlu2gw/b6hEHwIDAQABo2MwYTAdBgNVHQ4EFgQUO7PNkiD78zv+R5fibHyGc7LSPJ0wHwYDVR0jBBgwFoAUXzSzsTc0SkRl7NbzmVIeBpIxOEMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggIBABZvIP9OLJZ2cdAqgzSzYI94c5JwfKRMFE5gfpettZRGxx2HH+RKOcgxS6RV+JYUOf37kk79GuiG1QQXaHRItDyHCbQzfcF4Z8K3uW/EqAYD+8pMYv/m3ywzM4M+Ff8qkYQQMgY7XcVisn3F7sag5WTRhqFOsU/aF2kWhfuQUEiei03vrWQeZh6XPBjB6kAWc+xt+E7g3KNvi68WbwBnlGZnTasK4iVZ2/75WpPTC3PRHICS6arFZAgg7RLzINUxl8Nz9IGmNmKGQnlA47bNITd3hgP23F83qMTYM5qow2fgLgjyUXx10JgsAjLBKph8PAHZTavXScOrIcMEpHqb3j0aCxgladi8wLj8p0BMzTVYE+PDI3yFxtVvc7Xr0aKH0zAzwyOhWpJo7ubaJ1yZJ8uAVZxVbdM6dDrmRDaML5v86ANV/eW23MMFzui/8xYjIUmktGRbrPk1NEelkiFDa3rCSK9KX79lmkYbJWprPPTGA/ULo7cn6NnpRj6gQ5PaxsWSAEAFCyKgbQqKwslaWfcr6P8PwQAecnuHMJlHuKob6UfgFqdyc/c/v/PHuK+t3/OCXwVjC2fBRlmSFCSqFUmWOyH0WldJi1ab2FyRDFAu/A4UrJiHOd2zr3r569a+SqnkujWBwjg6kMoUUbWCEknr7AzVckJBGdGFXynA4jEB".to_string(),
            "MIIFQjCCAyqgAwIBAgIRALao9a7g7mkpyPAAvWkq6rcwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEBRMQZjkyMDA5ZTg1M2I2YjA0NTAeFw0yNDA3MTIyMTIwMzdaFw0zNDA3MTAyMTIwMzdaMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgN2I0ZDJhNWQ1ZmVkMDU2YmY3NDZjYjkxMDQ5ODk3OWQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCodLLALoxABfA0a0l62gfXMGicxvU7A/OJO6z3cPamONyaxVpAWYDcogwhkPh0gS271E6NdBFN1GiB1HgY/aqKpvl90h8gPzXypZRquFeh3X9WTNqR98hujEiCmyfCDuLV8pBoCYhOhjqIZIfz2hCuAgCN1Wi+DDiqn+D/+ZL1qDl1fmJSSFjww0HRnyfSkpWtazp5lvVgaOgha2drw4O+w4JB+8WK2ooq/IsVcZHjDg9dzEy/8AO6y7ZN6+/6p47xTMuuuSuBTVcamaVhO5djhj8BjQlztTvbePNYMfLFepi7AQjZp3WBR9QXCfK+rQrjiVJSAaFEwYStNsWViK0MU+0iY/ZWQMCBZvsAw/lq1SLgHztQh7QkoVQ6e9tTxdmJK7QNwHWieM4uLX7Vs0Gaj3ZO+HqMffPJNKHTGPm3LlwtGCUbTVcYVlPnWktPBeh5odb9tHxCcF2sZhI5sYP6fDgg0JWFYrQXZd2grAAHDNzqgV/RdtODvh8J+HaoF2TmXpGLOVZa7OMu4n63fQZSgPbIXsfCpc/Ow54dZ8ZXE8KtRZgjNns+tnqi8Wo2yFiG3/KpSUOquuJ/VAynzFqqdmYYeI0qdT7AepFFmzpo/elh4WAnnaRffZIoyytdlwshmFRYwRYGOLIF/a+JKXBfpTQBuc/NizAHk45keKQ+mwIDAQABo2MwYTAdBgNVHQ4EFgQUXzSzsTc0SkRl7NbzmVIeBpIxOEMwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggIBAENTTEEFHz7y3FW+aMkqTU5sAW8IhzjJJWn+NJDQr3m3ZvnA0YOrhjFghmmcQ2GOn0x1c1cSypU4WAc8rFUaM/osK7J/aQ75sMrIPnWIrWJEWo6xGcLZqPLxnTBVA27wTN+DR6Vz7B/BKBs/z4ymeJ/Gy3mLx7L2BgxAVrSdnm9tkth5Vx+BR6i3RcBfVVeYb2jLRMujy5KKo63ze8Bs/ZtXZsvKw6izXCnhu4FKC/4crGIV3GSOD9AJxk2HqVf1lESzo96VdwKd22Gu5Lwmpq+TQiVcIl8aFmwzX80S3dOG1xTMWFzBoJIdJ20xNihSY1NZeGtVeVSpKAtN95luwDIB3ATEJqVB4yDjbsEAMl5P0PNjvzK7ilsu+K1OWbuFslp/HXNrbSaBLKovsDr/i5vKYQg6aRloRsj8tHwuc4W8RGoKPKdOgGrXaCyQrXiiNfUy0ctWLtxf2p7NlJWheDG0CppN/t9olhDMA3TQWTP6nIrqym7YDXhUrHKRSfchUO+oLfO2Gf2vOM+ncppN43/dAWf2/XKA83BLQ2dDcpYk/wCS8hiitUArUeQWiKpYbokQaO3giXLM7lwE9DU9mj/QvmI0czzchtJLxQ5KRDN5EzC+9vbP24qTExflohoPmiEeGUqNrnBRwlN/SDRICswYMCn3Pny0YaFF41dj7tak".to_string(),
            "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgwNzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGICW/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2GtkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkxoSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mFmr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPzlHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVwn6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1EuzbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHovaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHnw1IdYIg2Wxg7yHcQZemFQg==".to_string(),
        ])
        .unwrap();

        println!("{:?}", cert_chain.serials());
    }
}
