use crate::{
    android::{
        android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
        android_cert_chain::{AndroidCertChain, AndroidCertChainError},
    },
    utils::BundleIdentifier,
};

#[derive(Debug)]

pub enum AndroidAttestationError {
    CaRegistry(AndroidCaRegistryError),
    CertChain(AndroidCertChainError),
    InvalidCaRoot,
    InvalidChallenge,
    LowSecurityLevel,
    DeviceNotLocked,
    InvalidPackageName,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct AndroidAttestationService {
    ca_registry: AndroidCaRegistry,
}

impl AndroidAttestationService {
    pub fn new(ca_registry: AndroidCaRegistry) -> Self {
        Self { ca_registry }
    }

    pub fn from_default_pem() -> Result<Self, AndroidAttestationError> {
        let ca_registry = AndroidCaRegistry::from_default_pem()
            .map_err(|e| AndroidAttestationError::CaRegistry(e))?;

        Ok(Self::new(ca_registry))
    }

    pub fn verify(
        self,
        base64_cert_chain: Vec<String>,
        bundle_identifier: &BundleIdentifier,
        nonce: &String,
        app_version: &String,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain)
            .map_err(|e| AndroidAttestationError::CertChain(e))?;

        if !self
            .ca_registry
            .has_public_key(cert_chain.root_ca_public_key())
        {
            return Err(AndroidAttestationError::InvalidCaRoot);
        }

        if cert_chain.attestation_challenge() != format!("n={},av={}", nonce, app_version) {
            return Err(AndroidAttestationError::InvalidChallenge);
        }

        if cert_chain.device_security_level() < 1 {
            return Err(AndroidAttestationError::LowSecurityLevel);
        }

        if !cert_chain.device_locked() {
            return Err(AndroidAttestationError::DeviceNotLocked);
        }

        if cert_chain.device_package_name() != bundle_identifier.to_string() {
            return Err(AndroidAttestationError::InvalidPackageName);
        }

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.device_public_key(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_pablo_chain1() {
    //     let chain = vec![
    //         "MIICzDCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs2uoTuLKmoC+unpsOJSFI0LsJCVNBiyKiTqYDXkno+MMeYoEsoHFdecOeBmoCImbKf8bWsDAxSbGOj6JzSIsqaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDCCAXoGCisGAQQB1nkCAREEggFqMIIBZgIBAwoBAQIBBAoBAQRWYXBwLnN0YWdlLmZhY2Uud29ybGRjb2luLm9yZyE3NTRiYTQyM2FkZjNhNmQ1Y2IyZWMzNmRhOGVjZmQ0NCEyMDI2LTAyLTI2VDIxOjE3OjI0LjQ1N1oEADBav4N9AgUAv4U9CAIGAZyb0Wewv4VFRARCMEAxGjAYBBFjb20ud29ybGRjb2luLmRldgIDPQ2wMSIEIKNBbt/cqq7MXlkrnKoHu3jsxvMa7EQJ9Jym07Tf8dvgMIGhoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgYf2hKzLthCFKnPE9Gv+3qoC9iiaKhh7Uu3oVFw8asAwBAf8KAQAEIMuBDKWKYbbA4RGjBGzOXFMM79ynwhOMxidq2r6VoXi6v4VBBQIDAdTAv4VCBQIDAxV+v4VOBgIEATRlPb+FTwYCBAE0ZT0wCgYIKoZIzj0EAwIDRwAwRAIgRYC4+rYMqjEi7Jq6J+lRR19BmcvCzaUqwMm5butcSVUCIB8pISV0K5+guf99CAxpRGlhc52EZvC+9YiAT5UUuHUA".to_string(),
    //         "MIICJjCCAaugAwIBAgIKEVR4FBYnAJkBFDAKBggqhkjOPQQDAjApMRkwFwYDVQQFExBiN2U4OWVkYTVjN2U3ZDBiMQwwCgYDVQQMDANURUUwHhcNMTgwOTIwMjIyNjI4WhcNMjgwOTE3MjIyNjI4WjApMRkwFwYDVQQFExAwZmNjZjBkNTQ4OWJhMDRjMQwwCgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRJq9kgNwBtR8vqU8I/1nZuj8skYkwAtpmxtggw8nFYrrcgKMCYsyHsI0O2ry5ZhZWcQWYJ7IfEHjPgexP4qaGo4G6MIG3MB0GA1UdDgQWBBRhvyMRj+HccCnev8pqpqJs8Yt1/TAfBgNVHSMEGDAWgBSrOYp4HmrnQ/5m1TOgTUB3R0xfqDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzExNTQ3ODE0MTYyNzAwOTkwMTE0MAoGCCqGSM49BAMCA2kAMGYCMQCE4gdd45J7cQ1oz4vfi18WMFPyq/euFzrXTIhAXXmAdm7IT0lqw3c8q+VwCZT3ocsCMQCI4ePgpo3r9rrzS/fQ2vQuqVL2G1FY428FKAjPWGZfdut/gnLo47M6+/r/oQ5UnHQ=".to_string(),
    //         "MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaFqDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDkyMDIyMjQ0NVoXDTI4MDkxNzIyMjQ0NVowKTEZMBcGA1UEBRMQYjdlODllZGE1YzdlN2QwYjEMMAoGA1UEDAwDVEVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEblioAoTtfGhsP2zIxjmsoKNiCwtSopTjrxGzbZHgOrHH9e2qdtnWkcI7NQGpGv2iOFpIY2cTWH/W3Aeppb4ZPqWazxhzT5juj2/NY2q9yO5UA0sFnr0+G5WBu9cPv35Fo4G2MIGzMB0GA1UdDgQWBBSrOYp4HmrnQ/5m1TOgTUB3R0xfqDAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsL0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBACIaj2DMlC1k+FrxuQ11TOtC9p/3XLJjqbh8oL+i5E9nQszZehx8xzJOboup3L7UnSCCwP8xFSXLUKa+/eTODVhwYYumVkyIpaQdurajcz0shk0xXsC5dIsC0FlDbuNmNv6eEymd3pocJRqHgE4KEL47Ye5q+cQzmjQRTNHr1qrQZnc3XX+6bAGavbnSb7NwXs4jjNYMulVpvhTJwO1LhvvmuTnT4oUT/Vy2phgaWxH4AsfnyIh5IEPhtwVSrqsq+mIKnBRdj96Ym1yhmOuYVQf78bYvIYjeNjng5YM3CJkt7A2/bVh3vTnEjwgq3nN01+9pgujrBlkMhZXKFeHxorndi+uUSafxGCn4OZnUHoVGY1V/kYWZFYyBO7C1dR1ndNkuu39sm/HOFvkOjDkMpdrbF8QUnYEU3g0uddAJpcHMuCPd3iLhsqZVOAs/ajZ+c5mEJG07PYRvZ0TFDTZaSCyn3RPwNFJdUir9W+xpWAxNSEWAnlz6P99tX2hHDjQDJ5io4S2dOquY0diqibdjPYdXx1nOmzsy57IZVw6tFmtDf4IUrRXa3Y80G0XJgOXjCYM2YS0BqaTb9nwSW+Hh0UswMh9ZzgDdn5NSUryvew1PZEp8pzZiAvpXwiNnpBG7zMoJ0O07kClwaiJed1S+AURUv228frnoRvVs5g9ilmj0".to_string(),
    //         "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk".to_string(),
    //     ];

    //     let attestation = AndroidAttestationService::from_default_pem().unwrap();
    //     let pablo_public_key = attestation.verify(chain).unwrap();

    //     assert!(pablo_public_key.device_public_key.len() > 0);
    // }
}
