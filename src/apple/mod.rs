use std::str::FromStr;

use crate::utils::{BundleIdentifier, ClientError, ErrorCode, VerificationOutput};
use base64::{engine::general_purpose, Engine as _};
use der_parser::parse_der;
use eyre::ContextCompat;
use openssl::{
    sha::Sha256,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use x509_parser::{
    der_parser::{ber::parse_ber_octetstring, oid},
    prelude::{FromDer, X509Certificate},
};

/// Verifies an Apple assertion (and optionally the initially attestation if this is a new public key)
///
/// # Errors
///
/// Returns server errors if something unexpected goes wrong during parsing and verification
pub fn verify(
    apple_assertion: &Option<String>,
    apple_public_key: &Option<String>,
    apple_initial_attestation: &Option<String>,
    request_hash: &String,
    bundle_identifier: &BundleIdentifier,
) -> eyre::Result<VerificationOutput> {
    tracing::debug!(
        "TEMP: Verifying Apple attestation or assertion: {:?} - {:?}",
        apple_assertion,
        apple_public_key
    );

    if let Some(attestation) = apple_initial_attestation {
        let attestation_result = verify_initial_attestation(
            attestation,
            request_hash,
            bundle_identifier.apple_app_id().context(format!(
                "Cannot retrieve `app_id` for bundle identifier: {bundle_identifier}"
            ))?,
            AAGUID::from_bundle_identifier(bundle_identifier)?,
        )?;

        // FIXME: Store public key in DB
        println!("Public key: {:?}", attestation_result.public_key);
        println!("Receipt: {:?}", attestation_result.receipt);
        println!("Key ID: {:?}", attestation_result.key_id);

        // TODO: Parse and verify receipt
    } else {
        todo!("Verify public key is in the DB and run assertion verification.")
    }

    Err(eyre::eyre!("Not implemented"))
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationStatement {
    x5c: Vec<ByteBuf>,
    receipt: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attestation {
    fmt: String,
    att_stmt: AttestationStatement,
    auth_data: ByteBuf,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, Copy)]
enum AAGUID {
    AppAttest,
    AppAttestDevelop,
}

#[derive(Debug)]
struct InitialAttestationOutput {
    pub public_key: String,
    pub receipt: String,
    pub key_id: String,
}

impl FromStr for AAGUID {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            // the `AAGUID` has a specific number of bytes, the production one has a \0 padding to match the length of develop version
            "appattest\0\0\0\0\0\0\0" => Ok(Self::AppAttest),
            "appattestdevelop" => Ok(Self::AppAttestDevelop),
            _ => eyre::bail!("Invalid AAGUID"),
        }
    }
}

impl AAGUID {
    fn from_bundle_identifier(bundle_identifier: &BundleIdentifier) -> eyre::Result<Self> {
        match bundle_identifier {
            BundleIdentifier::IOSProdWorldApp => Ok(Self::AppAttest),
            BundleIdentifier::IOSStageWorldApp => Ok(Self::AppAttestDevelop),
            _ => eyre::bail!("Invalid bundle identifier for Apple verification."),
        }
    }
}

/// Implements the verification of `DeviceCheck` *attestation* for iOS.
/// <https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643>
fn verify_initial_attestation(
    apple_initial_attestation: &String,
    request_hash: &String,
    expected_app_id: &str,
    expected_aaguid: AAGUID,
) -> eyre::Result<InitialAttestationOutput> {
    let attestation_bytes = general_purpose::STANDARD_NO_PAD
        .decode(apple_initial_attestation)
        .map_err(|e| {
            tracing::debug!(?e, "error decoding base64 encoded attestation.");
            eyre::eyre!(ClientError {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "error decoding base64 encoded attestation.".to_string(),
            })
        })?;

    let attestation: Attestation = serde_cbor::from_slice(&attestation_bytes).map_err(|e| {
        tracing::debug!(?e, "error decoding cbor formatted attestation.");
        eyre::eyre!(ClientError {
            code: ErrorCode::InvalidToken,
            internal_debug_info: "error decoding cbor formatted attestation.".to_string(),
        })
    })?;

    // REFERENCE https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-attestation

    // Step 1: verify certificate
    verify_cert_chain(&attestation)?;

    // Step 2 and 3: create clientDataHash from the "challenge" (internally called `request_hash`)
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let client_data_hash = hasher.finish();

    // Step 3: create nonce as composite item
    let mut hasher = Sha256::new();
    hasher.update(attestation.auth_data.as_ref());
    hasher.update(&client_data_hash);
    let nonce: &[u8] = &hasher.finish();

    // Step 4: check nonce
    let (_, res) = X509Certificate::from_der(&attestation.att_stmt.x5c[0])?;
    let oid = oid!(1.2.840 .113635 .100 .8 .2);
    let extension = res.get_extension_unique(&oid)?;
    let (_, content) = parse_der(extension.context("Cannot parse nonce.")?.value)?;
    let value = content.as_sequence()?;
    let value = &value[0].as_slice()?;
    let (_, value) = parse_ber_octetstring(value)?;
    let attested_nonce = value.as_slice()?;

    if nonce != attested_nonce {
        eyre::bail!(ClientError {
            code: ErrorCode::IntegrityFailed,
            internal_debug_info: "nonce in attestation object does not match provided nonce."
                .to_string(),
        })
    }

    // Step 5: get user's public key
    let cert = X509::from_der(&attestation.att_stmt.x5c[0])?;
    let public_key_der = cert.public_key()?.public_key_to_der()?;
    let public_key = res.public_key().subject_public_key.clone().data;

    // Step 6: check app_id
    let rp_id = &attestation.auth_data.clone()[0..32];
    let mut hasher = Sha256::new();
    hasher.update(expected_app_id.as_bytes());
    let hashed_app_id: &[u8] = &hasher.finish();

    if rp_id != hashed_app_id {
        eyre::bail!(ClientError {
            code: ErrorCode::InvalidAttestationForApp,
            internal_debug_info: "expected `app_id` for bundle identifier and `rp_id` from attestation object do not match."
                .to_string(),
        });
    }

    // Step 7: counter check
    let counter = u32::from_be_bytes(attestation.auth_data.clone()[33..37].try_into()?);

    if counter > 0 {
        eyre::bail!(ClientError {
            code: ErrorCode::IntegrityFailed,
            internal_debug_info: "counter larger than 0".to_string(),
        });
    }

    // Step 8: verify `aaguid` is as expected from config
    let aaguid = AAGUID::from_str(std::str::from_utf8(&attestation.auth_data.clone()[37..53])?)?;

    if expected_aaguid != aaguid {
        eyre::bail!(ClientError {
            code: ErrorCode::InvalidAttestationForApp,
            internal_debug_info: "expected `AAGUID` for bundle identifier and `AAGUID` from attestation object do not match."
                .to_string(),
        });
    }

    // Step 9: verify the `credentialId` is the same as the public key
    let credential_id = &attestation.auth_data.clone()[55..87];
    let mut hasher = Sha256::new();
    hasher.update(&public_key);
    let hashed_public_key: &[u8] = &hasher.finish();

    if hashed_public_key != credential_id {
        eyre::bail!(ClientError {
            code: ErrorCode::IntegrityFailed,
            internal_debug_info: "hashed public key and credential_id do not match.".to_string(),
        });
    }

    Ok(InitialAttestationOutput {
        public_key: hex::encode(public_key_der),
        receipt: hex::encode(attestation.att_stmt.receipt.as_ref()),
        key_id: general_purpose::STANDARD.encode(credential_id),
    })
}

/// Implements the verification of the certificate chain for `DeviceCheck` attestations.
fn verify_cert_chain(attestation: &Attestation) -> eyre::Result<()> {
    let root_cert = X509::from_pem(include_bytes!("./apple_app_attestation_root_ca.pem"))?;
    let mut store_builder = X509StoreBuilder::new()?;
    let mut cert_chain = Stack::new()?;

    store_builder.add_cert(root_cert.clone())?;
    cert_chain.push(root_cert)?;

    for cert_der in &attestation.att_stmt.x5c.iter().rev().collect::<Vec<_>>() {
        let cert = X509::from_der(cert_der)?;
        cert_chain.push(cert.clone())?;
        store_builder.add_cert(cert)?;
    }

    let store = store_builder.build();

    let target_cert = cert_chain
        .get(cert_chain.len() - 1)
        .context("No certificate found")?;

    let mut context = X509StoreContext::new()?;
    match context.init(
        &store,
        target_cert,
        &cert_chain,
        openssl::x509::X509StoreContextRef::verify_cert,
    ) {
        Ok(_) => Ok(()),
        Err(_) => eyre::bail!("Certificate verification failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VALID_ATTESTATION: &str = "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";

    #[test]
    fn test_verify_initial_attestation_success() {
        // REFERENCE below contains an example attestation to verify proper implementation, however it cannot be used with our code
        // because the server challenge is not hashed which causes a discrepancy in step 2
        // https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide

        let result = verify_initial_attestation(
            &TEST_VALID_ATTESTATION.to_string(),
            &"testhash".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap();

        assert!(!result.receipt.is_empty());
        assert!(!result.key_id.is_empty());
        assert_eq!(result.public_key, "3059301306072a8648ce3d020106082a8648ce3d030107034200041c1ea50e53ecc723444ba25260cfb0e6b2311799cf78dd7d77036548b60653d2c5c7991838a79a8d6aec10f4f795a7f550bd3b4b400d546fb61ebe650a27a20f");
    }

    #[test]
    fn test_verify_initial_attestation_success_two() {
        // cspell:disable-next-line
        let valid_attestation = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAzgwggM0MIICuaADAgECAgYBkSerCU4wCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjQwODA1MTIzMDA2WhcNMjUwMjE0MTcxMjA2WjCBkTFJMEcGA1UEAwxAMzg0NDFmZDZkZGI1ZTFhOGVkOGU1OTkwZGJkYzRkNzhjYjVkNTk4MzlmZTFkNTE2MGM5NDJiNDA1YTgyMjQ4YzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASHgF3UisSc1qX8o2mUrpVWsHJSriOxW1VXGkwj+Z7N5ByW5+VceKRTFh77GgH98AvdWcQDnMmUuhukdx+f/j7vo4IBPDCCATgwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwgYkGCSqGSIb3Y2QIBQR8MHqkAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQqBCgzNVJYS0I2NzM4Lm9yZy53b3JsZGNvaW4uaW5zaWdodC5zdGFnaW5npQYEBHNrcyC/iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBADBXBgkqhkiG92NkCAcESjBIv4p4CAQGMTcuNS4xv4hQBwIFAP////+/insHBAUyMUY5ML+KfQgEBjE3LjUuMb+KfgMCAQC/iwwPBA0yMS42LjkwLjAuMCwwMDMGCSqGSIb3Y2QIAgQmMCShIgQgmtCF0uZ/b2Yw05enEnUjRVAJd8hC4MRv/At12QeA+f0wCgYIKoZIzj0EAwIDaQAwZgIxAPRUcOcMJu8xjg2u53FQNhm+IrlyzAHBUmJCbH4ZiEU/w+2pfDDqh19ZTBKuAxbE3wIxAI0R/PdhmZFPZG48bdPNQc+qGkdmL55UiVazqQMUAfSCJnM7i1jjR3RxlRopAWGitFkCRzCCAkMwggHIoAMCAQICEAm6xeG8QBrZ1FOVvDgaCFQwCgYIKoZIzj0EAwMwUjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzOTU1WhcNMzAwMzEzMDAwMDAwWjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK5bN6B3TXmyNY9A59HyJibxwl/vF4At6rOCalmHT/jSrRUleJqiZgQZEki2PLlnBp6Y02O9XjcPv6COMp6Ac6mF53Ruo1mi9m8p2zKvRV4hFljVZ6+eJn6yYU3CGmbOmaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSskRBTM72+aEH/pwyp5frq5eWKoTAdBgNVHQ4EFgQUPuNdHAQZqcm0MfiEdNbh4Vdy45swDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2kAMGYCMQC7voiNc40FAs+8/WZtCVdQNbzWhyw/hDBJJint0fkU6HmZHJrota7406hUM/e2DQYCMQCrOO3QzIHtAKRSw7pE+ZNjZVP+zCl/LrTfn16+WkrKtplcS4IN+QQ4b3gHu1iUObdncmVjZWlwdFkOsDCABgkqhkiG9w0BBwKggDCAAgEBMQ8wDQYJYIZIAWUDBAIBBQAwgAYJKoZIhvcNAQcBoIAkgASCA+gxggRpMDACAQICAQEEKDM1UlhLQjY3Mzgub3JnLndvcmxkY29pbi5pbnNpZ2h0LnN0YWdpbmcwggNCAgEDAgEBBIIDODCCAzQwggK5oAMCAQICBgGRJ6sJTjAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yNDA4MDUxMjMwMDZaFw0yNTAyMTQxNzEyMDZaMIGRMUkwRwYDVQQDDEAzODQ0MWZkNmRkYjVlMWE4ZWQ4ZTU5OTBkYmRjNGQ3OGNiNWQ1OTgzOWZlMWQ1MTYwYzk0MmI0MDVhODIyNDhjMRowGAYDVQQLDBFBQUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIeAXdSKxJzWpfyjaZSulVawclKuI7FbVVcaTCP5ns3kHJbn5Vx4pFMWHvsaAf3wC91ZxAOcyZS6G6R3H5/+Pu+jggE8MIIBODAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DCBiQYJKoZIhvdjZAgFBHwweqQDAgEKv4kwAwIBAb+JMQMCAQC/iTIDAgEBv4kzAwIBAb+JNCoEKDM1UlhLQjY3Mzgub3JnLndvcmxkY29pbi5pbnNpZ2h0LnN0YWdpbmelBgQEc2tzIL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQC/iTsDAgEAMFcGCSqGSIb3Y2QIBwRKMEi/ingIBAYxNy41LjG/iFAHAgUA/////7+KewcEBTIxRjkwv4p9CAQGMTcuNS4xv4p+AwIBAL+LDA8EDTIxLjYuOTAuMC4wLDAwMwYJKoZIhvdjZAgCBCYwJKEiBCCa0IXS5n9vZjDTl6cSdSNFUAl3yELgxG/8C3XZB4D5/TAKBggqhkjOPQQDAgNpADBmAjEA9FRw5wwm7zGODa7ncVA2Gb4iuXLMAcFSYkJsfhmIRT/D7al8MOqHX1lMEq4DFsTfAjEAjRH892GZkU9kbjxt081Bz6oaR2YvnlSJVrOpAxQB9IImczuLWONHdHGVGikBYaK0MCgCAQQCAQEEIJ+G0IGITH1lmi/qoMVa0BWjv08bKwuCLNFdbBWw8AoIMGACAQUCAQEEWEdDVGkrZ0J1N0p4b2UrY1NwZm5TMkVOY1VYRmZPSlhWL3kvY3pqWGdOV3N3ditYN1VNM0owMGlMBIGFM3BDY3hTNXhscDB0MllZLzNlR2t2QzhBWmxaZHJRPT0wDgIBBgIBAQQGQVRURVNUMA8CAQcCAQEEB3NhbmRib3gwIAIBDAIBAQQYMjAyNC0wOC0wNlQxMjozMDowNi4xOTZaMCACARUCAQEEGDIwMjQtMTEtMDRUMTI6MzA6MDYuMTk2WgAAAAAAAKCAMIIDrjCCA1SgAwIBAgIQfgISYNjOd6typZ3waCe+/TAKBggqhkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yNDAyMjcxODM5NTJaFw0yNTAzMjgxODM5NTFaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARUN7iCxk/FE+l6UecSdFXhSxqQC5mL19QWh2k/C9iTyos16j1YI8lqda38TLd/kswpmZCT2cbcLRgAyQMg9HtEo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTZF/5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUK89JHvvPG3kO8K8CKRO1ARbheTQwDgYDVR0PAQH/BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDSAAwRQIhAIeoCSt0X5hAxTqUIUEaXYuqCYDUhpLV1tKZmdB4x8q1AiA/ZVOMEyzPiDA0sEd16JdTz8/T90SDVbqXVlx9igaBHDCCAvkwggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv+wSUgJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG+gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZeGl00GNnt7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGB/TCB+gIBATCBkDB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIQfgISYNjOd6typZ3waCe+/TANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRHMEUCICqgyIQ2zthKaAACCzGD2j4IfW3/VgHAP7Oub76SD/aBAiEA6C5aPArfBc/a92p4BMQhm0Hr9V3+9fbddF4x7w0D8AgAAAAAAABoYXV0aERhdGFYpNJYCIP3FikJXRKshlK4W68Qb+I/1miZc5AejfQ5oOt1QAAAAABhcHBhdHRlc3RkZXZlbG9wACA4RB/W3bXhqO2OWZDb3E14y11Zg5/h1RYMlCtAWoIkjKUBAgMmIAEhWCCHgF3UisSc1qX8o2mUrpVWsHJSriOxW1VXGkwj+Z7N5CJYIByW5+VceKRTFh77GgH98AvdWcQDnMmUuhukdx+f/j7v";

        let result = verify_initial_attestation(
            &valid_attestation.to_string(),
            &"test".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap();

        assert!(!result.receipt.is_empty());
        assert!(!result.public_key.is_empty());
        assert_eq!(
            result.key_id,
            "OEQf1t214ajtjlmQ29xNeMtdWYOf4dUWDJQrQFqCJIw="
        );
    }

    #[test]
    fn test_verify_initial_attestation_failure_on_completely_invalid_token() {
        let result = verify_initial_attestation(
            &"this_is_not_base64_encoded".to_string(),
            &"test".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap_err();

        // NOTE: We particularly want to make sure this returns a `ClientError` as this indicates an invalid token was provided
        let result = result.downcast_ref::<ClientError>().unwrap();

        assert_eq!(result.code, ErrorCode::InvalidToken);
        assert_eq!(
            result.internal_debug_info,
            "error decoding base64 encoded attestation.".to_string()
        );
    }

    #[test]
    fn test_verify_initial_attestation_failure_on_invalid_cbor_message() {
        //
        let result = verify_initial_attestation(
            // This is a valid base64 encoded string but not a valid CBOR message
            // cspell:disable-next-line
            &"dGhpcyBpcyBpbnZhbGlk".to_string(),
            &"test".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap_err();

        let result = result.downcast_ref::<ClientError>().unwrap();

        assert_eq!(result.code, ErrorCode::InvalidToken);
        assert_eq!(
            result.internal_debug_info,
            "error decoding cbor formatted attestation.".to_string()
        );
    }

    #[test]
    fn test_verify_initial_attestation_failure_nonce_mismatch() {
        let result = verify_initial_attestation(
            &TEST_VALID_ATTESTATION.to_string(),
            &"a_different_hash".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap_err();

        let result = result.downcast_ref::<ClientError>().unwrap();
        assert_eq!(result.code, ErrorCode::IntegrityFailed);
        assert_eq!(
            result.internal_debug_info,
            "nonce in attestation object does not match provided nonce.".to_string()
        );
    }

    #[test]
    fn test_verify_initial_attestation_failure_app_id_mismatch() {
        let result = verify_initial_attestation(
            &TEST_VALID_ATTESTATION.to_string(),
            &"testhash".to_string(),
            BundleIdentifier::IOSProdWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttestDevelop,
        )
        .unwrap_err();

        let result = result.downcast_ref::<ClientError>().unwrap();
        assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
        assert_eq!(
        result.internal_debug_info,
        "expected `app_id` for bundle identifier and `rp_id` from attestation object do not match."
            .to_string()
    );
    }

    #[test]
    fn test_verify_initial_attestation_failure_aaguid_mismatch() {
        let result = verify_initial_attestation(
            &TEST_VALID_ATTESTATION.to_string(),
            &"testhash".to_string(),
            BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
            AAGUID::AppAttest,
        )
        .unwrap_err();

        let result = result.downcast_ref::<ClientError>().unwrap();
        assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
        assert_eq!(
        result.internal_debug_info,
        "expected `AAGUID` for bundle identifier and `AAGUID` from attestation object do not match."
            .to_string()
    );
    }
}
