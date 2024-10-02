use std::{io::Cursor, str::FromStr};

use crate::utils::{BundleIdentifier, ClientError, ErrorCode, VerificationOutput};
use base64::{engine::general_purpose, Engine as _};
use der_parser::parse_der;
use dynamo::{fetch_apple_public_key, update_apple_public_key_counter_plus};
use eyre::ContextCompat;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sha::Sha256,
    sign::Verifier,
    stack::Stack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509StoreContext, X509,
    },
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use x509_parser::{
    der_parser::{ber::parse_ber_octetstring, oid},
    prelude::{FromDer, X509Certificate},
};

// made public to be used in integration tests
pub mod dynamo;

/// Verifies an Apple initial attestation and saves the key to Dynamo DB
///
/// # Errors
/// Returns server errors if something unexpected goes wrong during parsing and verification
pub async fn verify_initial_attestation(
    apple_initial_attestation: String,
    bundle_identifier: BundleIdentifier,
    request_hash: String,
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
) -> eyre::Result<VerificationOutput> {
    let attestation_result = decode_and_validate_initial_attestation(
        apple_initial_attestation,
        &request_hash,
        bundle_identifier.apple_app_id().context(format!(
            "Cannot retrieve `app_id` for bundle identifier: {bundle_identifier}"
        ))?,
        AAGUID::from_bundle_identifier(&bundle_identifier)?,
    )?;

    dynamo::insert_apple_public_key(
        aws_config,
        apple_keys_dynamo_table_name,
        bundle_identifier,
        attestation_result.key_id,
        attestation_result.public_key,
        attestation_result.receipt,
    )
    .await?;

    Ok(VerificationOutput {
        success: true,
        parsed_play_integrity_token: None,
        client_error: None,
    })
}

/// Verifies an Apple assertion (and optionally the initially attestation if this is a new public key)
///
/// # Errors
///
/// Returns server errors if something unexpected goes wrong during parsing and verification
pub async fn verify(
    apple_assertion: String,
    apple_public_key: String,
    bundle_identifier: &BundleIdentifier,
    request_hash: &str,
    aws_config: &aws_config::SdkConfig,
    apple_keys_dynamo_table_name: &String,
) -> eyre::Result<VerificationOutput> {
    // Fetch public key and counter from DB
    let key = fetch_apple_public_key(
        aws_config,
        apple_keys_dynamo_table_name,
        apple_public_key.clone(),
    )
    .await?;

    if &key.bundle_identifier != bundle_identifier {
        eyre::bail!(ClientError {
            code: ErrorCode::InvalidPublicKey,
            internal_debug_info: "the key_id is not valid for this bundle identifier".to_string(),
        });
    }

    let counter = decode_and_validate_assertion(
        apple_assertion,
        key.public_key,
        bundle_identifier.apple_app_id().context(format!(
            "Cannot retrieve `app_id` for bundle identifier: {bundle_identifier}"
        ))?,
        request_hash,
        key.counter,
    )?;

    // Update the key counter on DB
    update_apple_public_key_counter_plus(
        aws_config,
        apple_keys_dynamo_table_name,
        apple_public_key,
        counter,
    )
    .await?;

    Ok(VerificationOutput {
        success: true,
        parsed_play_integrity_token: None,
        client_error: None,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationStatement {
    x5c: Vec<ByteBuf>,
    receipt: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    fmt: String,
    att_stmt: AttestationStatement,
    auth_data: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// we make it public to be used in integration tests
pub struct Assertion {
    pub signature: ByteBuf,
    pub authenticator_data: ByteBuf,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, Copy)]
enum AAGUID {
    AppAttest,
    AppAttestDevelop,
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

#[derive(Debug)]
struct InitialAttestationOutput {
    pub public_key: String,
    pub receipt: String,
    pub key_id: String,
}

/// Implements the verification of `DeviceCheck` *attestations* for iOS.
/// Attestations are sent the first time to attest to the validity of a specific public key.
/// <https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643>
fn decode_and_validate_initial_attestation(
    apple_initial_attestation: String,
    request_hash: &str,
    expected_app_id: &str,
    expected_aaguid: AAGUID,
) -> eyre::Result<InitialAttestationOutput> {
    let attestation_bytes = general_purpose::STANDARD
        .decode(apple_initial_attestation)
        .map_err(|e| {
            tracing::debug!(?e, "error decoding base64 encoded attestation.");
            eyre::eyre!(ClientError {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "error decoding base64 encoded attestation.".to_string(),
            })
        })?;

    let cursor = Cursor::new(attestation_bytes);

    let attestation: Attestation = ciborium::from_reader(cursor).map_err(|e| {
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
        public_key: general_purpose::STANDARD.encode(public_key_der),
        receipt: general_purpose::STANDARD.encode(attestation.att_stmt.receipt.as_ref()),
        key_id: general_purpose::STANDARD.encode(credential_id),
    })
}

/// Implements the verification of the certificate chain for `DeviceCheck` attestations, using Apple's root CA.
fn verify_cert_chain(attestation: &Attestation) -> eyre::Result<()> {
    let root_cert = X509::from_pem(include_bytes!("./apple_app_attestation_root_ca.pem"))?;

    // Trusted root CA store
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(root_cert)?;
    let store = store_builder.build();

    // # Safety
    // It is safe to call this function because we've initialized the store with the trusted root CA from Apple.
    unsafe { internal_verify_cert_chain(attestation, &store) }
}

/// Implements the verification of the certificate chain for `DeviceCheck` attestations.
///
/// # Safety
/// This should only be called with the right trusted store.
unsafe fn internal_verify_cert_chain(
    attestation: &Attestation,
    store: &X509Store,
) -> eyre::Result<()> {
    let mut cert_chain = Stack::new()?;

    for cert_der in attestation.att_stmt.x5c.iter().rev() {
        let cert = X509::from_der(cert_der)?;
        cert_chain.push(cert)?;
    }
        let cert = X509::from_der(cert_der)?;
        cert_chain.push(cert.clone())?;
    }

    let target_cert = cert_chain
        .get(cert_chain.len() - 1)
        .context("No certificate found")?;

    let mut context = X509StoreContext::new()?;

    match context.init(
        store,
        target_cert,
        &cert_chain,
        openssl::x509::X509StoreContextRef::verify_cert,
    ) {
        Ok(result) => {
            if result {
                Ok(())
            } else {
                eyre::bail!("Certificate verification failed ({})", context.error())
            }
        }
        Err(e) => eyre::bail!("Certificate verification failed ({})", e),
    }
}

/// Implements the verification of `DeviceCheck` *assertions* for iOS.
/// <https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644>
fn decode_and_validate_assertion(
    assertion: String,
    public_key: String,
    expected_app_id: &str,
    request_hash: &str,
    last_counter: u32,
) -> eyre::Result<u32> {
    let assertion_bytes = general_purpose::STANDARD.decode(assertion).map_err(|_| {
        eyre::eyre!(ClientError {
            code: ErrorCode::InvalidToken,
            internal_debug_info: "error decoding base64 encoded assertion.".to_string(),
        })
    })?;

    let cursor = Cursor::new(assertion_bytes);

    let assertion: Assertion = ciborium::from_reader(cursor)?;

    // Step 1 and 2: Calculate nonce
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let hashed_nonce = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&assertion.authenticator_data);
    hasher.update(&hashed_nonce);
    let nonce: &[u8] = &hasher.finish();

    // Step 3: Verify signature
    let public_key = PKey::public_key_from_der(&general_purpose::STANDARD.decode(public_key)?)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(nonce)?;
    if !verifier.verify(&assertion.signature)? {
        eyre::bail!(ClientError {
            code: ErrorCode::InvalidToken,
            internal_debug_info:
                "signature failed validation for public key (request_hash may be wrong)".to_string(),
        });
    }

    // Step 4: check app_id
    let rp_id = &assertion.authenticator_data.clone()[0..32];
    let mut hasher = Sha256::new();
    hasher.update(expected_app_id.as_bytes());
    let hashed_app_id: &[u8] = &hasher.finish();

    if rp_id != hashed_app_id {
        eyre::bail!(ClientError {
            code: ErrorCode::InvalidAttestationForApp,
            internal_debug_info: "expected `app_id` for bundle identifier and `rp_id` from assertion object do not match."
                .to_string(),
        });
    }

    // Step 5: Counter check
    let counter = u32::from_be_bytes(assertion.authenticator_data.clone()[33..37].try_into()?);

    if counter <= last_counter {
        eyre::bail!(ClientError {
            code: ErrorCode::ExpiredToken,
            internal_debug_info: "last_counter is greater than provided counter.".to_string(),
        });
    }

    // Step 6: Check for nonce
    // Nonce is verified by downstream services and not by the Attestation Gateway

    Ok(counter)
}

#[cfg(test)]
mod tests;
