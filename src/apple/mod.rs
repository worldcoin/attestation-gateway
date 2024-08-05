use std::str::FromStr;

use crate::utils::{BundleIdentifier, VerificationOutput};
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
    apple_assertion: &String,
    apple_public_key: &str,
    apple_initial_attestation: Option<&String>,
    request_hash: &String,
    bundle_identifier: &BundleIdentifier,
) -> eyre::Result<VerificationOutput> {
    tracing::info!(
        "Verifying Apple attestation or assertion: {:?}",
        apple_assertion
    );

    if let Some(attestation) = apple_initial_attestation {
        verify_initial_attestation(
            attestation,
            apple_public_key,
            request_hash,
            bundle_identifier,
        )?;
    } else {
        todo!("Verify public key is in the DB.")
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
#[derive(Debug, PartialEq, Clone)]
enum AAGUID {
    AppAttest,
    AppAttestDevelop,
}

impl FromStr for AAGUID {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "appattest" => Ok(Self::AppAttest),
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
    apple_public_key: &str,
    request_hash: &String,
    bundle_identifier: &BundleIdentifier,
) -> eyre::Result<()> {
    let attestation_bytes = general_purpose::STANDARD_NO_PAD.decode(apple_initial_attestation)?;

    let attestation: Attestation = serde_cbor::from_slice(&attestation_bytes)?;

    // REFERENCE https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-attestation

    // Step 1: verify certificate
    verify_cert_chain(&attestation)?;

    // FIXME: Double check ClientErrors

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
    let received_nonce = value.as_slice()?;

    if nonce != received_nonce {
        eyre::bail!("Nonce mismatch.")
    }

    // Step 5: get user's public key & verifies it matches passed key
    let cert = X509::from_der(&attestation.att_stmt.x5c[0])?;
    let public_key_der = cert.public_key()?.public_key_to_der()?;
    let public_key = res.public_key().subject_public_key.clone().data;
    if apple_public_key != hex::encode(public_key_der) {
        eyre::bail!("Public key mismatch.")
    }

    // Step 6: check app_id
    let rp_id = &attestation.auth_data.clone()[0..32];
    let mut hasher = Sha256::new();
    let app_id = bundle_identifier.apple_app_id().context(format!(
        "Cannot retrieve `app_id` for bundle identifier: {bundle_identifier}"
    ))?;
    hasher.update(app_id.as_bytes());
    let hashed_app_id: &[u8] = &hasher.finish();

    if rp_id != hashed_app_id {
        eyre::bail!("expected `app_id` & `rp_id` mismatch.")
    }

    // Step 7: counter check
    let counter = u32::from_be_bytes(attestation.auth_data.clone()[33..37].try_into()?);

    if counter > 0 {
        eyre::bail!("Counter larger than 0.")
    }

    // Step 8: verify `aaguid` is as expected from config
    let aaguid = AAGUID::from_str(std::str::from_utf8(&attestation.auth_data.clone()[37..53])?)?;

    if AAGUID::from_bundle_identifier(bundle_identifier)? != aaguid {
        eyre::bail!("AAGUID does not match config.")
    }

    // Step 9: verify the `credentialId` is the same as the public key
    let credential_id = &attestation.auth_data.clone()[55..87];
    let mut hasher = Sha256::new();
    hasher.update(&public_key);
    let hashed_public_key: &[u8] = &hasher.finish();

    if hashed_public_key != credential_id {
        eyre::bail!("`credentialId` does not match public key.")
    }

    Ok(())
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
