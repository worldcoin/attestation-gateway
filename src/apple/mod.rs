use crate::utils::{ErrorCode, RequestError};
use base64::{engine::general_purpose, Engine as _};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Verifier,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use x509_parser::{
    der_parser::{ber::parse_ber_octetstring, oid},
    prelude::{FromDer, X509Certificate},
};

fn verify_apple_attestation_or_assertion(
    apple_assertion: String,
    apple_public_key: String,
    apple_initial_attestation: Option<String>,
) -> Result<(), RequestError> {
    // Verify the initial attestation

    if let Some(apple_initial_attestation) = apple_initial_attestation {
        verify_initial_attestation(apple_initial_attestation, apple_public_key)?;
    } else {
        // Verify public key in Dynamo
    }

    // Verify the assertion
    // verify_assertion(apple_public_key, apple_assertion)?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct AttestationStatement {
    x5c: Vec<ByteBuf>,
    receipt: ByteBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attestation {
    fmt: String,
    att_stmt: AttestationStatement,
    auth_data: ByteBuf,
}

fn verify_initial_attestation(
    apple_initial_attestation: String,
    apple_public_key: String,
) -> Result<(), RequestError> {
    let Ok(attestation_bytes) = general_purpose::STANDARD_NO_PAD.decode(apple_initial_attestation)
    else {
        return Err(RequestError {
            code: ErrorCode::InvalidToken,
            internal_details: Some("Failed to decode initial_attestation bytes".to_string()),
        });
    };

    let Ok(attestation): Result<Attestation, _> = serde_cbor::from_slice(&attestation_bytes) else {
        return Err(RequestError {
            code: ErrorCode::InvalidToken,
            internal_details: Some("Failed to deserialize initial_attestation".to_string()),
        });
    };

    let result = verify_cert_chain(&attestation);

    Ok(())
}

/// Implements the verification of the certificate chain for DeviceCheck attestations.
fn verify_cert_chain(attestation: &Attestation) -> Result<bool, Box<dyn std::error::Error>> {
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
    match context.init(&store, &target_cert, &cert_chain, |c| c.verify_cert()) {
        Ok(_) => return Ok(true),
        Err(_) => return Ok(false),
    }
}
