/// Verifies an Apple assertion (and optionally the initially attestation if this is a new public key)
///
/// # Errors
///
/// Returns server errors if something unexpected goes wrong during parsing and verification
pub fn verify(
    apple_assertion: String,
    _apple_public_key: String,
    _apple_initial_attestation: Option<String>,
) -> eyre::Result<()> {
    tracing::info!(
        "Verifying Apple attestation or assertion: {:?}",
        apple_assertion
    );

    Err(eyre::eyre!("Not implemented"))
}
