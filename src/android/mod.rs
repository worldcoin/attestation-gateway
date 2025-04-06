use crate::utils::{BundleIdentifier, ClientException, ErrorCode, VerificationOutput};
use base64::Engine;
pub use integrity_token_data::PlayIntegrityToken;
use josekit::jwe::{self, A256KW};
use josekit::jws::ES256;

mod integrity_token_data;

/// Verifies an Android Play Integrity token and returns a parsed `PlayIntegrityToken`
///
/// # Errors
///
/// Returns server errors if something unexpected goes wrong during parsing and verification (integrity failures are returned as part of the `VerificationOutput`)
pub fn verify(
    integrity_token: &str,
    bundle_identifier: &BundleIdentifier,
    request_hash: &str,
    android_outer_jwe_private_key: String,
    android_inner_jws_verifier_key: String,
) -> eyre::Result<VerificationOutput> {
    let decrypted_jws = decrypt_outer_jwe(integrity_token, android_outer_jwe_private_key)?;

    let play_integrity_payload =
        verify_and_parse_inner_jws(decrypted_jws, android_inner_jws_verifier_key)?;

    let parsed_token = PlayIntegrityToken::from_json(&play_integrity_payload)?;

    let validation_result = parsed_token.validate_all_claims(bundle_identifier, request_hash);

    if let Err(err) = validation_result {
        if let Some(client_error) = err.downcast_ref::<ClientException>() {
            // We do this additional error handling to return the parsed token in the response and be able to log it for analytics purposes
            return Ok(VerificationOutput {
                success: false,
                parsed_play_integrity_token: Some(parsed_token),
                client_exception: Some(client_error.clone()),
            });
        }
        return Err(err);
    }

    Ok(VerificationOutput {
        success: true,
        parsed_play_integrity_token: Some(parsed_token),
        client_exception: None,
    })
}

/// Decrypts the outer JWE (JSON Web Encryption) token using the AES secret provided by Google for each bundle identifier
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
fn decrypt_outer_jwe(
    integrity_token: &str,
    android_outer_jwe_private_key: String,
) -> eyre::Result<Vec<u8>> {
    // Decrypt the outer JWE
    let key = base64::engine::general_purpose::STANDARD.decode(android_outer_jwe_private_key)?;
    let decrypter = A256KW.decrypter_from_bytes(key)?;

    let (compact_jws, _) = jwe::deserialize_compact(integrity_token, &decrypter).map_err(|e| {
        eyre::eyre!(ClientException {
            code: ErrorCode::InvalidToken,
            internal_debug_info: format!("JWE failed decryption {e}"),
        })
    })?;

    Ok(compact_jws)
}

/// Verifies the signature of the inner JWS and parses the payload into a `PlayIntegrityToken` struct
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
///
fn verify_and_parse_inner_jws(
    compact_jws: Vec<u8>,
    android_inner_jws_verifier_key: String,
) -> eyre::Result<String> {
    let decoded_key = base64::engine::general_purpose::STANDARD
        .decode(android_inner_jws_verifier_key.into_bytes())?;
    let verifier = ES256.verifier_from_der(decoded_key)?;

    let (jws, _) = josekit::jwt::decode_with_verifier(compact_jws, &verifier)?;

    // NOTE: The JWS doesn't have an `exp` claim and has instead a `timestampMillis` so we don't verify the `exp` claim

    Ok(serde_json::to_string(jws.claims_set())?)
}

#[cfg(test)]
mod tests {

    use super::{verify, verify_and_parse_inner_jws};
    use crate::utils::{BundleIdentifier, ClientException, ErrorCode};
    use josekit::jwe::{self, JweHeader, A128KW, A256KW};
    use josekit::jws::{JwsHeader, ES256};
    use josekit::jwt::{self, JwtPayload};

    fn helper_get_test_keys() -> (String, String) {
        dotenvy::from_filename(".env.example").unwrap();
        (
            std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY")
                .expect("`ANDROID_OUTER_JWE_PRIVATE_KEY` must be set for tests."),
            std::env::var("ANDROID_INNER_JWS_PUBLIC_KEY")
                .expect("`ANDROID_INNER_JWS_PUBLIC_KEY` must be set for tests."),
        )
    }

    // SECTION - JWE tests

    #[test]
    fn test_invalid_jwe_fails_verification() {
        // Generate and encrypt a JWE with an unexpected key
        let other_private_key = "caba71cf1b1e3896136dc70301c0613f";

        let encrypter = A256KW.encrypter_from_bytes(other_private_key).unwrap();

        let mut headers = JweHeader::new();
        headers.set_algorithm("A256KW");
        headers.set_content_encryption("A256GCM");

        let test_jwe = jwe::serialize_compact(b"test", &headers, &encrypter).unwrap();

        let (jwe_sk, jws_pk) = helper_get_test_keys();

        let error_report = verify(
            &test_jwe,
            &BundleIdentifier::AndroidStageWorldApp,
            "test",
            jwe_sk,
            jws_pk,
        )
        .unwrap_err();

        assert_eq!(
            error_report.downcast::<ClientException>().unwrap(),
            ClientException {
                code: ErrorCode::InvalidToken,
                internal_debug_info:
                    "JWE failed decryption Invalid JWE format: Failed to unwrap key.".to_string()
            }
        );
    }

    #[test]
    fn test_invalid_encryption_algorithm() {
        let other_private_key = "caba71cf1b1e389c";

        // NOTE: We're trying a different encryption algorithm
        let encrypter = A128KW.encrypter_from_bytes(other_private_key).unwrap();

        let mut headers = JweHeader::new();
        headers.set_algorithm("A128KW");
        // cspell:disable-next-line
        headers.set_content_encryption("A256GCM");

        let test_jwe = jwe::serialize_compact(b"test", &headers, &encrypter).unwrap();

        let (jwe_sk, jws_pk) = helper_get_test_keys();

        let error_report = verify(
            &test_jwe,
            &BundleIdentifier::AndroidStageWorldApp,
            "test",
            jwe_sk,
            jws_pk,
        )
        .unwrap_err();

        assert_eq!(
            error_report.downcast::<ClientException>().unwrap(),
            ClientException {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "JWE failed decryption Invalid JWE format: The JWE alg header claim is not A256KW: A128KW".to_string()
            }
        );
    }

    // SECTION - JWS tests

    #[test]
    fn test_invalid_jws_signature_verification() {
        // cspell:disable-next-line
        // Generate new test keys with: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`
        let verifier_private_key = "-----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgju+eEEYRI/cCZ4Lt
    iBRYNfoa9P8vdmea4HRcY9MrIcuhRANCAAQ3GAij5E/RgUggXkCmKFSMme5KrGkP
    LWUzsm73Mx4njtA2Caop0UIzoVKbh41NoBZ+BKnuH/a97Qti2nDPcjUX
    -----END PRIVATE KEY-----";

        // Generate a JWS with an unexpected signing key
        let mut payload = JwtPayload::new();
        payload.set_subject("subject");

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = ES256.signer_from_pem(verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let (_, jws_pk) = helper_get_test_keys();

        let error_report = verify_and_parse_inner_jws(jws.into_bytes(), jws_pk).unwrap_err();
        assert_eq!(
            "Invalid signature: The signature does not match.",
            error_report.to_string()
        );
    }
}
