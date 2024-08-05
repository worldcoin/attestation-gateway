use std::time::SystemTime;

use crate::utils::{BundleIdentifier, ClientError, ErrorCode, VerificationOutput};
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
) -> eyre::Result<VerificationOutput> {
    let decrypted_jws = decrypt_outer_jwe(integrity_token, android_outer_jwe_private_key)?;

    let play_integrity_payload = verify_and_parse_inner_jws(&decrypted_jws)?;

    let parsed_token = PlayIntegrityToken::new(&play_integrity_payload)?;

    let validation_result = parsed_token.validate_all_claims(bundle_identifier, request_hash);

    if let Err(err) = validation_result {
        if let Some(client_error) = err.downcast_ref::<ClientError>() {
            // We do this additional error handling to return the parsed token in the response and be able to log it for analytics purposes
            return Ok(VerificationOutput {
                success: false,
                parsed_play_integrity_token: Some(parsed_token),
                client_error: Some(client_error.clone()),
            });
        }
        return Err(err);
    }

    Ok(VerificationOutput {
        success: true,
        parsed_play_integrity_token: Some(parsed_token),
        client_error: None,
    })
}

/// Decrypts the outer JWE (JSON Web Encryption) token using the AES secret provided by Google for each bundle identifier
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
fn decrypt_outer_jwe(
    integrity_token: &str,
    android_outer_jwe_private_key: String,
) -> eyre::Result<Vec<u8>> {
    // Decrypt the outer JWE
    let decrypter = A256KW.decrypter_from_bytes(android_outer_jwe_private_key)?;

    let (compact_jws, _) = jwe::deserialize_compact(integrity_token, &decrypter).map_err(|_| {
        eyre::eyre!(ClientError {
            code: ErrorCode::InvalidToken,
            internal_debug_info: "JWE failed decryption".to_string(),
        })
    })?;

    Ok(compact_jws)
}

/// Verifies the signature of the inner JWS (as well as expiration) and parses the payload into a `PlayIntegrityToken` struct
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
///
fn verify_and_parse_inner_jws(compact_jws: &[u8]) -> eyre::Result<String> {
    // FIXME: These are temporary keys for local development
    let verifier_key = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+D+pCqBGmautdPLe/D8ot+e0/ESc
v4MgiylljSWZUPzQU0npHMNTO8Z9meOTHa3rORO3c2s14gu+Wc5eKdvoHw==
-----END PUBLIC KEY-----";

    let verifier = ES256.verifier_from_pem(verifier_key)?;

    let (jws, _) = josekit::jwt::decode_with_verifier(compact_jws, &verifier)?;

    // Verify expiration
    jws.expires_at()
        .ok_or_else(|| eyre::eyre!("Unexpected token format, invalid exp claim."))
        .and_then(|value| {
            value.duration_since(SystemTime::now()).map_err(|_| {
                eyre::eyre!(ClientError {
                    code: ErrorCode::InvalidToken,
                    internal_debug_info: "JWS is expired".to_string(),
                })
            })
        })?;

    // Parse the JWS
    let Some(integrity_payload) = jws.claim("payload") else {
        return Err(eyre::eyre!(
            "JWT does not have a `payload` attribute".to_string()
        ));
    };

    Ok(integrity_payload.to_string())
}

#[cfg(test)]
mod tests {

    use super::{verify, verify_and_parse_inner_jws};
    use crate::utils::{BundleIdentifier, ClientError, ErrorCode};
    use josekit::jwe::{self, JweHeader, A128KW, A256KW};
    use josekit::jws::{JwsHeader, ES256};
    use josekit::jwt::{self, JwtPayload};
    use std::time::{Duration, SystemTime};

    fn helper_get_test_key() -> String {
        dotenvy::from_filename(".env.example").unwrap();
        std::env::var("ANDROID_OUTER_JWE_PRIVATE_KEY").unwrap()
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

        let error_report = verify(
            &test_jwe,
            &BundleIdentifier::AndroidStageWorldApp,
            "test",
            helper_get_test_key(),
        )
        .unwrap_err();

        assert_eq!(
            error_report.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "JWE failed decryption".to_string()
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

        let error_report = verify(
            &test_jwe,
            &BundleIdentifier::AndroidStageWorldApp,
            "test",
            helper_get_test_key(),
        )
        .unwrap_err();

        assert_eq!(
            error_report.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "JWE failed decryption".to_string()
            }
        );
    }

    // SECTION - JWS tests

    #[test]
    fn test_invalid_jws_signature_verification() {
        // cspell:disable-next-line
        // Generate new test keys with: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256``
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

        let error_report = verify_and_parse_inner_jws(&jws.into_bytes()).unwrap_err();
        assert_eq!(
            "Invalid signature: The signature does not match.",
            error_report.to_string()
        );
    }

    #[test]
    fn test_expired_jws_fails_verification() {
        // TODO: Replace once we use actual keys
        let verifier_private_key = "-----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFU28VNv+wsvcC0rR
    5n05rAs2xRxfmbHzDjEQdQqvRSmhRANCAAT4P6kKoEaZq6108t78Pyi357T8RJy/
    gyCLKWWNJZlQ/NBTSekcw1M7xn2Z45Mdres5E7dzazXiC75Zzl4p2+gf
    -----END PRIVATE KEY-----";

        // Generate a JWS which expired 5 seconds ago
        let exp = SystemTime::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload.set_subject("subject");
        payload.set_expires_at(&exp);

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = ES256.signer_from_pem(verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let error_report = verify_and_parse_inner_jws(&jws.into_bytes()).unwrap_err();

        assert_eq!(
            error_report.downcast::<ClientError>().unwrap(),
            ClientError {
                code: ErrorCode::InvalidToken,
                internal_debug_info: "JWS is expired".to_string()
            }
        );
    }

    #[test]
    fn test_jws_without_a_valid_exp_is_rejected() {
        // TODO: Replace once we use actual keys
        let verifier_private_key = "-----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFU28VNv+wsvcC0rR
    5n05rAs2xRxfmbHzDjEQdQqvRSmhRANCAAT4P6kKoEaZq6108t78Pyi357T8RJy/
    gyCLKWWNJZlQ/NBTSekcw1M7xn2Z45Mdres5E7dzazXiC75Zzl4p2+gf
    -----END PRIVATE KEY-----";

        // Generate a JWS without an expiration claim
        let mut payload = JwtPayload::new();
        payload.set_subject("sub");

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = ES256.signer_from_pem(verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let error_report = verify_and_parse_inner_jws(&jws.into_bytes()).unwrap_err();

        assert_eq!(
            error_report.to_string(),
            "Unexpected token format, invalid exp claim."
        );
    }
}
