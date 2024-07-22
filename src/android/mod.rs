use std::time::SystemTime;

use crate::utils::{BundleIdentifier, ErrorCode, RequestError};
pub use integrity_token_data::{PlayIntegrityToken, RequestErrorWithIntegrityToken};
use josekit::jwe::{self, A256KW};
use josekit::jws::ES256;

mod integrity_token_data;

/// Verifies an Android Play Integrity token and returns a parsed `PlayIntegrityToken`
///
/// # Errors
///
/// If the token is invalid, expired, or otherwise fails verification, a `RequestErrorWithIntegrityToken` is returned,
/// when the token passes basic parsing but integrity checks fail, the failed payload is returned in the `failed_integrity_token` attribute of the error.
pub fn verify_token(
    integrity_token: &str,
    bundle_identifier: &BundleIdentifier,
    request_hash: &str,
) -> Result<PlayIntegrityToken, RequestErrorWithIntegrityToken> {
    let decrypted_jws =
        decrypt_outer_jwe(integrity_token).map_err(handle_request_error_with_integrity_token)?;

    let play_integrity_payload = verify_and_parse_inner_jws(&decrypted_jws)
        .map_err(handle_request_error_with_integrity_token)?;

    PlayIntegrityToken::new(&play_integrity_payload, bundle_identifier, request_hash)
}

fn handle_request_error_with_integrity_token(e: RequestError) -> RequestErrorWithIntegrityToken {
    RequestErrorWithIntegrityToken {
        request_error: RequestError {
            code: e.code,
            internal_details: e.internal_details,
        },
        failed_integrity_token: None,
    }
}

/// Decrypts the outer JWE (JSON Web Encryption) token using the AES secret provided by Google for each bundle identifier
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
fn decrypt_outer_jwe(integrity_token: &str) -> Result<Vec<u8>, RequestError> {
    // FIXME: These are temporary keys for local development
    let private_key = b"7d5b44298bf959af149a0086d79334e6";

    // Decrypt the outer JWE
    let decrypter = A256KW.decrypter_from_bytes(private_key).map_err(|e| {
        tracing::error!(?e, "A256KW error.");
        RequestError {
            code: ErrorCode::InternalServerError,
            internal_details: Some("A256KW error".to_string()),
        }
    })?;

    let (compact_jws, _) = jwe::deserialize_compact(integrity_token, &decrypter).map_err(|e| {
        tracing::debug!("Android JWE failed decryption: {e}");
        RequestError {
            code: ErrorCode::InvalidToken,
            internal_details: Some("JWE failed decryption".to_string()),
        }
    })?;

    Ok(compact_jws)
}

/// Verifies the signature of the inner JWS (as well as expiration) and parses the payload into a `PlayIntegrityToken` struct
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
///
fn verify_and_parse_inner_jws(compact_jws: &[u8]) -> Result<String, RequestError> {
    // FIXME: These are temporary keys for local development
    let verifier_key = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+D+pCqBGmautdPLe/D8ot+e0/ESc
v4MgiylljSWZUPzQU0npHMNTO8Z9meOTHa3rORO3c2s14gu+Wc5eKdvoHw==
-----END PUBLIC KEY-----";

    let verifier = ES256.verifier_from_pem(verifier_key).map_err(|e| {
        tracing::error!(?e, "ES256 error.");

        RequestError {
            code: ErrorCode::InternalServerError,
            internal_details: Some("ES256 error".to_string()),
        }
    })?;

    let (jws, _) = josekit::jwt::decode_with_verifier(compact_jws, &verifier).map_err(|e| {
        // This is **not** expected because the JWE is encrypted with a symmetric secret
        tracing::error!(?e, "JWS signature could not be verified.");

        RequestError {
            code: ErrorCode::InternalServerError,
            internal_details: Some("JWS signature could not be verified".to_string()),
        }
    })?;

    // Verify expiration
    jws.expires_at()
        .ok_or_else(|| RequestError {
            code: ErrorCode::UnexpectedTokenFormat,
            internal_details: Some("JWS does not have a valid `exp` claim".to_string()),
        })
        .and_then(|value| {
            value
                .duration_since(SystemTime::now())
                .map_err(|_| RequestError {
                    code: ErrorCode::InvalidToken,
                    internal_details: Some("JWS is expired".to_string()),
                })
        })?;

    // Parse the JWS

    let Some(integrity_payload) = jws.claim("payload") else {
        return Err(RequestError {
            code: ErrorCode::UnexpectedTokenFormat,
            internal_details: Some("JWT does not have a `payload` attribute".to_string()),
        });
    };

    Ok(integrity_payload.to_string())
}

#[cfg(test)]
mod tests {

    use super::{verify_and_parse_inner_jws, verify_token, RequestErrorWithIntegrityToken};
    use crate::utils::{BundleIdentifier, ErrorCode, RequestError};
    use josekit::jwe::{self, JweHeader, A256KW};
    use josekit::jws::{JwsHeader, ES256};
    use josekit::jwt::{self, JwtPayload};
    use std::time::{Duration, SystemTime};
    use tracing_test::traced_test;

    // SECTION - JWE tests

    #[traced_test]
    #[test]
    fn test_invalid_jwe_fails_verification() {
        // Generate and encrypt a JWE with an unexpected key
        let other_private_key = b"caba71cf1b1e3896136dc70301c0613f";

        let encrypter = A256KW.encrypter_from_bytes(other_private_key).unwrap();

        let mut headers = JweHeader::new();
        headers.set_algorithm("A256KW");
        headers.set_content_encryption("A256GCM");

        let test_jwe = jwe::serialize_compact(b"test", &headers, &encrypter).unwrap();

        let _subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_test_writer()
            .finish();

        let result = verify_token(&test_jwe, &BundleIdentifier::AndroidStageWorldApp, "test");

        // Now we assert the JWE failed decryption
        assert!(
            matches!(
                result,
                Err(RequestErrorWithIntegrityToken {
                    request_error: RequestError {
                        code: ErrorCode::InvalidToken,
                        internal_details: Some(ref reason)
                    },
                    failed_integrity_token: _
                }) if reason == "JWE failed decryption"
            ),
            "Token decryption should have failed."
        );

        assert!(logs_contain("Android JWE failed decryption: "));
    }

    #[test]
    fn test_invalid_encryption_algorithm() {
        // TODO
    }

    // SECTION - JWS tests

    #[traced_test]
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

        let _subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_test_writer()
            .finish();

        let result = verify_and_parse_inner_jws(&jws.into_bytes());

        assert!(
            matches!(
                result,
                Err(RequestError {
                    code: ErrorCode::InternalServerError,
                    internal_details: Some(ref reason)
                }) if reason == "JWS signature could not be verified"
            ),
            "JWS signature verification should have failed."
        );

        assert!(logs_contain("JWS signature could not be verified."));
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

        let result = verify_and_parse_inner_jws(&jws.into_bytes());

        assert!(
            matches!(
                result,
                Err(RequestError {
                    code: ErrorCode::InvalidToken,
                    internal_details: Some(ref reason)
                }) if reason == "JWS is expired"
            ),
            "JWS signature verification should have failed."
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

        let result = verify_and_parse_inner_jws(&jws.into_bytes());

        assert!(
            matches!(
                result,
                Err(RequestError {
                    code: ErrorCode::UnexpectedTokenFormat,
                    internal_details: Some(ref reason)
                }) if reason == "JWS does not have a valid `exp` claim"
            ),
            "JWS parsing should have failed."
        );
    }
}
