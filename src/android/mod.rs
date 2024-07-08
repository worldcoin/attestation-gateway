use std::time::{Duration, SystemTime};

use crate::utils::{BundleIdentifier, ErrorCode, RequestError};
use integrity_token_data::{AppIntegrityVerdict, PlayIntegrityToken};
use josekit::jwe::{self, A256KW};
use josekit::jws::ES256;

mod integrity_token_data;

// TODO const TOKEN_MAX_AGE: u64 = 10 * 600;
const TOKEN_MAX_AGE: u64 = 10_000_000_000_000;

pub fn verify_token(
    integrity_token: &str,
    bundle_identifier: &BundleIdentifier,
    request_hash: &str,
) -> Result<(), RequestError> {
    let decrypted_jws = decrypt_outer_jwe(integrity_token)?;

    let integrity_payload = verify_and_parse_inner_jws(&decrypted_jws)?;

    // SECTION --- Request details checks ---

    if integrity_payload.request_details.request_package_name != bundle_identifier.to_string() {
        return Err(RequestError {
            code: ErrorCode::InvalidBundleIdentifier,
            internal_details: Some(
                "Provided `bundle_identifier` does not match request_details.request_package_name"
                    .to_string(),
            ),
        });
    }

    if integrity_payload.request_details.nonce != request_hash {
        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            internal_details: Some(
                "Provided `request_hash` does not match request_details.nonce".to_string(),
            ),
        });
    }

    println!("{:?}", integrity_payload.request_details.timestamp_millis);

    let timestamp_millis: SystemTime = match integrity_payload
        .request_details
        .timestamp_millis
        .parse::<u64>()
    {
        Ok(value) => SystemTime::UNIX_EPOCH + Duration::from_secs(value / 1000),
        Err(_e) => {
            return Err(RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some("Could not parse timestamp_millis".to_string()),
            });
        }
    };

    let duration = match SystemTime::now().duration_since(timestamp_millis) {
        Ok(value) => value,
        Err(_e) => {
            return Err(RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some(
                    "Could not calculate timestamp_millis difference".to_string(),
                ),
            });
        }
    };

    if duration.as_secs() > TOKEN_MAX_AGE {
        return Err(RequestError {
            code: ErrorCode::ExpiredToken,
            internal_details: Some(
                "The timestamp_millis of the token is older than the TOKEN_MAX_AGE".to_string(),
            ),
        });
    }

    // SECTION --- App integrity checks ---

    if integrity_payload.app_integrity.package_name != bundle_identifier.to_string() {
        return Err(RequestError {
            code: ErrorCode::InvalidBundleIdentifier,
            internal_details: Some(
                "Provided `bundle_identifier` does not match app_integrity.package_name"
                    .to_string(),
            ),
        });
    }

    if integrity_payload.app_integrity.app_recognition_verdict
        != AppIntegrityVerdict::PlayRecognized
    {
        return Err(RequestError {
            code: ErrorCode::IntegrityFailed,
            internal_details: Some("AppIntegrityVerdict does not match PlayRecognized".to_string()),
        });
    }

    Ok(())
}

/// Decrypts the outer JWE (JSON Web Encryption) token using the AES secret provided by Google for each bundle identifier
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
fn decrypt_outer_jwe(integrity_token: &str) -> Result<Vec<u8>, RequestError> {
    // FIXME: These are temporary keys for local development
    let private_key = b"7d5b44298bf959af149a0086d79334e6";

    // Decrypt the outer JWE
    let decrypter = match A256KW.decrypter_from_bytes(private_key) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!("A256KW error: {e}");
            return Err(RequestError {
                code: ErrorCode::InternalServerError,
                internal_details: Some("A256KW error".to_string()),
            });
        }
    };
    let (compact_jws, _headers) = match jwe::deserialize_compact(integrity_token, &decrypter) {
        Ok(payload) => payload,
        Err(e) => {
            // We log a debug because this is a client error (provided an invalidly encrypted token)
            tracing::debug!("Android JWE failed decryption: {e}");
            return Err(RequestError {
                code: ErrorCode::InvalidToken,
                internal_details: Some("JWE failed decryption".to_string()),
            });
        }
    };

    Ok(compact_jws)
}

/// Verifies the signature of the inner JWS (as well as expiration) and parses the payload into a `PlayIntegrityToken` struct
/// <https://developer.android.com/google/play/integrity/classic#kotlin>
///
fn verify_and_parse_inner_jws(compact_jws: &Vec<u8>) -> Result<PlayIntegrityToken, RequestError> {
    // FIXME: These are temporary keys for local development
    let verifier_key = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+D+pCqBGmautdPLe/D8ot+e0/ESc
v4MgiylljSWZUPzQU0npHMNTO8Z9meOTHa3rORO3c2s14gu+Wc5eKdvoHw==
-----END PUBLIC KEY-----";

    let verifier = match ES256.verifier_from_pem(verifier_key) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!("ES256 error: {e}");
            return Err(RequestError {
                code: ErrorCode::InternalServerError,
                internal_details: Some("ES256 error".to_string()),
            });
        }
    };

    let (jws, _headers) = match josekit::jwt::decode_with_verifier(compact_jws, &verifier) {
        Ok(value) => value,
        Err(e) => {
            // This is **not** expected because the JWE is encrypted with a symmetric secret
            tracing::error!("JWS signature could not be verified: {e}.");
            return Err(RequestError {
                code: ErrorCode::InternalServerError,
                internal_details: Some("JWS signature could not be verified".to_string()),
            });
        }
    };

    // Verify expiration
    match jws.expires_at() {
        Some(value) => {
            match value.duration_since(SystemTime::now()) {
                Ok(_value) => (),
                Err(_e) => {
                    return Err(RequestError {
                        code: ErrorCode::InvalidToken,
                        internal_details: Some("JWS is expired".to_string()),
                    });
                }
            };
        }
        None => {
            return Err(RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some("JWS does not have a valid `exp` claim".to_string()),
            });
        }
    }

    // Parse the JWS

    let integrity_payload = match jws.claim("payload") {
        Some(value) => value.to_string(),
        None => {
            return Err(RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some("JWT does not have a `payload` attribute".to_string()),
            });
        }
    };

    let integrity_payload: PlayIntegrityToken = match serde_json::from_str(&integrity_payload) {
        Ok(value) => value,
        Err(e) => {
            // This is **not** an expected client error, because this is a signed and encrypted token, suggests Google is sending an attribute incorrectly
            tracing::error!("Received invalid token payload: {e}. Payload: {integrity_payload}");
            return Err(RequestError {
                code: ErrorCode::UnexpectedTokenFormat,
                internal_details: Some("Failure parsing integrity payload".to_string()),
            });
        }
    };

    Ok(integrity_payload)
}

#[cfg(test)]
mod tests {

    use std::time::{Duration, SystemTime};

    use super::{verify_and_parse_inner_jws, verify_token};
    use crate::utils::{BundleIdentifier, ErrorCode, RequestError};
    use josekit::jwe::{self, JweHeader, A256KW};
    use josekit::jws::{JwsHeader, ES256};
    use josekit::jwt::{self, JwtPayload};
    use tracing_test::traced_test;

    // SECTION - JWE tests

    #[traced_test]
    #[test]
    fn test_invalid_jwe_fails_verification() -> Result<(), ()> {
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
                Err(RequestError {
                    code: ErrorCode::InvalidToken,
                    internal_details: Some(ref reason)
                }) if reason == "JWE failed decryption"
            ),
            "Token decryption should have failed."
        );

        assert!(logs_contain("Android JWE failed decryption: "));

        Ok(())
    }

    #[test]
    fn test_invalid_encryption_algorithm() -> Result<(), ()> {
        // TODO
        Ok(())
    }

    // SECTION - JWS tests

    #[traced_test]
    #[test]
    fn test_invalid_jws_signature_verification() -> Result<(), ()> {
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

        let signer = ES256.signer_from_pem(&verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let _subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_test_writer()
            .finish();

        let result = verify_and_parse_inner_jws(&jws.into_bytes().to_vec());

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

        assert!(logs_contain("JWS signature could not be verified: "));

        Ok(())
    }

    #[test]
    fn test_expired_jws_fails_verification() -> Result<(), ()> {
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

        let signer = ES256.signer_from_pem(&verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let result = verify_and_parse_inner_jws(&jws.into_bytes().to_vec());

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

        Ok(())
    }

    #[test]
    fn test_jws_without_a_valid_exp_is_rejected() -> Result<(), ()> {
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

        let signer = ES256.signer_from_pem(&verifier_private_key).unwrap();

        let jws = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let result = verify_and_parse_inner_jws(&jws.into_bytes().to_vec());

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

        Ok(())
    }
}
