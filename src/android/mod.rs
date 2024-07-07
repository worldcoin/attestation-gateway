use crate::utils::{BundleIdentifier, RequestError};
use integrity_token_data::PlayIntegrityToken;
use josekit::jwe::{self, A256KW};
use josekit::jws::ES256;

mod integrity_token_data;

pub fn verify_token(
    integrity_token: &str,
    bundle_identifier: &BundleIdentifier,
) -> Result<(), RequestError> {
    let decrypted_jws = decrypt_outer_jwe(integrity_token)?;

    let integrity_payload = verify_and_parse_inner_jws(&decrypted_jws)?;

    // --- requestHash matches ---
    if integrity_payload.request_details.request_package_name != bundle_identifier.to_string() {
        return Err(RequestError::InvalidBundleIdentifier);
    }

    Ok(())
}

/// Decrypts the outer JWE (JSON Web Encryption) token using the AES secret provided by Google for each bundle identifier
/// https://developer.android.com/google/play/integrity/classic#kotlin
fn decrypt_outer_jwe(integrity_token: &str) -> Result<Vec<u8>, RequestError> {
    // FIXME: These are temporary keys for local development
    let private_key = b"7d5b44298bf959af149a0086d79334e6";

    // Decrypt the outer JWE
    let decrypter = match A256KW.decrypter_from_bytes(private_key) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!("A256KW error: {e}");
            return Err(RequestError::InternalServerError);
        }
    };
    let (compact_jws, _headers) = match jwe::deserialize_compact(integrity_token, &decrypter) {
        Ok(payload) => payload,
        Err(e) => {
            // We log an info because this is a client error (provided an invalidly encrypted token)
            tracing::info!("Received Android JWE failed decryption: {e}");
            return Err(RequestError::InvalidToken);
        }
    };

    Ok(compact_jws)
}

/// Verifies the signature of the inner JWS (as well as expiration) and parses the payload into a PlayIntegrityToken struct
/// https://developer.android.com/google/play/integrity/classic#kotlin
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
            return Err(RequestError::InternalServerError);
        }
    };

    let (jws, _headers) = match josekit::jwt::decode_with_verifier(compact_jws, &verifier) {
        Ok(value) => value,
        Err(e) => {
            // We log an info because this is a client error (provided an invalidly signed token)
            tracing::info!("Received Android JWS with invalid signature: {e}");
            return Err(RequestError::InvalidToken);
        }
    };

    // Parse the JWS

    let integrity_payload = match jws.claim("payload") {
        Some(value) => value.to_string(),
        None => {
            return Err(RequestError::InvalidToken);
        }
    };

    let integrity_payload: PlayIntegrityToken = match serde_json::from_str(&integrity_payload) {
        Ok(value) => value,
        Err(e) => {
            // This is not an expected client error, because this is a signed and encrypted token, suggests Google is sending an attribute incorrectly
            tracing::error!("Received invalid token payload: {e}. Payload: {integrity_payload}");
            return Err(RequestError::InternalServerError);
        }
    };

    Ok(integrity_payload)
}

#[cfg(test)]
mod tests {

    use super::verify_token;
    use crate::utils::{BundleIdentifier, RequestError};
    use josekit::jwe::{self, JweHeader, A256KW};
    use tracing_test::traced_test;

    // SECTION - JWE tests

    #[traced_test]
    #[test]
    fn test_invalid_jwe_fails_verification() -> Result<(), ()> {
        let other_private_key = b"caba71cf1b1e3896136dc70301c0613f";

        let encrypter = A256KW.encrypter_from_bytes(other_private_key).unwrap();

        let mut headers = JweHeader::new();
        headers.set_algorithm("A256KW");
        headers.set_content_encryption("A256GCM");

        let test_jwe = jwe::serialize_compact(b"test", &headers, &encrypter).unwrap();

        let _subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_test_writer()
            .finish();

        let result = verify_token(&test_jwe, &BundleIdentifier::AndroidStageWorldApp);

        assert!(
            matches!(result, Err(RequestError::InvalidToken)),
            "Token decryption should have failed."
        );

        assert!(logs_contain("Received Android JWE failed decryption: "));

        Ok(())
    }

    #[test]
    fn test_invalid_encryption_algorithm() -> Result<(), ()> {
        // TODO
        Ok(())
    }

    // SECTION - JWS tests

    #[test]
    fn test_invalid_signature_verification() -> Result<(), ()> {
        // TODO
        Ok(())
    }

    #[test]
    fn test_expired_jws_fails_verification() -> Result<(), ()> {
        // TODO
        Ok(())
    }
}
