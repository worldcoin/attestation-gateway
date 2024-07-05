use crate::utils::{BundleIdentifier, RequestError};
use josekit::jwe::{self, A256KW};
use josekit::jws::HS256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct PlayIntegrityClaims {
    sub: String,
    iss: String,
    aud: String,
}

pub fn verify_token(
    integrity_token: &String,
    bundle_identifier: &BundleIdentifier,
) -> Result<(), RequestError> {
    // FIXME: These are temporary keys for local development
    let private_key = b"7d5b44298bf959af149a0086d79334e6";
    let verifier_key = b"cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2";

    // Decrypt the outer JWE
    let decrypter = match A256KW.decrypter_from_bytes(private_key) {
        Ok(decrypter) => decrypter,
        Err(e) => {
            tracing::error!("A256KW error: {e}");
            return Err(RequestError::InternalServerError);
        }
    };
    let (compact_jws, _headers) = match jwe::deserialize_compact(&integrity_token, &decrypter) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::info!("Received Android JWE failed decryption: {e}");
            return Err(RequestError::InvalidToken);
        }
    };

    // Verify the JWS and extract the payload

    let verifier = HS256.verifier_from_bytes(&verifier_key).unwrap();
    let (payload, _headers) = josekit::jwt::decode_with_verifier(&compact_jws, &verifier).unwrap();

    println!("{:?}", payload.claim("sub"));

    println!(
        "Verifying Android token: {} - {}",
        integrity_token, bundle_identifier
    );

    Ok(())
}

#[cfg(test)]
mod tests {

    use josekit::jwe::{self, JweHeader, A256KW};

    use crate::utils::{BundleIdentifier, RequestError};

    use super::verify_token;

    // SECTION - JWE tests

    #[test]
    fn test_invalid_jwe_fails_verification() -> Result<(), ()> {
        let other_private_key = b"caba71cf1b1e3896136dc70301c0613f";

        let encrypter = A256KW.encrypter_from_bytes(other_private_key).unwrap();

        let mut headers = JweHeader::new();
        headers.set_algorithm("A256KW");
        headers.set_content_encryption("A256GCM");

        let test_jwe = jwe::serialize_compact(b"test", &headers, &encrypter).unwrap();

        // TODO: Assert tracing info

        match verify_token(&test_jwe, &BundleIdentifier::AndroidStageWorldApp) {
            Ok(()) => panic!("Token decryption should have failed."),
            Err(e) => {
                assert_eq!(e, RequestError::InvalidToken);
                return Ok(());
            }
        }
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
