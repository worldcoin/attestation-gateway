use crate::utils::{BundleIdentifier, RequestError};
use biscuit::jwa::ContentEncryptionAlgorithm;
use biscuit::jwa::KeyManagementAlgorithm;
use biscuit::jwk::JWK;
use biscuit::Empty;
use biscuit::JWE;
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
    let private_key = b"7d5b44298bf959af149a0086d79334e6";

    let encrypted_jwe: JWE<PlayIntegrityClaims, Empty, Empty> =
        JWE::new_encrypted(&integrity_token);

    let key: JWK<Empty> = JWK::new_octet_key(&private_key.to_vec(), Default::default());

    let decrypted_jwe = encrypted_jwe
        .into_decrypted(
            &key,
            KeyManagementAlgorithm::A256KW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        // TODO: Don't unwrap
        .unwrap();

    // .setProtectedHeader({ alg: "A256KW", enc: "A256GCM" })
    // let decrypted_jws = decrypted_jwe.payload().unwrap();

    // println!("{:?}", decrypted_jws);

    println!(
        "Verifying Android token: {} - {}",
        integrity_token, bundle_identifier
    );

    if integrity_token != "my_integrity_token" {
        return Err(RequestError::InvalidToken);
    }

    Ok(())
}
