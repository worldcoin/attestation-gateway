use aws_sdk_kms::primitives::Blob;
use base64::Engine;
use josekit::{
    JoseError,
    jws::{JwsAlgorithm, JwsHeader, JwsSigner},
    jwt::{self, JwtPayload},
    util::der::{DerReader, DerType},
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::utils::SIGNING_CONFIG;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KMSKeyDefinition {
    pub id: String,
    pub arn: String,
}

impl KMSKeyDefinition {
    /// Extracts the key ID from the key ARN
    ///
    /// # Panics
    /// If the provided key ARN is not valid. This should never happen in production and it is a fatal error.
    #[must_use]
    pub fn from_arn(arn: String) -> Self {
        let parts: Vec<&str> = arn.split('/').collect();
        assert!(
            !(!parts.len() == 2 && parts[1].contains('-')),
            "Unexpected key ARN."
        );

        let mut hasher = openssl::sha::Sha224::new();
        hasher.update(parts[1].as_bytes());
        let key_hash = hasher.finish();
        let id = format!(
            "key_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_hash)
        );

        Self { id, arn }
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsSignerWithKms {
    // Fields are public to allow usage in keys/tests.rs
    pub key: KMSKeyDefinition,
    pub kms_client: aws_sdk_kms::Client,
}

/// Implement the `JwsSigner` trait for `EcdsaJwsSignerWithKms` to be able to have a custom `sign` method which relies on KMS instead of local keys
impl JwsSigner for EcdsaJwsSignerWithKms {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &SIGNING_CONFIG.jose_kit_algorithm
    }

    fn signature_len(&self) -> usize {
        SIGNING_CONFIG.signature_len
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.key.id)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> eyre::Result<Vec<u8>> {
            // NOTE: We skip hashing because KMS will hash the message

            let rt = Runtime::new().unwrap();
            let der_signature = rt.block_on(async {
                // NOTE: KMS signing is async, so we need to block the current thread
                sign_with_kms(&self.kms_client, &self.key.arn, message).await
            })?;

            // NOTE: Code below is kept as is from the original `josekit` implementation

            let signature_len = self.signature_len();
            let sep = signature_len / 2;

            let mut signature = Vec::with_capacity(signature_len);
            let mut reader = DerReader::from_bytes(&der_signature);
            match reader.next()? {
                Some(DerType::Sequence) => {}
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    signature.extend_from_slice(&reader.to_be_bytes(false, sep));
                }
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    signature.extend_from_slice(&reader.to_be_bytes(false, sep));
                }
                _ => unreachable!("A generated signature is invalid."),
            }

            Ok(signature)
        })()
        // Convert eyre error to anyhow which is required for JoseError
        .map_err(|e| JoseError::InvalidSignature(anyhow::anyhow!(e)))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

async fn sign_with_kms(
    client: &aws_sdk_kms::Client,
    key_id: &str,
    message: &[u8],
) -> eyre::Result<Vec<u8>> {
    // We could technically fetch the key ID after signing using a key alias but the `kid` must be known before signing
    let result = client
        .sign()
        .key_id(key_id)
        .message(Blob::new(message))
        .message_type(aws_sdk_kms::types::MessageType::Raw)
        .signing_algorithm(SIGNING_CONFIG.kms_algorithm)
        .send()
        .await?;

    result.signature.map_or_else(
        || Err(eyre::eyre!("No signature returned from KMS")),
        |signature| Ok(signature.as_ref().to_vec()),
    )
}

/// Generate the output JWS token from the Attestation Gateway using the provided KMS client and key ARN
///
/// # Errors
///
/// This function will return a `RequestError` if the JWS signature generation fails
pub async fn generate_output_token(
    aws_config: &aws_config::SdkConfig,
    key_arn: String,
    payload: JwtPayload,
) -> eyre::Result<String> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let kms_client = aws_sdk_kms::Client::new(aws_config);

    let key = KMSKeyDefinition::from_arn(key_arn);

    let signer = EcdsaJwsSignerWithKms { key, kms_client };

    let jwt =
        tokio::task::spawn_blocking(move || jwt::encode_with_signer(&payload, &header, &signer))
            .await??;

    Ok(jwt)
}

#[cfg(test)]
mod tests;
