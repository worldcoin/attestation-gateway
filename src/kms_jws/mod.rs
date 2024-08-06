use aws_sdk_kms::primitives::Blob;
use base64::Engine;
use josekit::{
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, JwsAlgorithm, JwsHeader, JwsSigner},
    jwt::{self, JwtPayload},
    util::der::{DerReader, DerType},
    JoseError,
};
use tokio::runtime::Runtime;

#[derive(Debug, Clone)]
pub struct EcdsaJwsSignerWithKms {
    key_arn: String,
    kms_client: aws_sdk_kms::Client,
    key_id: String,
}

impl EcdsaJwsSignerWithKms {
    /// Initializes a new `EcdsaJwsSignerWithKms` instance while parsing the `key_arn` to generate the `key_id`
    /// Extracts the key ID from the key ARN
    fn new(key_arn: String, kms_client: aws_sdk_kms::Client) -> Self {
        let parts: Vec<&str> = key_arn.split('/').collect();
        assert!(
            !(!parts.len() == 2 && parts[1].contains('-')),
            "Unexpected key ARN."
        );

        let mut hasher = openssl::sha::Sha224::new();
        hasher.update(parts[1].as_bytes());
        let key_hash = hasher.finish();
        let key_id = format!(
            "key_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_hash)
        );

        Self {
            key_arn,
            kms_client,
            key_id,
        }
    }
}

/// Implement the `JwsSigner` trait for `EcdsaJwsSignerWithKms` to be able to have a custom `sign` method which relies on KMS instead of local keys
impl JwsSigner for EcdsaJwsSignerWithKms {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &EcdsaJwsAlgorithm::Es256
    }

    fn signature_len(&self) -> usize {
        // SHA-256 with ECDSA generates a 64-byte signature
        64
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.key_id)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> eyre::Result<Vec<u8>> {
            // NOTE: We skip hashing because KMS will hash the message

            let rt = Runtime::new().unwrap();
            let der_signature = rt.block_on(async {
                // NOTE: KMS signing is async, so we need to block the current thread
                sign_with_kms(&self.kms_client, &self.key_arn, message).await
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
    let result = client
        .sign()
        .key_id(key_id)
        .message(Blob::new(message))
        .message_type(aws_sdk_kms::types::MessageType::Raw)
        .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
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

    let signer = EcdsaJwsSignerWithKms::new(key_arn, kms_client);

    let jwt =
        tokio::task::spawn_blocking(move || jwt::encode_with_signer(&payload, &header, &signer))
            .await??;

    Ok(jwt)
}

#[cfg(test)]
mod tests;
