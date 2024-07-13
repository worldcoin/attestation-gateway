use crate::utils::{ErrorCode, RequestError};
use aws_sdk_kms::{primitives::Blob, Error};
use josekit::{
    jws::{alg::ecdsa::EcdsaJwsAlgorithm, JwsAlgorithm, JwsHeader, JwsSigner},
    jwt::{self, JwtPayload},
    util::der::{DerReader, DerType},
    JoseError,
};
use tokio::runtime::Runtime;

#[derive(Debug, Clone)]
pub struct EcdsaJwsSignerWithKms {
    algorithm: EcdsaJwsAlgorithm,
    key_arn: String,
    kms_client: aws_sdk_kms::Client,
}

/// Implement the `JwsSigner` trait for `EcdsaJwsSignerWithKms` to be able to have a custom `sign` method which relies on KMS instead of local keys
impl JwsSigner for EcdsaJwsSignerWithKms {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        // SHA-256 with ECDSA generates a 64-byte signature
        64
    }

    /// Extracts the key ID from the key ARN
    fn key_id(&self) -> Option<&str> {
        let parts: Vec<&str> = self.key_arn.split('/').collect();
        assert!(
            !(!parts.len() == 2 && parts[1].contains('-')),
            "Unexpected key ARN."
        );
        Some(parts[1])
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
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
        .map_err(JoseError::InvalidSignature)
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

async fn sign_with_kms(
    client: &aws_sdk_kms::Client,
    key_id: &str,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let result = client
        .sign()
        .key_id(key_id)
        .message(Blob::new(message))
        .message_type(aws_sdk_kms::types::MessageType::Raw)
        .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
        .send()
        .await?;

    // TODO: Improve error handling
    Ok(result.signature.unwrap().as_ref().to_vec())
}

/// Generate the output JWS token from the Attestation Gateway using the provided KMS client and key ARN
///
/// # Errors
///
/// This function will return a `RequestError` if the JWS signature generation fails
pub async fn generate_output_token(
    kms_client: aws_sdk_kms::Client,
    key_arn: String,
    payload: JwtPayload,
) -> Result<String, RequestError> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let signer = EcdsaJwsSignerWithKms {
        algorithm: EcdsaJwsAlgorithm::Es256,
        key_arn,
        kms_client,
    };

    let jwt =
        tokio::task::spawn_blocking(move || jwt::encode_with_signer(&payload, &header, &signer))
            .await
            .map_err(|e| {
                tracing::error!("Error generating JWS signature in tokio task: {:?}", e);
                RequestError {
                    code: ErrorCode::InternalServerError,
                    internal_details: Some("Error generating JWS signature".to_string()),
                }
            })?
            .map_err(|e| {
                tracing::error!("Error generating JWS signature: {:?}", e);
                RequestError {
                    code: ErrorCode::InternalServerError,
                    internal_details: Some("Error generating JWS signature".to_string()),
                }
            })?;

    Ok(jwt)
}
