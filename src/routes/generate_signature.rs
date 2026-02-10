use axum::Extension;
use axum_jsonschema::Json;
use eyre::ContextCompat;

use base64::Engine;

const ATTESTATION_GATEWAY_MESSAGE_V1: &[u8] = "ATTESTATION_GATEWAY_MESSAGE_V1".as_bytes();

use crate::{
    apple,
    utils::{
        BundleIdentifier, ErrorCode, GlobalConfig, RequestError, SignatureGenerationRequest,
        SignatureGenerationResponse,
    },
};

pub async fn handler(
    Extension(global_config): Extension<GlobalConfig>,
    Json(request): Json<SignatureGenerationRequest>,
) -> Result<Json<SignatureGenerationResponse>, RequestError> {
    let my_span = tracing::span!(tracing::Level::DEBUG, "generate_signature", endpoint = "/h");

    let _enter = my_span.enter();

    if !global_config
        .enabled_bundle_identifiers
        .contains(&request.bundle_identifier)
    {
        return Err(RequestError {
            code: ErrorCode::BadRequest,
            details: Some("This bundle identifier is currently unavailable.".to_string()),
        });
    }

    let device_public_key = match request.bundle_identifier {
        BundleIdentifier::IOSProdWorldApp | BundleIdentifier::IOSStageWorldApp => {
            let app_id = request
                .bundle_identifier
                .apple_app_id()
                .context("".to_string())
                .map_err(|_| RequestError {
                    code: ErrorCode::BadRequest,
                    details: Some("Invalid bundle identifier".to_string()),
                })?;

            let allowed_aaguid_vec = apple::AAGUID::allowed_for_bundle_identifier(
                &request.bundle_identifier,
            )
            .map_err(|_| RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Invalid bundle identifier".to_string()),
            })?;

            let initial_attestation = apple::decode_and_validate_initial_attestation(
                request.attested_certificate,
                &request.timestamp,
                app_id,
                &allowed_aaguid_vec.as_slice(),
            )
            .map_err(|e| RequestError {
                code: ErrorCode::BadRequest,
                details: Some(e.to_string()),
            })?;

            initial_attestation.key_public_key
        }
        _ => {
            return Err(RequestError {
                code: ErrorCode::InvalidInitialAttestation,
                details: Some("Not supported bundle identifier".to_string()),
            });
        }
    };

    let enrollment_commitment_fe = request
        .enrollment_commitment
        .parse::<world_id_primitives::FieldElement>()
        .map_err(|_| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Invalid enrollment commitment hex".to_string()),
        })?;

    let device_public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(device_public_key.clone())
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Invalid device public key base64".to_string()),
        })?;

    let device_public_key_fe =
        hash_bytes_fe_empty_tag(&device_public_key_bytes).map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to hash device public key".to_string()),
        })?;

    let message_hash = poseidon_hash_sequence(
        ATTESTATION_GATEWAY_MESSAGE_V1,
        &[enrollment_commitment_fe, device_public_key_fe],
    )
    .map_err(|_| RequestError {
        code: ErrorCode::InternalServerError,
        details: Some("Failed to hash message".to_string()),
    })?;

    let gateway_signature_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(global_config.gateway_signature_key)
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to decode signature key".to_string()),
        })?;
    let gateway_signature_key_bytes_const: [u8; 32] = gateway_signature_key_bytes[0..32]
        .try_into()
        .map_err(|_| RequestError {
            code: ErrorCode::InternalServerError,
            details: Some("Failed to convert signature key to bytes".to_string()),
        })?;

    let attestation_gateway_signature_bytes =
        taceo_eddsa_babyjubjub::EdDSAPrivateKey::from_bytes(gateway_signature_key_bytes_const)
            .sign(*message_hash)
            .to_compressed_bytes()
            .map_err(|_| RequestError {
                code: ErrorCode::InternalServerError,
                details: Some("Failed to sign message".to_string()),
            })?;

    let attestation_gateway_signature =
        base64::engine::general_purpose::STANDARD.encode(attestation_gateway_signature_bytes);

    Ok(Json(SignatureGenerationResponse {
        attestation_gateway_signature,
        device_public_key,
    }))
}

/// Hash arbitrary bytes into a FieldElement using the approved primitive.
/// Uses an empty domain tag so individual nodes are hashed as part of a parent domain separator tag.
/// fold gets an explicit tag via `poseidon_hash_sequence`).
///
/// Special case: empty data hashes to ZERO to avoid errors from the underlying primitive.
fn hash_bytes_fe_empty_tag(
    data: &[u8],
) -> Result<world_id_primitives::FieldElement, world_id_primitives::PrimitiveError> {
    if data.is_empty() {
        return Ok(world_id_primitives::FieldElement::ZERO);
    }

    Ok(world_id_primitives::sponge::hash_bytes_to_field_element(
        b"", data,
    )?)
}

/// Fold an ordered sequence of `FieldElement` values into one `FieldElement`
/// using the SAFE-inspired Poseidon2 sponge primitive.
///
/// Each step computes:
///   acc := hash_bytes_to_field_element(tag, acc_bytes || next_val_bytes)
///
/// Returns an error if the input sequence is empty.
fn poseidon_hash_sequence(
    tag: &[u8],
    values: &[world_id_primitives::FieldElement],
) -> Result<world_id_primitives::FieldElement, world_id_primitives::PrimitiveError> {
    if values.is_empty() {
        return Err(world_id_primitives::PrimitiveError::InvalidInput {
            attribute: "poseidon_hash_sequence".to_string(),
            reason: "Input sequence is empty".to_string(),
        });
    }

    let mut acc = world_id_primitives::FieldElement::ZERO;
    let mut buf = [0u8; 64];

    for value in values {
        let acc_bytes = fe_to_bytes32(&acc)?;
        let value_bytes = fe_to_bytes32(value)?;

        buf[0..32].copy_from_slice(&acc_bytes);
        buf[32..].copy_from_slice(&value_bytes);

        acc = world_id_primitives::sponge::hash_bytes_to_field_element(tag, &buf)?;
    }

    Ok(acc)
}

/// Serialize a FieldElement to exactly 32 bytes (canonical compressed form).
fn fe_to_bytes32(
    fe: &world_id_primitives::FieldElement,
) -> Result<[u8; 32], world_id_primitives::PrimitiveError> {
    let mut v = Vec::with_capacity(32);
    fe.serialize_as_bytes(&mut v)?;
    if v.len() != 32 {
        return Err(world_id_primitives::PrimitiveError::InvalidInput {
            attribute: "poseidon_hash_sequence".to_string(),
            reason: "FieldElement did not serialize to 32 bytes".to_string(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
