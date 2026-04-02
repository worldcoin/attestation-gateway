use std::time::SystemTime;

use aws_config::SdkConfig;

use axum::{Extension, Json};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, Utc};
use josekit::jwt::JwtPayload;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    sha::sha256,
};
use redis::aio::ConnectionManager;
use schemars::JsonSchema;

use crate::{
    android::AndroidAttestationService,
    apple, keys, kms_jws,
    nonces::{NonceDb, NonceDbError},
    utils::{BundleIdentifier, ErrorCode, GlobalConfig, Platform, RequestError},
};

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub nonce: String,
    pub app_version: String,
    pub bundle_identifier: BundleIdentifier,
    pub apple_attestation: Option<String>,
    pub android_attestation: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Response {
    pub integrity_token: String,
}

#[derive(Debug)]
pub struct IntegrityTokenPayload {
    pub v: String,
    pub platform: Platform,
    pub app_version: String,
    pub aud: String,
    pub cnf: Vec<u8>,
    pub pass: bool,
    pub exp: DateTime<Utc>,
}

impl IntegrityTokenPayload {
    pub fn generate(&self) -> eyre::Result<JwtPayload> {
        if self.cnf.len() != 65 {
            return Err(eyre::eyre!("Invalid device public key"));
        }

        let cnf_ec_key = EcKey::from_public_key_affine_coordinates(
            &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
            &BigNum::from_slice(&self.cnf[1..33]).unwrap(),
            &BigNum::from_slice(&self.cnf[33..65]).unwrap(),
        )
        .map_err(|_| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Invalid device public key".to_string()),
        })?;

        let cnf_pkey = PKey::from_ec_key(cnf_ec_key).map_err(|_| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Invalid device public key".to_string()),
        })?;

        let cnf_key_id = Base64.encode(sha256(&self.cnf));
        let cnf_jwk = keys::public_key_to_jwk(&cnf_pkey, Some(cnf_key_id))?;

        let mut cfn = josekit::Map::new();
        cfn.insert("jwk".to_string(), josekit::Value::Object(cnf_jwk.into()));

        let mut payload = JwtPayload::new();
        payload.set_issued_at(&SystemTime::now());
        payload.set_issuer("attestation.worldcoin.org"); // TODO: what about attestation.worldcoin.dev?
        payload.set_expires_at(&self.exp.into());
        payload.set_claim("v", Some(josekit::Value::String(self.v.clone())))?;
        payload.set_claim(
            "app_version",
            Some(josekit::Value::String(self.app_version.clone())),
        )?;
        payload.set_claim(
            "platform",
            Some(josekit::Value::String(self.platform.to_string())),
        )?;
        payload.set_claim("aud", Some(josekit::Value::String(self.aud.clone())))?;
        payload.set_claim("cnf", Some(josekit::Value::Object(cfn)))?;
        payload.set_claim("pass", Some(josekit::Value::Bool(self.pass)))?;

        Ok(payload)
    }
}

pub async fn handler(
    Extension(global_config): Extension<GlobalConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(mut nonce_db): Extension<NonceDb>,
    Extension(android_attestation): Extension<AndroidAttestationService>,
    Extension(aws_config): Extension<SdkConfig>,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let tracing_span = tracing::span!(tracing::Level::DEBUG, "a", endpoint = "/a");
    let _enter = tracing_span.enter();

    if !global_config
        .enabled_bundle_identifiers
        .contains(&request.bundle_identifier)
    {
        return Err(RequestError {
            code: ErrorCode::BadRequest,
            details: Some("This bundle identifier is currently unavailable.".to_string()),
        });
    }

    let challenge = format!("n={},av={}", request.nonce, request.app_version);
    let platform = request.bundle_identifier.platform();

    let device_public_key = match platform {
        Platform::AppleIOS => {
            let apple_attestation = request.apple_attestation.ok_or_else(|| RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Apple attestation is required".to_string()),
            })?;

            validate_apple_attestation_and_get_device_public_key(
                &global_config.apple_root_ca_pem,
                &challenge,
                &request.bundle_identifier,
                apple_attestation,
            )?
        }
        Platform::Android => {
            let android_cert_chain = request.android_attestation.ok_or_else(|| RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Android attestation is required".to_string()),
            })?;

            let attestation_result = android_attestation.verify(
                &android_cert_chain,
                &request.nonce,
                &request.app_version,
                &request.bundle_identifier,
            );

            let attestation_output = match attestation_result {
                Ok(attestation_output) => Ok(attestation_output),
                Err(e) => {
                    metrics::counter!("attestation_gateway.android_error",  "reason" => e.reason_tag())
                        .increment(1);

                    if e.is_internal_error() {
                        tracing::error!(error = ?e, "Error validating Android attestation");

                        Err(RequestError {
                            code: ErrorCode::InternalServerError,
                            details: None,
                        })
                    } else {
                        Err(RequestError {
                            code: ErrorCode::BadRequest,
                            details: Some(e.to_string()),
                        })
                    }
                }
            }?;

            if let Some(os_patch_level) = attestation_output.os_patch_level {
                metrics::gauge!("attestation_gateway.android_os_patch_level")
                    .set(f64::from(os_patch_level));
            } else {
                metrics::counter!("attestation_gateway.android_missing_os_patch_level")
                    .increment(1);
            }

            attestation_output.device_public_key
        }
    };

    metrics::counter!("attestation_gateway.attestation", "platform" => platform.to_string())
        .increment(1);

    let token_details = nonce_db.consume_nonce(&request.nonce).await.map_err(|e| {
        if matches!(e, NonceDbError::NonceNotFound) {
            RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Nonce not found".to_string()),
            }
        } else {
            tracing::error!(error = ?e, "Error consuming token nonce");

            RequestError {
                code: ErrorCode::InternalServerError,
                details: Some("Error consuming token nonce".to_string()),
            }
        }
    })?;

    let integrity_token = generate_integrity_token(
        &mut redis,
        &aws_config,
        IntegrityTokenPayload {
            v: "1".to_string(),
            platform,
            app_version: request.app_version,
            aud: token_details.aud,
            cnf: device_public_key,
            pass: true,
            exp: token_details.exp,
        },
    )
    .await?;

    Ok(Json(Response { integrity_token }))
}

fn validate_apple_attestation_and_get_device_public_key(
    apple_root_ca_pem: &[u8],
    challenge: &str,
    bundle_identifier: &BundleIdentifier,
    apple_attestation: String,
) -> Result<Vec<u8>, RequestError> {
    let app_id = bundle_identifier
        .apple_app_id()
        .ok_or_else(|| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Invalid bundle identifier".to_string()),
        })?;

    let allowed_aaguid_vec = apple::AAGUID::allowed_for_bundle_identifier(bundle_identifier)
        .map_err(|_| RequestError {
            code: ErrorCode::BadRequest,
            details: Some("Invalid bundle identifier".to_string()),
        })?;

    let initial_attestation = apple::decode_and_validate_initial_attestation(
        apple_attestation,
        challenge,
        app_id,
        allowed_aaguid_vec.as_slice(),
        apple_root_ca_pem,
    )
    .map_err(|e| RequestError {
        code: ErrorCode::BadRequest,
        details: Some(e.to_string()),
    })?;

    Ok(initial_attestation.key_public_key)
}

async fn generate_integrity_token(
    redis: &mut ConnectionManager,
    aws_config: &SdkConfig,
    integrity_token_payload: IntegrityTokenPayload,
) -> Result<String, RequestError> {
    let integrity_token_payload = integrity_token_payload.generate().map_err(|e| {
        tracing::error!(error = ?e, "Error generating integrity token payload");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    let kms_key = keys::fetch_active_key(redis, aws_config)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Error fetching active key");
            RequestError {
                code: ErrorCode::InternalServerError,
                details: None,
            }
        })?;

    let integrity_token = kms_jws::generate_output_token(
        aws_config,
        kms_key.key_definition.arn,
        integrity_token_payload,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = ?e, "Error generating output token");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    Ok(integrity_token)
}
