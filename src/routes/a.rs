use std::time::SystemTime;

use base64::prelude::*;

use axum::{Extension, Json};
use eyre::ContextCompat;
use schemars::JsonSchema;

use crate::{
    apple,
    challenges::ChallengesDb,
    keys, kms_jws,
    utils::{BundleIdentifier, ErrorCode, GlobalConfig, RequestError},
};

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub challenge: String,
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
    pub aud: String,
    pub cnf: openssl::pkey::PKey<openssl::pkey::Public>,
    pub pass: bool,
    pub exp: SystemTime,
}

impl IntegrityTokenPayload {
    pub fn generate(&self) -> eyre::Result<josekit::jwt::JwtPayload> {
        let cfn_jwk = keys::public_key_to_jwk(&self.cnf, None)?;
        let mut cfn = josekit::Map::new();
        cfn.insert("jwk".to_string(), josekit::Value::Object(cfn_jwk.into()));

        let mut payload = josekit::jwt::JwtPayload::new();
        payload.set_issued_at(&std::time::SystemTime::now());
        payload.set_issuer("attestation.worldcoin.org"); // TODO: what about attestation.worldcoin.dev?
        payload.set_expires_at(&self.exp);
        payload.set_claim("v", Some(josekit::Value::String(self.v.clone())))?;
        payload.set_claim("aud", Some(josekit::Value::String(self.aud.clone())))?;
        payload.set_claim("cnf", Some(josekit::Value::Object(cfn)))?;
        payload.set_claim("pass", Some(josekit::Value::Bool(self.pass)))?;

        Ok(payload)
    }
}

pub async fn handler(
    Extension(global_config): Extension<GlobalConfig>,
    Extension(mut redis): Extension<redis::aio::ConnectionManager>,
    Extension(mut challenges_db): Extension<ChallengesDb>,
    Extension(aws_config): Extension<aws_config::SdkConfig>,
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

    let device_public_key = match request.bundle_identifier {
        BundleIdentifier::IOSProdWorldApp | BundleIdentifier::IOSStageWorldApp => {
            let apple_attestation = request.apple_attestation.ok_or(RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Apple attestation is required".to_string()),
            })?;

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
                apple_attestation,
                &request.challenge,
                app_id,
                &allowed_aaguid_vec.as_slice(),
            )
            .map_err(|e| RequestError {
                code: ErrorCode::BadRequest,
                details: Some(e.to_string()),
            })?;

            initial_attestation.key_public_key_der
        }
        BundleIdentifier::AndroidDevWorldApp
        | BundleIdentifier::AndroidStageWorldApp
        | BundleIdentifier::AndroidProdWorldApp => {
            let android_attestation = request.android_attestation.ok_or(RequestError {
                code: ErrorCode::BadRequest,
                details: Some("Android attestation is required".to_string()),
            })?;

            let attested_certificate = base64::engine::general_purpose::STANDARD
                .decode(&android_attestation[0])
                .map_err(|_| RequestError {
                    code: ErrorCode::BadRequest,
                    details: Some("Invalid attested certificate base64 encoding".to_string()),
                })?;

            let (_, res) = x509_parser::parse_x509_certificate(attested_certificate.as_slice())
                .map_err(|_| RequestError {
                    code: ErrorCode::BadRequest,
                    details: Some("Not a valid X.509 certificate".to_string()),
                })?;

            res.public_key().subject_public_key.data.clone().into()
        }
    };

    let ec_key = openssl::ec::EcKey::from_public_key_affine_coordinates(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        &openssl::bn::BigNum::from_slice(&device_public_key[1..33]).unwrap(),
        &openssl::bn::BigNum::from_slice(&device_public_key[33..65]).unwrap(),
    )
    .map_err(|e| RequestError {
        code: ErrorCode::BadRequest,
        details: Some(e.to_string()),
    })?;

    let cnf = openssl::pkey::PKey::from_ec_key(ec_key).map_err(|_| RequestError {
        code: ErrorCode::BadRequest,
        details: Some("Invalid device public key".to_string()),
    })?;

    let kms_key = keys::fetch_active_key(&mut redis, &aws_config)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Error fetching active key");
            RequestError {
                code: ErrorCode::InternalServerError,
                details: None,
            }
        })?;

    let token_details = challenges_db
        .consume_token_challenge(&request.challenge)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Error consuming token challenge");
            RequestError {
                code: ErrorCode::InternalServerError,
                details: None,
            }
        })?;

    let integrity_token_payload = IntegrityTokenPayload {
        v: "1".to_string(),
        aud: token_details.aud,
        cnf,
        pass: true,
        exp: token_details.exp,
    }
    .generate()
    .map_err(|e| {
        tracing::error!(error = ?e, "Error generating integrity token payload");
        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    })?;

    let integrity_token = kms_jws::generate_output_token(
        &aws_config,
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

    Ok(Json(Response { integrity_token }))
}
