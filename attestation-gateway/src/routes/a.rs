use aws_config::SdkConfig;

use axum::{Extension, Json, http::HeaderMap};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, SubsecRound, Utc};
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
    android::{AndroidAttestationError, AndroidAttestationService},
    apple, keys, kms_jws,
    nonces::{NonceDb, NonceDbError},
    utils::{
        BundleIdentifier, ClientException, ErrorCode, GlobalConfig, Platform, RequestError,
        client_session_id,
    },
};

fn headers_to_map(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::<String, String>::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.entry(name.as_str().to_string())
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(v);
                })
                .or_insert_with(|| v.to_string());
        }
    }
    map
}

fn bad_request(details: impl Into<String>) -> RequestError {
    let details = details.into();
    tracing::warn!(endpoint = "/a", message = %details);
    RequestError {
        code: ErrorCode::BadRequest,
        details: Some(details),
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct Request {
    pub nonce: String,
    pub exp: Option<i64>,
    pub app_version: String,
    pub bundle_identifier: BundleIdentifier,
    pub apple_attestation: Option<String>,
    pub apple_public_key: Option<String>,
    pub integrity_signature: Option<String>,
    pub android_attestation: Option<Vec<String>>,
    pub device_model: Option<String>,
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
    pub exp: i64,
}

impl IntegrityTokenPayload {
    pub fn generate(&self, issuer: &str) -> eyre::Result<JwtPayload> {
        if self.cnf.len() != 65 {
            return Err(eyre::eyre!("Invalid device public key"));
        }

        let cnf_ec_key = EcKey::from_public_key_affine_coordinates(
            &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
            &BigNum::from_slice(&self.cnf[1..33]).unwrap(),
            &BigNum::from_slice(&self.cnf[33..65]).unwrap(),
        )
        .map_err(|_| bad_request("Invalid device public key"))?;

        let cnf_pkey =
            PKey::from_ec_key(cnf_ec_key).map_err(|_| bad_request("Invalid device public key"))?;

        let cnf_key_id = Base64.encode(sha256(&self.cnf));
        let cnf_jwk = keys::public_key_to_jwk(&cnf_pkey, Some(cnf_key_id))?;

        let mut cfn = josekit::Map::new();
        cfn.insert("jwk".to_string(), josekit::Value::Object(cnf_jwk.into()));

        let mut payload = JwtPayload::new();
        payload.set_issued_at(&Utc::now().round_subsecs(0).into());
        payload.set_issuer(issuer);
        payload.set_expires_at(
            &DateTime::<Utc>::from_timestamp(self.exp, 0)
                .ok_or(eyre::Error::msg("Unreachable exp conversion"))?
                .into(),
        );
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

fn map_android_attestation_error(e: &AndroidAttestationError, session_id: &str) -> RequestError {
    metrics::counter!("attestation_gateway.android_error", "reason" => e.reason_tag()).increment(1);

    if e.is_internal_error() {
        tracing::error!(error = ?e, "Error validating Android attestation");

        RequestError {
            code: ErrorCode::InternalServerError,
            details: None,
        }
    } else {
        // The precise verify failure stays server-side; the client gets only the coarse
        // default message so rejection reasons don't aid attestation probing.
        tracing::warn!(endpoint = "/a", session_id = %session_id, message = %e);
        RequestError {
            code: ErrorCode::AttestationRejected,
            details: None,
        }
    }
}

fn infer_platform(request: &Request) -> Result<Platform, RequestError> {
    let has_android = request.android_attestation.is_some();
    let has_apple_attestation = request.apple_attestation.is_some();
    let has_apple_public_key = request.apple_public_key.is_some();

    if has_android && (has_apple_attestation || has_apple_public_key) {
        return Err(bad_request(
            "Conflicting attestation fields for platform inference.",
        ));
    }

    if has_android {
        return Ok(Platform::Android);
    }

    if has_apple_attestation {
        if has_apple_public_key {
            return Err(bad_request(
                "For initial attestations, `apple_public_key` is not allowed.",
            ));
        }
        return Ok(Platform::AppleIOS);
    }

    if has_apple_public_key {
        if request.integrity_signature.is_none() {
            return Err(bad_request(
                "`integrity_signature` is required with `apple_public_key`.",
            ));
        }
        return Ok(Platform::AppleIOS);
    }

    Err(bad_request(
        "Could not infer platform from attestation fields.",
    ))
}

pub async fn handler(
    Extension(global_config): Extension<GlobalConfig>,
    Extension(mut redis): Extension<ConnectionManager>,
    Extension(mut nonce_db): Extension<NonceDb>,
    Extension(mut android_attestation): Extension<AndroidAttestationService>,
    Extension(aws_config): Extension<SdkConfig>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Result<Json<Response>, RequestError> {
    let session_id = client_session_id(&headers);
    let tracing_span =
        tracing::span!(tracing::Level::DEBUG, "a", endpoint = "/a", session_id = %session_id);
    let _enter = tracing_span.enter();

    if !global_config
        .enabled_bundle_identifiers
        .contains(&request.bundle_identifier)
    {
        return Err(bad_request(
            "This bundle identifier is currently unavailable.",
        ));
    }

    let token_details = nonce_db.consume_nonce(&request.nonce).await.map_err(|e| {
        if matches!(e, NonceDbError::NonceNotFound) {
            tracing::warn!(endpoint = "/a", session_id = %session_id, message = "Nonce not found");
            RequestError {
                code: ErrorCode::NonceNotFound,
                details: None,
            }
        } else {
            tracing::error!(error = ?e, "Error consuming token nonce");

            RequestError {
                code: ErrorCode::InternalServerError,
                details: Some("Error consuming token nonce".to_string()),
            }
        }
    })?;

    let challenge = format!("n={},av={}", request.nonce, request.app_version);
    let platform = infer_platform(&request)?;

    let device_public_key = match platform {
        Platform::AppleIOS => {
            verify_apple_proof(
                &request,
                &challenge,
                &global_config,
                &aws_config,
                session_id,
            )
            .await?
        }
        Platform::Android => {
            let android_cert_chain = request
                .android_attestation
                .ok_or_else(|| bad_request("Android attestation is required"))?;

            let attestation_result = android_attestation
                .verify(
                    &android_cert_chain,
                    &token_details.aud,
                    &request.nonce,
                    &request.app_version,
                    &request.bundle_identifier,
                    headers_to_map(&headers),
                    request.device_model.clone(),
                )
                .await;

            let attestation_output =
                attestation_result.map_err(|e| map_android_attestation_error(&e, session_id))?;

            if let Some(os_patch_level_delta) = attestation_output.os_patch_level_delta {
                metrics::gauge!("attestation_gateway.android_os_patch_level_delta")
                    .set(f64::from(os_patch_level_delta));
            } else {
                metrics::counter!("attestation_gateway.android_missing_os_patch_level")
                    .increment(1);
            }

            attestation_output.device_public_key
        }
    };

    metrics::counter!("attestation_gateway.attestation", "platform" => platform.to_string())
        .increment(1);

    let exp = match request.exp {
        Some(exp) if exp > token_details.exp_max => {
            return Err(bad_request("Exp is greater than token exp max"));
        }
        Some(exp) => exp,
        None => token_details.exp_max,
    };
    let integrity_token = generate_integrity_token(
        &mut redis,
        &aws_config,
        &global_config.jwt_issuer,
        IntegrityTokenPayload {
            v: "1".to_string(),
            platform,
            app_version: request.app_version,
            aud: token_details.aud,
            cnf: device_public_key,
            pass: true,
            exp,
        },
    )
    .await?;

    Ok(Json(Response { integrity_token }))
}

fn validate_apple_attestation(
    apple_root_ca_pem: &[u8],
    challenge: &str,
    bundle_identifier: &BundleIdentifier,
    apple_attestation: String,
) -> Result<apple::InitialAttestationOutput, RequestError> {
    let app_id = bundle_identifier
        .apple_app_id()
        .ok_or_else(|| bad_request("Invalid bundle identifier"))?;

    let allowed_aaguid_vec = apple::AAGUID::allowed_for_bundle_identifier(bundle_identifier)
        .map_err(|_| bad_request("Invalid bundle identifier"))?;

    // Canonical App ID only — the re-signed-build allow-list is intentionally scoped to the
    // `/g` token flow (via `apple_accepted_app_ids`); this `/a` route is unchanged.
    apple::decode_and_validate_initial_attestation(
        apple_attestation,
        challenge,
        &[app_id],
        allowed_aaguid_vec.as_slice(),
        apple_root_ca_pem,
    )
    .map_err(|error| bad_request(error.to_string()))
}

async fn verify_apple_proof(
    request: &Request,
    challenge: &str,
    global_config: &GlobalConfig,
    aws_config: &SdkConfig,
    session_id: &str,
) -> Result<Vec<u8>, RequestError> {
    if let Some(apple_attestation) = &request.apple_attestation {
        let initial_attestation = validate_apple_attestation(
            &global_config.apple_root_ca_pem,
            challenge,
            &request.bundle_identifier,
            apple_attestation.clone(),
        )?;

        apple::dynamo::insert_apple_public_key(
            aws_config,
            &global_config.apple_keys_dynamo_table_name,
            request.bundle_identifier.clone(),
            initial_attestation.key_id,
            initial_attestation.public_key,
            initial_attestation.receipt,
        )
        .await
        .map_err(|error| map_apple_verification_error(&error, session_id))?;

        return Ok(initial_attestation.key_public_key);
    }

    let apple_public_key = request
        .apple_public_key
        .clone()
        .ok_or_else(|| bad_request("Apple public key is required"))?;
    let integrity_signature = request
        .integrity_signature
        .clone()
        .ok_or_else(|| bad_request("Apple assertion is required"))?;
    let app_id = request
        .bundle_identifier
        .apple_app_id()
        .ok_or_else(|| bad_request("Invalid bundle identifier"))?;

    apple::verify_assertion_and_get_device_public_key(
        integrity_signature,
        apple_public_key,
        &request.bundle_identifier,
        &[app_id],
        challenge,
        aws_config,
        &global_config.apple_keys_dynamo_table_name,
    )
    .await
    .map_err(|error| map_apple_verification_error(&error, session_id))
}

fn map_apple_verification_error(error: &eyre::Report, session_id: &str) -> RequestError {
    if let Some(client_error) = error.downcast_ref::<ClientException>() {
        tracing::warn!(endpoint = "/a", session_id = %session_id, error = ?error);
        return RequestError {
            code: client_error.code,
            details: None,
        };
    }

    tracing::error!(endpoint = "/a", session_id = %session_id, error = ?error);
    RequestError {
        code: ErrorCode::InternalServerError,
        details: None,
    }
}

async fn generate_integrity_token(
    redis: &mut ConnectionManager,
    aws_config: &SdkConfig,
    issuer: &str,
    integrity_token_payload: IntegrityTokenPayload,
) -> Result<String, RequestError> {
    let integrity_token_payload = integrity_token_payload.generate(issuer).map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> Request {
        Request {
            nonce: "nonce".to_string(),
            exp: None,
            app_version: "1.0.0".to_string(),
            bundle_identifier: BundleIdentifier::OrgWorldId,
            apple_attestation: None,
            apple_public_key: None,
            integrity_signature: None,
            android_attestation: None,
            device_model: None,
        }
    }

    #[test]
    fn infer_platform_android_from_android_attestation() {
        let mut request = base_request();
        request.android_attestation = Some(vec!["cert".to_string()]);
        assert_eq!(infer_platform(&request).unwrap(), Platform::Android);
    }

    #[test]
    fn infer_platform_ios_from_apple_attestation() {
        let mut request = base_request();
        request.apple_attestation = Some("attestation".to_string());
        assert_eq!(infer_platform(&request).unwrap(), Platform::AppleIOS);
    }

    #[test]
    fn infer_platform_ios_from_apple_assertion() {
        let mut request = base_request();
        request.apple_public_key = Some("public-key".to_string());
        request.integrity_signature = Some("assertion".to_string());
        assert_eq!(infer_platform(&request).unwrap(), Platform::AppleIOS);
    }

    #[test]
    fn infer_platform_rejects_apple_public_key_without_assertion() {
        let mut request = base_request();
        request.apple_public_key = Some("public-key".to_string());
        assert_eq!(
            infer_platform(&request).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn infer_platform_rejects_initial_attestation_with_public_key() {
        let mut request = base_request();
        request.apple_attestation = Some("attestation".to_string());
        request.apple_public_key = Some("public-key".to_string());
        request.integrity_signature = Some("assertion".to_string());
        assert_eq!(
            infer_platform(&request).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn maps_unknown_apple_key_to_invalid_public_key() {
        let error = eyre::eyre!(ClientException {
            code: ErrorCode::InvalidPublicKey,
            internal_debug_info: "unknown key".to_string(),
        });

        assert_eq!(
            map_apple_verification_error(&error, "session").code,
            ErrorCode::InvalidPublicKey
        );
    }

    #[test]
    fn infer_platform_rejects_both_attestations() {
        let mut request = base_request();
        request.android_attestation = Some(vec!["cert".to_string()]);
        request.apple_attestation = Some("attestation".to_string());
        assert_eq!(
            infer_platform(&request).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn headers_to_map_joins_duplicate_header_values() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert("header-1", HeaderValue::from_static("value-1"));
        headers.append("header-1", HeaderValue::from_static("value-1b"));
        headers.insert("header-2", HeaderValue::from_static("value-2"));

        let map = headers_to_map(&headers);
        assert_eq!(map["header-1"], "value-1, value-1b");
        assert_eq!(map["header-2"], "value-2");
    }
}
