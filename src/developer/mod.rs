//! Developer token verification module.
//!
//! This module provides functionality for verifying developer tokens issued by relying parties.
//! It includes JWKS fetching, JWT parsing, and validation logic for developer-issued tokens used in attestation flows.

use crate::{
    developer::integrity_token_data::{ActorTokenExtraClaims, DeveloperTokenExtraClaims},
    utils::{ClientException, ErrorCode, VerificationOutput},
};
pub use integrity_token_data::{ActorTokenClaims, DeveloperTokenClaims};
use jwtk::jwk::RemoteJwksVerifier;
use std::time::Duration;
use tokio::sync::OnceCell;

mod integrity_token_data;

static TOOLS_FOR_HUMANITY_VERIFIER: OnceCell<RemoteJwksVerifier> = OnceCell::const_new();

/// Verifies a developer token and returns the sub.
///
/// Currently supported developers:
/// - Tools for Humanity (TFH)
///
/// # Errors
/// Will return a `eyre::Error` if there is an error verifying the token.
pub async fn verify(
    developer_token: &str,
    jwks_url: Option<&str>,
    request_hash: &str,
) -> eyre::Result<VerificationOutput> {
    // Initialize the verifier if it's not already initialized
    let developer_token_verifier = if let Some(jwks_url) = jwks_url {
        TOOLS_FOR_HUMANITY_VERIFIER
            .get_or_init(|| async {
                tracing::info!("✅ Initializing Tools for Humanity verifier...");
                RemoteJwksVerifier::new(jwks_url.to_string(), None, Duration::from_secs(3600))
            })
            .await
    } else {
        tracing::error!("No JWKS URL provided for developer token verification");
        return Err(eyre::eyre!(
            "No JWKS URL provided for developer token verification"
        ));
    };

    // Parse outer JWT
    let outer_jwt_payload = parse_outer_jwt(developer_token)?;

    // Verify and parse inner JWT
    let inner_jwt_payload =
        verify_and_parse_inner_jwt(&outer_jwt_payload, developer_token_verifier).await?;

    // Verify outer JWT against inner JWT public key
    verify_outer_jwt(developer_token, &inner_jwt_payload)?;

    validate_developer_token_claims(&outer_jwt_payload, request_hash)?;

    // Return verification output
    Ok(VerificationOutput {
        success: true,
        app_version: None,
        parsed_play_integrity_token: None,
        client_exception: None,
        developer_token: Some(inner_jwt_payload),
    })
}

fn parse_outer_jwt(tools_for_humanity_token: &str) -> eyre::Result<ActorTokenClaims> {
    ActorTokenClaims::from_json(tools_for_humanity_token)
}

async fn verify_and_parse_inner_jwt(
    outer_token: &ActorTokenClaims,
    tools_for_humanity_verifier: &RemoteJwksVerifier,
) -> eyre::Result<DeveloperTokenClaims> {
    let jwt = tools_for_humanity_verifier
        .verify::<DeveloperTokenExtraClaims>(&outer_token.certificate)
        .await
        .map_err(|e| {
            let error_message = format!("Error verifying inner JWT: {e}");
            tracing::error!(error_message);
            eyre::eyre!(ClientException {
                code: ErrorCode::InvalidDeveloperToken,
                internal_debug_info: error_message,
            })
        })?;

    let claims = serde_json::to_string(jwt.claims()).unwrap();

    Ok(serde_json::from_str(&claims)?)
}

fn verify_outer_jwt(
    tools_for_humanity_outer_token: &str,
    tools_for_humanity_inner_token: &DeveloperTokenClaims,
) -> eyre::Result<()> {
    let verification_key =
        // Try to parse the public key as a PEM string
        jwtk::SomePublicKey::from_pem(tools_for_humanity_inner_token.public_key.as_bytes())
            .or_else(|_| {
                // If that fails, parse the public key as a JWK
                let parsed_key: jwtk::jwk::Jwk =
                    serde_json::from_str(&tools_for_humanity_inner_token.public_key)?;
                parsed_key.to_verification_key()
            })?;

    jwtk::verify::<ActorTokenExtraClaims>(tools_for_humanity_outer_token, &verification_key)
        .map_err(|e| {
            let error_message = format!("Error verifying outer JWT: {e}");
            tracing::error!(%e, "Error verifying outer JWT");
            eyre::eyre!(ClientException {
                code: ErrorCode::InvalidDeveloperToken,
                internal_debug_info: error_message,
            })
        })?;

    Ok(())
}

fn validate_developer_token_claims(
    outer_token: &ActorTokenClaims,
    request_hash: &str,
) -> eyre::Result<()> {
    if outer_token.jti != request_hash {
        return Err(eyre::eyre!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: "Provided `request_hash` does not match token's `jti`".to_string(),
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jwtk::PublicKeyToJwk;
    use mockito::Server;
    use serde_json::json;

    fn generate_inner_token(key: &jwtk::SomePrivateKey, kid: &str, client_pub_key: &str) -> String {
        let mut claims = jwtk::HeaderAndClaims::new_dynamic();
        claims
            .set_exp_from_now(Duration::from_secs(60))
            .set_iat_now()
            .set_iss("https://relying-party.example.com")
            .set_sub("test@relying-party.example.com")
            .insert("publicKey", client_pub_key)
            .set_kid(kid);

        jwtk::sign(&mut claims, key).unwrap()
    }

    fn generate_outer_token(
        client_key: &jwtk::SomePrivateKey,
        certificate: &str,
        request_hash: &str,
    ) -> String {
        let mut claims = jwtk::HeaderAndClaims::new_dynamic();
        claims
            .set_exp_from_now(Duration::from_secs(60))
            .set_iat_now()
            .set_jti(request_hash)
            .insert("certificate", certificate);

        jwtk::sign(&mut claims, client_key).unwrap()
    }

    static DEVELOPER_PRIVATE_KEY: OnceCell<jwtk::ecdsa::EcdsaPrivateKey> = OnceCell::const_new();
    static JWK_SERVER: OnceCell<mockito::ServerGuard> = OnceCell::const_new();

    async fn generate_keys_and_mock_jwks_server()
    -> (String, jwtk::SomePrivateKey, jwtk::SomePrivateKey, String) {
        // Generate Developer key (used for inner JWT signing)
        let developer_kid = String::from("developer-test-key");
        let developer_private_key = DEVELOPER_PRIVATE_KEY
            .get_or_init(|| async {
                jwtk::ecdsa::EcdsaPrivateKey::generate(jwtk::ecdsa::EcdsaAlgorithm::ES256).unwrap()
            })
            .await;

        let developer_some_private_key = jwtk::SomePrivateKey::Ecdsa(developer_private_key.clone());

        // Prepare mock JWKS endpoint that returns Developer public key
        let server = JWK_SERVER
            .get_or_init(|| async {
                let mut server = Server::new_async().await;

                let mut developer_some_public_key =
                    developer_some_private_key.public_key_to_jwk().unwrap();
                developer_some_public_key.kid = Some(developer_kid.to_string());
                let body = json!({ "keys": [developer_some_public_key] });

                server
                    .mock("GET", "/.well-known/jwks.json")
                    .with_status(200)
                    .with_body(body.to_string())
                    .create();

                server
            })
            .await;

        // Generate client key (used for outer JWT)
        let client_private_key =
            jwtk::ecdsa::EcdsaPrivateKey::generate(jwtk::ecdsa::EcdsaAlgorithm::ES256).unwrap();
        let client_some_private_key = jwtk::SomePrivateKey::Ecdsa(client_private_key);

        (
            developer_kid,
            developer_some_private_key,
            client_some_private_key,
            server.url() + "/.well-known/jwks.json",
        )
    }

    #[tokio::test]
    async fn test_verify_token_success() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Create an inner JWT that uses a **PEM** public key string
        let inner_token = generate_inner_token(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );
        // 🧪 Create outer JWT with correct requestHash
        let calculated_request_hash = "test-request-hash";
        let outer_token = generate_outer_token(
            &client_some_private_key,
            &inner_token,
            calculated_request_hash,
        );

        // 🧪 Call the function under test
        let user = verify(&outer_token, Some(&jwks_url), calculated_request_hash)
            .await
            .expect("should succeed");

        assert_eq!(user.success, true);
    }

    #[tokio::test]
    async fn test_verify_token_with_jwk_public_key_fallback() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Create an inner JWT that uses a **JWK** public key string (not PEM)
        let inner_token = generate_inner_token(
            &developer_some_private_key,
            &developer_kid,
            // Convert the public key to a JWK string instead of a PEM string
            &serde_json::to_string(&client_some_private_key.public_key_to_jwk().unwrap()).unwrap(),
        );
        // 🧪 Create outer JWT with correct requestHash
        let calculated_request_hash = "test-request-hash";
        let outer_token = generate_outer_token(
            &client_some_private_key,
            &inner_token,
            calculated_request_hash,
        );

        // 🧪 Call the function under test
        let user = verify(&outer_token, Some(&jwks_url), calculated_request_hash)
            .await
            .expect("should succeed");

        assert_eq!(user.success, true);
    }

    #[tokio::test]
    async fn test_verify_token_invalid_outer_token_format() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        let inner_token = generate_inner_token(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );

        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash")
                .split(".")
                .collect::<Vec<&str>>()[0..2]
                .join(".");

        let result = verify(&outer_token, Some(&jwks_url), "test-request-hash").await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("Invalid JWT format: expected 3 parts")
        );
    }

    #[tokio::test]
    async fn test_verify_token_invalid_inner_token_signature() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        let mut inner_token = generate_inner_token(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );
        // Replace signature with invalid signature
        let invalid_signature = "invalid-signature";
        inner_token.replace_range(
            inner_token.len() - invalid_signature.len()..,
            invalid_signature,
        );

        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");

        let result = verify(&outer_token, Some(&jwks_url), "test-request-hash").await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .eq("Error Code: `invalid_developer_token`. Internal debug info: \"Error verifying inner JWT: failed to verify signature\"")
        );
    }

    #[tokio::test]
    async fn test_verify_token_invalid_outer_token_signature() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        let inner_token = generate_inner_token(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );

        let mut outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");
        // Replace signature with invalid signature
        let invalid_signature = "invalid-signature";
        outer_token.replace_range(
            outer_token.len() - invalid_signature.len()..,
            invalid_signature,
        );

        let result = verify(&outer_token, Some(&jwks_url), "test-request-hash").await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .eq("Error Code: `invalid_developer_token`. Internal debug info: \"Error verifying outer JWT: failed to verify signature\"")
        );
    }
}
