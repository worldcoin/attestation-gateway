//! Developer token verification module.
//!
//! This module provides functionality for verifying tokens issued by developers of Authenticators.
//! It includes JWKS fetching, JWT parsing, and validation logic for developer-issued tokens used in attestation flows.
///
/// These tokens are generally used for test builds, staging builds or other types of builds not distributed through stores but whose integrity is protected by the developer.
use crate::{
    developer::integrity_token_data::{ActorTokenExtraClaims, DeveloperTokenExtraClaims},
    utils::{ClientException, ErrorCode, VerificationOutput},
};
use base64::Engine;
pub use integrity_token_data::{ActorTokenClaims, DeveloperTokenClaims};
use jwtk::jwk::RemoteJwksVerifier;
use std::time::Duration;
use tokio::sync::OnceCell;

mod integrity_token_data;

static DEVELOPER_VERIFIER: OnceCell<RemoteJwksVerifier> = OnceCell::const_new();

/// Audience the certificate authority stamps on every Laissez-Passer certificate.
/// Single fixed value for now; may become a set if audiences are enriched later.
const EXPECTED_CERTIFICATE_AUDIENCE: &str = "lp.certificate";

/// Well-known JWKS path published by the certificate authority. The expected
/// certificate issuer is the JWKS URL with this suffix removed (e.g.
/// `https://certauth.worldcoin.dev/.well-known/jwks.json` ->
/// `https://certauth.worldcoin.dev`).
const WELL_KNOWN_JWKS_SUFFIX: &str = "/.well-known/jwks.json";

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
    let Some(jwks_url) = jwks_url else {
        tracing::error!("No JWKS URL provided for developer verifier");
        return Err(eyre::eyre!("No JWKS URL provided for developer verifier"));
    };

    // Initialize the verifier if it's not already initialized
    let developer_token_verifier = DEVELOPER_VERIFIER
        .get_or_init(|| async {
            RemoteJwksVerifier::new(jwks_url.to_string(), None, Duration::from_secs(3600))
        })
        .await;

    // Parse outer JWT
    let outer_jwt_payload = parse_outer_jwt(developer_token)?;

    // Verify and parse inner JWT
    let inner_jwt_payload =
        verify_and_parse_inner_jwt(&outer_jwt_payload, developer_token_verifier).await?;

    // Validate inner certificate claims (iss must match the certificate authority
    // the JWKS was fetched from, aud must be the LP certificate audience)
    validate_inner_certificate_claims(&inner_jwt_payload, jwks_url)?;

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

fn parse_outer_jwt(developer_token: &str) -> eyre::Result<ActorTokenClaims> {
    ActorTokenClaims::from_json(developer_token).map_err(|e| {
        let error_message = format!("Failed to parse outer JWT: {e}");
        tracing::warn!(error_message);
        eyre::eyre!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: error_message,
        })
    })
}

async fn verify_and_parse_inner_jwt(
    outer_token: &ActorTokenClaims,
    developer_verifier: &RemoteJwksVerifier,
) -> eyre::Result<DeveloperTokenClaims> {
    let jwt = developer_verifier
        .verify::<DeveloperTokenExtraClaims>(&outer_token.certificate)
        .await
        .map_err(|e| {
            let error_message = format!("Error verifying inner JWT: {e}");
            tracing::warn!(error_message);
            eyre::eyre!(ClientException {
                code: ErrorCode::InvalidDeveloperToken,
                internal_debug_info: error_message,
            })
        })?;

    let claims = serde_json::to_string(jwt.claims()).unwrap();

    let parsed_claims: DeveloperTokenClaims = serde_json::from_str(&claims).map_err(|e| {
        let error_message = format!("Failed to parse inner JWT claims: {e}");
        tracing::warn!(error_message);
        eyre::eyre!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: error_message,
        })
    })?;

    Ok(parsed_claims)
}

fn verify_outer_jwt(
    developer_outer_token: &str,
    developer_inner_token: &DeveloperTokenClaims,
) -> eyre::Result<()> {
    let verification_key =
        // Try to parse the public key as a PEM string
        jwtk::SomePublicKey::from_pem(developer_inner_token.public_key.as_bytes())
            .or_else(|_| {
                // Or as a JWK JSON object.
                let parsed_key: jwtk::jwk::Jwk =
                    serde_json::from_str(&developer_inner_token.public_key)?;
                parsed_key.to_verification_key()
            })
            .or_else(|_| {
                // Or as a base64url-encoded SubjectPublicKeyInfo DER blob (what
                // Android emits via `KeyFactory`/`PublicKey.getEncoded()`). We
                // rewrap the DER bytes in a PEM envelope and reuse `from_pem`
                // since `EcdsaPublicKey::from_pkey` is `pub(crate)` in `jwtk`.
                let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(developer_inner_token.public_key.as_bytes())
                    .or_else(|_| {
                        base64::engine::general_purpose::URL_SAFE
                            .decode(developer_inner_token.public_key.as_bytes())
                    })?;
                jwtk::SomePublicKey::from_pem(der_to_pem(&der).as_bytes())
            })?;

    jwtk::verify::<ActorTokenExtraClaims>(developer_outer_token, &verification_key).map_err(
        |e| {
            let error_message = format!("Error verifying outer JWT: {e}");
            tracing::warn!(error_message);
            eyre::eyre!(ClientException {
                code: ErrorCode::InvalidDeveloperToken,
                internal_debug_info: error_message,
            })
        },
    )?;

    Ok(())
}

/// Validates the `iss` and `aud` claims of the inner certificate.
///
/// The expected issuer is derived from the configured JWKS URL: the certificate
/// authority publishes its keys at `<issuer>/.well-known/jwks.json`, so a
/// certificate is only accepted if its `iss` matches the authority whose keys
/// verified it (`https://certauth.toolsforhumanity.com` in prod,
/// `https://certauth.worldcoin.dev` in staging). Trailing slashes are ignored
/// to tolerate formatting differences between issuers and configuration.
fn validate_inner_certificate_claims(
    inner_token: &DeveloperTokenClaims,
    jwks_url: &str,
) -> eyre::Result<()> {
    let expected_issuer = jwks_url
        .strip_suffix(WELL_KNOWN_JWKS_SUFFIX)
        .unwrap_or(jwks_url)
        .trim_end_matches('/');

    if inner_token.iss.trim_end_matches('/') != expected_issuer {
        let error_message = format!(
            "Inner certificate issuer does not match certificate authority: {actual} != {expected_issuer}",
            actual = inner_token.iss,
        );
        tracing::warn!(error_message);
        eyre::bail!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: error_message,
        });
    }

    if inner_token.aud != EXPECTED_CERTIFICATE_AUDIENCE {
        let error_message = format!(
            "Inner certificate audience is not {EXPECTED_CERTIFICATE_AUDIENCE}: {actual}",
            actual = inner_token.aud,
        );
        tracing::warn!(error_message);
        eyre::bail!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: error_message,
        });
    }

    Ok(())
}

fn validate_developer_token_claims(
    outer_token: &ActorTokenClaims,
    request_hash: &str,
) -> eyre::Result<()> {
    if outer_token.request_hash != request_hash {
        let error_message = format!(
            "Outer token and request hash do not match: {left} != {right}",
            left = outer_token.request_hash,
            right = request_hash
        );
        tracing::warn!(error_message);
        eyre::bail!(ClientException {
            code: ErrorCode::InvalidDeveloperToken,
            internal_debug_info: error_message,
        });
    }
    Ok(())
}

/// Wraps a SubjectPublicKeyInfo DER blob in a PEM envelope so it can be fed
/// back into `SomePublicKey::from_pem`. Lines are wrapped at 64 chars as per
/// RFC 7468 — OpenSSL is lenient about this, but staying conventional avoids
/// surprises with stricter parsers.
fn der_to_pem(der: &[u8]) -> String {
    const LINE_WIDTH: usize = 64;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / LINE_WIDTH + 64);
    out.push_str("-----BEGIN PUBLIC KEY-----\n");
    for chunk in body.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jwtk::PublicKeyToJwk;
    use mockito::Server;
    use serde_json::json;

    fn generate_inner_token(key: &jwtk::SomePrivateKey, kid: &str, client_pub_key: &str) -> String {
        generate_inner_token_with_claims(
            key,
            kid,
            client_pub_key,
            &issuer_for_tests(),
            EXPECTED_CERTIFICATE_AUDIENCE,
        )
    }

    fn generate_inner_token_with_claims(
        key: &jwtk::SomePrivateKey,
        kid: &str,
        client_pub_key: &str,
        iss: &str,
        aud: &str,
    ) -> String {
        let mut claims = jwtk::HeaderAndClaims::new_dynamic();
        claims
            .set_exp_from_now(Duration::from_secs(60))
            .set_iat_now()
            .set_iss(iss)
            .set_sub("test@relying-party.example.com")
            .insert("public_key", client_pub_key)
            .insert("aud", aud)
            .set_kid(kid);

        jwtk::sign(&mut claims, key).unwrap()
    }

    /// Issuer matching the mock JWKS server, i.e. the JWKS URL minus the
    /// well-known suffix — mirrors how `validate_inner_certificate_claims`
    /// derives the expected issuer.
    fn issuer_for_tests() -> String {
        JWK_SERVER
            .get()
            .expect("JWKS mock server must be initialized before generating tokens")
            .url()
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
            .insert("request_hash", request_hash)
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
    async fn test_verify_token_with_base64url_der_public_key_fallback() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // Reproduce what Android emits: base64url-encoded SubjectPublicKeyInfo DER.
        // We don't have direct access to the raw DER through `jwtk`, so we round-trip
        // through PEM (strip BEGIN/END lines + whitespace, decode standard base64, then
        // re-encode as URL_SAFE_NO_PAD).
        let pem = client_some_private_key.public_key_to_pem().unwrap();
        let der_b64 = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(der_b64)
            .unwrap();
        let base64url_der = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der);

        // 🧪 Create an inner JWT that uses a **base64url DER** public key string
        let inner_token =
            generate_inner_token(&developer_some_private_key, &developer_kid, &base64url_der);
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
    async fn test_verify_token_rejects_wrong_issuer() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Inner JWT signed by the trusted key but claiming a different issuer
        let inner_token = generate_inner_token_with_claims(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
            "https://evil-issuer.example.com",
            EXPECTED_CERTIFICATE_AUDIENCE,
        );
        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");

        let result = verify(&outer_token, Some(&jwks_url), "test-request-hash").await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("Inner certificate issuer does not match certificate authority")
        );
    }

    #[tokio::test]
    async fn test_verify_token_rejects_wrong_audience() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Inner JWT with correct issuer but wrong audience
        let inner_token = generate_inner_token_with_claims(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
            &issuer_for_tests(),
            "some.other.audience",
        );
        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");

        let result = verify(&outer_token, Some(&jwks_url), "test-request-hash").await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("Inner certificate audience is not lp.certificate")
        );
    }

    #[tokio::test]
    async fn test_verify_token_accepts_issuer_with_trailing_slash() {
        let (developer_kid, developer_some_private_key, client_some_private_key, jwks_url) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Same issuer but with a trailing slash — must still be accepted
        let inner_token = generate_inner_token_with_claims(
            &developer_some_private_key,
            &developer_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
            &(issuer_for_tests() + "/"),
            EXPECTED_CERTIFICATE_AUDIENCE,
        );
        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");

        let user = verify(&outer_token, Some(&jwks_url), "test-request-hash")
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
