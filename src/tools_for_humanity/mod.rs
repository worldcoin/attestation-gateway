use crate::request_hasher;
use crate::utils::{ErrorCode, GlobalConfig, RequestError};
use axum::{
    Extension, body,
    extract::Request,
    http::{self, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
pub use integrity_token_data::{ToolsForHumanityInnerToken, ToolsForHumanityOuterToken};
use jwtk::{HeaderAndClaims, jwk::RemoteJwksVerifier};
use std::time::Duration;
use tokio::sync::OnceCell;

mod integrity_token_data;

#[derive(Clone)]
pub struct User {
    pub principal: String,
}

static TOOLS_FOR_HUMANITY_VERIFIER: OnceCell<RemoteJwksVerifier> = OnceCell::const_new();
const TFH_TOKEN_HEADER_NAME: http::header::HeaderName =
    http::header::HeaderName::from_static("x-tfh-token");

/// Verifies a Tools for Humanity token and returns the user.
///
/// # Errors
/// Will return a `eyre::Error` if there is an error verifying the token.
pub async fn verify(
    tools_for_humanity_outer_token: &str,
    tools_for_humanity_verifier: &RemoteJwksVerifier,
    request_hash: String,
) -> eyre::Result<User> {
    // Parse outer JWT
    let outer_jwt_payload = parse_outer_jwt(tools_for_humanity_outer_token)?;

    // Verify and parse inner JWT
    let inner_jwt_payload =
        verify_and_parse_inner_jwt(outer_jwt_payload, tools_for_humanity_verifier).await?;

    let user = User {
        principal: inner_jwt_payload.principal.clone(),
    };

    // Verify outer JWT against inner JWT public key
    let outer_jwt_payload = verify_outer_jwt(tools_for_humanity_outer_token, &inner_jwt_payload)?;

    // Validate request hash
    if outer_jwt_payload.request_hash != request_hash {
        return Err(eyre::eyre!(
            "Request hash mismatch: {request_hash} != {}",
            outer_jwt_payload.request_hash
        ));
    }

    // Return verification output
    Ok(user)
}

fn parse_outer_jwt(tools_for_humanity_token: &str) -> eyre::Result<ToolsForHumanityOuterToken> {
    // Just parse the payload without verifying, we can manually split the JWT and base64-decode the payload.
    let parts: Vec<&str> = tools_for_humanity_token.split('.').collect();
    if parts.len() != 3 {
        return Err(eyre::eyre!("Invalid JWT format: expected 3 parts"));
    }
    let payload_b64 = parts[1];

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .map_err(|e| eyre::eyre!("Failed to decode JWT payload as base64url: {e}"))?;

    let parsed_payload: ToolsForHumanityOuterToken = serde_json::from_slice(&payload_bytes)?;

    Ok(parsed_payload)
}

async fn verify_and_parse_inner_jwt(
    outer_token: ToolsForHumanityOuterToken,
    tools_for_humanity_verifier: &RemoteJwksVerifier,
) -> eyre::Result<ToolsForHumanityInnerToken> {
    let jwt: HeaderAndClaims<ToolsForHumanityInnerToken> = tools_for_humanity_verifier
        .verify(&outer_token.certificate)
        .await
        .map_err(|e| {
            let error_message = format!("Error verifying inner JWT: {e}");
            tracing::error!(error_message);
            eyre::eyre!(error_message)
        })?;

    let claims = jwt.claims();

    Ok(claims.extra.clone())
}

fn verify_outer_jwt(
    tools_for_humanity_outer_token: &str,
    tools_for_humanity_inner_token: &ToolsForHumanityInnerToken,
) -> eyre::Result<ToolsForHumanityOuterToken> {
    let some_public_key =
        // Try to parse the public key as a PEM string
        jwtk::SomePublicKey::from_pem(tools_for_humanity_inner_token.public_key.as_bytes())
            .or_else(|_| {
                // If that fails, parse the public key as a JWK
                let parsed_key: jwtk::jwk::Jwk =
                    serde_json::from_str(&tools_for_humanity_inner_token.public_key)?;
                parsed_key.to_verification_key()
            })?;

    let claims = jwtk::verify::<ToolsForHumanityOuterToken>(
        tools_for_humanity_outer_token,
        &some_public_key,
    )
    .map_err(|e| {
        let error_message = format!("Error verifying outer JWT: {e}");
        tracing::error!(error_message);
        eyre::eyre!(error_message)
    })?;

    Ok(claims.claims().extra.clone())
}

/// Middleware to verify Tools for Humanity tokens and insert the user into the request extensions.
///
/// # Errors
/// Will catch and log any errors verifying the token.
pub async fn middleware(
    Extension(global_config): Extension<GlobalConfig>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    req.extensions_mut().insert(Option::<User>::None);

    // Initialize the verifier if it's not already initialized
    let tools_for_humanity_verifier = if let Some(jwks_url) =
        global_config.tools_for_humanity_inner_jwks_url
    {
        TOOLS_FOR_HUMANITY_VERIFIER
            .get_or_init(|| async {
                tracing::info!("✅ Initializing Tools for Humanity verifier...");
                RemoteJwksVerifier::new(jwks_url, None, Duration::from_secs(3600))
            })
            .await
    } else {
        tracing::info!("✅ Skipping Tools for Humanity token verification (no JWKS URL provided)");
        return Ok(next.run(req).await);
    };

    let (parts, body) = req.into_parts();

    // Clone the parts to avoid moving them
    let cloned_parts = parts.clone();
    let uri: Uri = cloned_parts.uri;
    let method = cloned_parts.method;
    let headers = cloned_parts.headers;

    let auth_header = headers
        .get(TFH_TOKEN_HEADER_NAME)
        .map(|h| h.to_str().unwrap_or_default().to_string());

    let Some(auth_header) = auth_header else {
        let req: http::Request<body::Body> = Request::from_parts(parts, body);
        return Ok(next.run(req).await);
    };

    // Convert the body to a string
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    // body_bytes to Option<String>
    let body_string = if body_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8(body_bytes.to_vec()).unwrap_or_default())
    };

    // Reconstruct the request once we have the body as a string
    let mut req: http::Request<body::Body> =
        Request::from_parts(parts, axum::body::Body::from(body_bytes));

    let hasher = request_hasher::RequestHasher::new();
    let input = request_hasher::GenerateRequestHashInput {
        path_uri: uri.path().to_string(),
        method: match method {
            Method::GET => request_hasher::AllowedHttpMethod::Get,
            Method::POST => request_hasher::AllowedHttpMethod::Post,
            _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
        },
        body: body_string,
    };

    let request_hash = match hasher.generate_json_request_hash(&input) {
        Ok(request_hash) => request_hash,
        Err(e) => {
            tracing::error!("Error generating request hash: {:?}", e);
            let error_code = ErrorCode::InternalServerError;
            return Ok(RequestError {
                code: error_code,
                details: Some(e.to_string()),
            }
            .into_response());
        }
    };

    match verify(&auth_header, tools_for_humanity_verifier, request_hash).await {
        Ok(user) => {
            req.extensions_mut().insert(Some(user));
        }
        // If token is provided but invalid, return a 400 error
        Err(e) => {
            tracing::error!("Error verifying Tools for Humanity token: {:?}", e);
            let error_code = ErrorCode::InvalidToolsForHumanityToken;
            return Ok(RequestError {
                code: error_code,
                details: Some(e.to_string()),
            }
            .into_response());
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;
    use jwtk::{PublicKeyToJwk, jwk::RemoteJwksVerifier};
    use serde_json::json;

    fn generate_inner_token(key: &jwtk::SomePrivateKey, kid: &str, client_pub_key: &str) -> String {
        let mut claims = jwtk::HeaderAndClaims::new_dynamic();
        claims
            .insert("principal", "test@toolsforhumanity.com")
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
            .insert("certificate", certificate)
            .insert("requestHash", request_hash);

        jwtk::sign(&mut claims, client_key).unwrap()
    }

    async fn generate_keys_and_mock_jwks_server() -> (
        String,
        jwtk::SomePrivateKey,
        jwtk::SomePrivateKey,
        RemoteJwksVerifier,
    ) {
        // Generate TFH key (used for inner JWT signing)
        let tfh_kid = String::from("tfh-test-key");
        let tfh_private_key =
            jwtk::ecdsa::EcdsaPrivateKey::generate(jwtk::ecdsa::EcdsaAlgorithm::ES256).unwrap();
        let tfh_some_private_key = jwtk::SomePrivateKey::Ecdsa(tfh_private_key);

        // Generate client key (used for outer JWT)
        let client_private_key =
            jwtk::ecdsa::EcdsaPrivateKey::generate(jwtk::ecdsa::EcdsaAlgorithm::ES256).unwrap();
        let client_some_private_key = jwtk::SomePrivateKey::Ecdsa(client_private_key);

        // Prepare mock JWKS endpoint that returns TFH public key
        let mut tfh_some_public_key = tfh_some_private_key.public_key_to_jwk().unwrap();
        tfh_some_public_key.kid = Some(tfh_kid.to_string());
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.path("/.well-known/jwks.json").method("GET");
                then.status(200)
                    .json_body(json!({ "keys": [tfh_some_public_key] }));
            })
            .await;

        // Generate a verifier for the mock JWKS server
        let verifier = RemoteJwksVerifier::new(
            server.url("/.well-known/jwks.json"),
            None,
            Duration::from_secs(3600),
        );

        (
            tfh_kid,
            tfh_some_private_key,
            client_some_private_key,
            verifier,
        )
    }

    #[tokio::test]
    async fn test_verify_token_success() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Create an inner JWT that uses a **PEM** public key string
        let inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
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
        let user = verify(&outer_token, &verifier, calculated_request_hash.to_string())
            .await
            .expect("should succeed");

        assert_eq!(user.principal, "test@toolsforhumanity.com");
    }

    #[tokio::test]
    async fn test_verify_token_with_jwk_public_key_fallback() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        // 🧪 Create an inner JWT that uses a **JWK** public key string (not PEM)
        let inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
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
        let user = verify(&outer_token, &verifier, calculated_request_hash.to_string())
            .await
            .expect("should succeed");

        assert_eq!(user.principal, "test@toolsforhumanity.com");
    }

    #[tokio::test]
    async fn test_verify_token_invalid_outer_token_format() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        let inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );

        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash")
                .split(".")
                .collect::<Vec<&str>>()[0..2]
                .join(".");

        let result = verify(&outer_token, &verifier, "test-request-hash".to_string()).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("Invalid JWT format: expected 3 parts")
        );
    }

    #[tokio::test]
    async fn test_verify_token_invalid_inner_token_signature() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        let mut inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );
        // Change last char of inner_token
        inner_token.pop();
        inner_token.push('x');

        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");

        let result = verify(&outer_token, &verifier, "test-request-hash".to_string()).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .eq("Error verifying inner JWT: failed to verify signature")
        );
    }

    #[tokio::test]
    async fn test_verify_token_invalid_outer_token_signature() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        let inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );

        let mut outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, "test-request-hash");
        // Change last char of outer_token
        outer_token.pop();
        outer_token.push('x');

        let result = verify(&outer_token, &verifier, "test-request-hash".to_string()).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .eq("Error verifying outer JWT: failed to verify signature")
        );
    }

    #[tokio::test]
    async fn test_verify_token_hash_mismatch() {
        let (tfh_kid, tfh_some_private_key, client_some_private_key, verifier) =
            generate_keys_and_mock_jwks_server().await;

        let inner_token = generate_inner_token(
            &tfh_some_private_key,
            &tfh_kid,
            &client_some_private_key.public_key_to_pem().unwrap(),
        );

        // 🧪 Create outer JWT with wrong requestHash
        let wrong_request_hash = "wrong-request-hash";
        let correct_request_hash = "test-request-hash";
        let outer_token =
            generate_outer_token(&client_some_private_key, &inner_token, wrong_request_hash);

        // 🧪 Call the function under test
        let result = verify(&outer_token, &verifier, correct_request_hash.to_string()).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Request hash mismatch"));
    }
}
