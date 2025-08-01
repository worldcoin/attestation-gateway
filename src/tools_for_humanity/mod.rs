use crate::utils::GlobalConfig;
use axum::{
    extract::Request,
    http::{self, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use base64::Engine;
pub use integrity_token_data::{ToolsForHumanityInnerToken, ToolsForHumanityOuterToken};
use josekit::jws::ES512;

mod integrity_token_data;

#[derive(Clone)]
pub struct User {
    pub principal: String,
}

/// Verifies a Tools for Humanity token and returns the user.
///
/// # Errors
/// Will return a `eyre::Error` if there is an error verifying the token.
pub fn verify(
    tools_for_humanity_outer_token: &str,
    tools_for_humanity_inner_jwt_verifier_key: String,
) -> eyre::Result<User> {
    // Parse outer JWT
    let outer_jwt_payload = parse_outer_jwt(tools_for_humanity_outer_token)?;

    // Verify and parse inner JWT
    let inner_jwt_payload =
        verify_and_parse_inner_jwt(outer_jwt_payload, tools_for_humanity_inner_jwt_verifier_key)?;

    let user = User {
        principal: inner_jwt_payload.principal.clone(),
    };

    // Verify outer JWT against inner JWT public key
    verify_outer_jwt(tools_for_humanity_outer_token, inner_jwt_payload)?;

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

    let parsed_payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    let parsed_token: ToolsForHumanityOuterToken =
        ToolsForHumanityOuterToken::from_json(&parsed_payload.to_string())?;

    Ok(parsed_token)
}

fn verify_and_parse_inner_jwt(
    outer_token: ToolsForHumanityOuterToken,
    tools_for_humanity_inner_jwt_verifier_key: String,
) -> eyre::Result<ToolsForHumanityInnerToken> {
    let decoded_key = base64::engine::general_purpose::STANDARD
        .decode(tools_for_humanity_inner_jwt_verifier_key.into_bytes())?;
    let verifier = ES512.verifier_from_der(decoded_key)?;

    let (jwt, _) = josekit::jwt::decode_with_verifier(outer_token.certificate, &verifier)?;

    let parsed_payload = serde_json::to_string(jwt.claims_set())?;
    let parsed_token: ToolsForHumanityInnerToken =
        ToolsForHumanityInnerToken::from_json(&parsed_payload)?;

    Ok(parsed_token)
}

fn verify_outer_jwt(
    tools_for_humanity_outer_token: &str,
    tools_for_humanity_inner_token: ToolsForHumanityInnerToken,
) -> eyre::Result<ToolsForHumanityOuterToken> {
    let decoded_key = base64::engine::general_purpose::STANDARD
        .decode(tools_for_humanity_inner_token.public_key.into_bytes())?;
    let verifier = ES512.verifier_from_der(decoded_key)?;

    let (jwt, _) = josekit::jwt::decode_with_verifier(tools_for_humanity_outer_token, &verifier)?;
    let parsed_payload = serde_json::to_string(jwt.claims_set())?;
    let parsed_token: ToolsForHumanityOuterToken =
        ToolsForHumanityOuterToken::from_json(&parsed_payload)?;

    Ok(parsed_token)
}

/// Middleware to verify Tools for Humanity tokens and insert the user into the request extensions.
///
/// # Errors
/// Will catch and log any errors verifying the token.
pub async fn middleware(
    Extension(global_config): Extension<GlobalConfig>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    match auth_header {
        Some(auth_header) => {
            match verify(
                auth_header,
                global_config.tools_for_humanity_inner_jwt_public_key,
            ) {
                Ok(user) => {
                    req.extensions_mut().insert(Some(user));
                }
                Err(e) => {
                    tracing::error!("Error verifying Tools for Humanity token: {:?}", e);
                    req.extensions_mut().insert(Option::<User>::None);
                }
            }
        }
        None => {
            req.extensions_mut().insert(Option::<User>::None);
        }
    }

    Ok(next.run(req).await)
}
