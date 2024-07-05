use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `collect`

use attestation_gateway::utils::{BundleIdentifier, TokenGenerationRequest};

#[tokio::test]
async fn test_token_generation() {
    let api_router = attestation_gateway::routes::handler();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.KFIgLrj9rJevODYuKPPAh--ZwsNncWQU9W9uFFOV6i-hNHvoq9XTBA.DuiL258_ExC1Xs_p.y12JrBydvyZTdGaSmwtoGNmQQO2qY-flr2kxWApr0FrdIbYZ-VrWXmyOZvAIpXGyvxO_TP5fHmFl9m6wiy08S2zJY2_mgAFKJPj1OSHYBUtT2jO-4oSJvaWsW373BqwDY3nzwqTXhdGC29CcLE7P-Xypt3Uw2i9LSTmC8564-LdXVgUcqFymyxfVVWc3l5bARXZxktrVylKYtqpD6ghRVQKHOF--TNkcP-Bk8XrRGvDes7xvLsHAD3hPtZqu-vdYbE1t0DnLzxJxt2oW_kn8EJ2WAAuBrVmLtt3R9ga3Ezg2wf6Fl9jHbiOdK1-YtC1b1N3oDULyXg.reQSLjXhKGyquoZFveeX2g".to_string(),
        aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidProdWorldApp,
        request_hash: "my_request_hash".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body,
        json!({ "attestation_gateway_token": "my_token".to_string() })
    );
}

#[tokio::test]
async fn test_token_generation_fails_on_invalid_bundle_identifier() {
    let api_router = attestation_gateway::routes::handler();

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "toolsforhumanity.com".to_string(),
        "bundle_identifier": "com.worldcoin.invalid".to_string(),
        "request_hash": "my_request_hash".to_string(),
    });

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body["schema_validation"][0]["instance_location"],
        "/bundle_identifier".to_string()
    );
}
