use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `collect`

#[tokio::test]
async fn test_token_generation() {
    let api_router = attestation_gateway::routes::handler();

    let token_generation_request = json!( {
        "integrity_token": "your_integrity_token".to_string(),
        "client_error": None::<String>,
        "aud": "your_aud".to_string(),
        "bundle_identifier": "your_bundle_identifier".to_string(),
        "request_hash": "your_request_hash".to_string(),
        "apple_initial_attestation": "your_apple_initial_attestation".to_string(),
        "apple_public_key": "your_apple_public_key".to_string(),
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

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    println!("{:?}", body);

    assert_eq!(
        body,
        json!({ "attestation_gateway_token": "your_bundle_identifier".to_string() })
    );
}
