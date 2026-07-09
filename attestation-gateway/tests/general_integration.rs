use std::time::Duration;

use aide::axum::routing::get;
use attestation_gateway::routes::get_timeout_layer;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_health() {
    let api_router = attestation_gateway::routes::handler();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_timeout() {
    async fn handler() -> StatusCode {
        tokio::time::sleep(Duration::from_secs(6)).await;

        StatusCode::OK
    }

    let api_router = attestation_gateway::routes::handler()
        .api_route("/timeout", get(handler))
        .layer(get_timeout_layer()); // we need to re-add the timeout layer because otherwise it won't apply to the new route

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/timeout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}
