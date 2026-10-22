use axum::{extract::Request, middleware::Next, response::Response};

// CloudFront sends this shared secret so the origin WAF admits only CloudFront traffic
// (see the web stack in `attestation-gateway-deploy`). It must never reach handlers,
// because Android `/a` forwards request headers to analytics and risk evaluation.
const ORIGIN_VERIFY_HEADER: &str = "x-origin-verify";

/// Removes the `CloudFront` origin secret before any other layer or handler sees the request.
pub async fn strip_header(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(ORIGIN_VERIFY_HEADER);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::HeaderMap, middleware, routing::post};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn removes_origin_secret_and_keeps_other_headers() {
        let app = Router::new()
            .route(
                "/a",
                post(|headers: HeaderMap| async move {
                    assert!(!headers.contains_key(ORIGIN_VERIFY_HEADER));
                    assert_eq!(headers["user-agent"], "test-agent");
                }),
            )
            .layer(middleware::from_fn(strip_header));

        let response = app
            .oneshot(
                Request::post("/a")
                    .header("X-Origin-Verify", "secret")
                    .header("user-agent", "test-agent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status().is_success());
    }
}
