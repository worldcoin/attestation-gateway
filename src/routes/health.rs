use axum::http::StatusCode;

pub async fn handler() -> StatusCode {
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    StatusCode::OK
}

// NOTE: Integration tests for route handlers are in the `/tests` module
