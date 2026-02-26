use axum::http::StatusCode;

pub async fn handler() -> StatusCode {
    StatusCode::OK
}

// NOTE: Integration tests for route handlers are in the `/tests` module
