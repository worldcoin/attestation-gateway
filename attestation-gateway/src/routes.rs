use aide::axum::{
    ApiRouter,
    routing::{get, post},
};
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

mod a;
mod c;
mod generate_token;
mod health;
mod jwks;

#[must_use]
pub fn get_timeout_layer() -> TimeoutLayer {
    TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(5),
    )
}

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .api_route("/a", post(a::handler))
        .api_route("/c", post(c::handler))
        .api_route("/g", post(generate_token::handler))
        .api_route("/.well-known/jwks.json", get(jwks::handler))
        .api_route("/health", get(health::handler))
        .layer(TraceLayer::new_for_http()) // adds HTTP tracing & context to all routes
        .layer(get_timeout_layer())
}
