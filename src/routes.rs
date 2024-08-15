use std::time::Duration;

use aide::axum::{routing::get, routing::post, ApiRouter};
use tower_http::trace::TraceLayer;
mod generate_token;
mod health;
use tower_http::timeout::TimeoutLayer;

#[must_use]
pub fn get_timeout_layer() -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(5))
}

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .api_route("/g", post(generate_token::handler))
        .api_route("/health", get(health::handler))
        .layer(TraceLayer::new_for_http()) // adds HTTP tracing & context to all routes
        .layer(get_timeout_layer())
}
