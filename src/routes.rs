use crate::tools_for_humanity;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

mod generate_token;
mod health;
mod jwks;

#[must_use]
pub fn get_timeout_layer() -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(5))
}

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .api_route("/g", post(generate_token::handler))
        .route_layer(axum::middleware::from_fn(tools_for_humanity::middleware))
        .api_route("/.well-known/jwks.json", get(jwks::handler))
        .api_route("/health", get(health::handler))
        .layer(TraceLayer::new_for_http()) // adds HTTP tracing & context to all routes
        .layer(get_timeout_layer())
}
