use aide::axum::{routing::get, routing::post, ApiRouter};
use tower_http::trace::TraceLayer;
mod generate_token;
mod health;

pub fn handler() -> ApiRouter {
    // TODO: Timeout handling
    ApiRouter::new()
        .api_route("/g", post(generate_token::handler))
        .api_route("/health", get(health::handler))
        // adds HTTP tracing & context to all routes
        .layer(TraceLayer::new_for_http())
}
