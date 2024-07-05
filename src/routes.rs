use aide::axum::{routing::get, routing::post, ApiRouter};

mod generate_token;
mod health;

pub fn handler() -> ApiRouter {
    // TODO: Timeout handling
    ApiRouter::new()
        .api_route("/g", post(generate_token::handler))
        .api_route("/health", get(health::handler))
}
