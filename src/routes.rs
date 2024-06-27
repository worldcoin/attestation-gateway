use aide::axum::{routing::post, ApiRouter};

mod generate_token;

pub fn handler() -> ApiRouter {
    ApiRouter::new().api_route("/g", post(generate_token::handler))
}
