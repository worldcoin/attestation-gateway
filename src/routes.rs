use std::time::Duration;

use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::Request,
    middleware::{self, Next},
    response::Response,
};
use std::net::SocketAddr;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

mod generate_token;
mod health;
mod jwks;

async fn log_ip_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    let client_ip = if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            forwarded_str
                .split(',')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string()
        } else {
            if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
                addr.to_string()
            } else {
                "unknown".to_string()
            }
        }
    } else {
        if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    };

    let span = tracing::info_span!("request", "network.client.ip" = %client_ip, method = %method, path = %uri);

    let _guard = span.enter();

    next.run(req).await
}

#[must_use]
pub fn get_timeout_layer() -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(5))
}

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .api_route("/g", post(generate_token::handler))
        .api_route("/.well-known/jwks.json", get(jwks::handler))
        .api_route("/health", get(health::handler))
        .route_layer(middleware::from_fn(log_ip_middleware))
        .layer(TraceLayer::new_for_http()) // adds HTTP tracing & context to all routes
        .layer(get_timeout_layer())
}
