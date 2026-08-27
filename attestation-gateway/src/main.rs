#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

#[tokio::main]
async fn main() {
    attestation_gateway::start_from_env().await;
}
