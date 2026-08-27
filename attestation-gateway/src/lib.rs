#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod android;
pub mod apple;
pub mod audience_authorizer;
mod bootstrap;
pub mod developer;
pub mod keys;
pub mod kinesis;
pub mod kms_jws;
pub mod nonces;
pub mod routes;
pub mod server;
pub mod utils;

pub use bootstrap::start_from_env;
