use serial_test::serial;
use std::sync::{Arc, Mutex};
use tokio::task;
use tracing::{subscriber, Instrument};

use super::*;

async fn get_aws_config() -> aws_config::SdkConfig {
    // Required to load default AWS Config variables
    dotenvy::from_filename(".env.example").unwrap();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    aws_config
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build()
}

async fn get_redis_client() -> redis::aio::ConnectionManager {
    let client = redis::Client::open("redis://localhost").unwrap();
    // Reset Redis before each test run
    redis::cmd("FlUSHALL").execute(&mut client.clone().get_connection().unwrap());

    redis::aio::ConnectionManager::new(client).await.unwrap()
}

#[test]
fn test_fetch_all_keys_valid_for_verifying() {
    // insert a key valid for signing, one for verifying, one for neither
    todo!("todo");
}

#[test]
fn test_fetch_already_existing_active_key() {
    todo!("todo");
}

#[test]
fn test_fetch_active_key_creating_a_new_one() {
    todo!("todo");
}

#[tokio::test]
#[serial]
/// Asserts only one key is generated
async fn test_fetch_active_key_with_race_condition() {
    // Define the number of concurrent calls
    let num_calls = 10;

    // Create a vector to hold the join handles
    let mut handles = vec![];

    // Mutex to hold the outputs
    let output_mutex = Arc::new(Mutex::new(vec![]));

    let redis_client = get_redis_client().await;
    let aws_config = get_aws_config().await;

    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _ = subscriber::set_global_default(subscriber);

    // Spawn tasks
    for i in 0..num_calls {
        let output_mutex = Arc::clone(&output_mutex);

        let mut redis = redis_client.clone();
        let aws_config = aws_config.clone();
        let span = tracing::span!(tracing::Level::INFO, "fetch_active_key", task_id = i);

        let handle = task::spawn(
            async move {
                let output = fetch_active_key(&mut redis, &aws_config).await.unwrap();
                let mut outputs = output_mutex.lock().unwrap();
                outputs.push(output);
            }
            .instrument(span),
        );

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Check if all outputs are the same
    let outputs = {
        let outputs = output_mutex.lock().unwrap();
        outputs.clone()
    };
    let first_key_arn = outputs[0].clone().key_definition.arn;
    for key in &outputs {
        assert_eq!(
            key.key_definition.arn, first_key_arn,
            "Key ARNs are not the same, multiple keys were created."
        );
    }
}

#[test]
fn test_public_key_to_jwk() {
    let test_pk_pem = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8juOBvTjX/Z23rca/uGth7I8LkuK
hnX+pFZq78Se67+BOJDjy1rpIDxDAJgXMy7QbKbztaUGOIrSiRCeMc8lhg==
-----END PUBLIC KEY-----";
    let public_key = PKey::public_key_from_pem(test_pk_pem.as_bytes()).unwrap();

    let jwk = public_key_to_jwk(
        &public_key,
        "key_b9734d0e56ef4ad68e1fee2086a6e8e9".to_string(),
    )
    .unwrap();

    assert_eq!(
        jwk.key_id().unwrap(),
        "key_b9734d0e56ef4ad68e1fee2086a6e8e9"
    );
    assert_eq!(jwk.key_type(), "EC");
    assert_eq!(jwk.algorithm().unwrap(), "ES256");
    assert_eq!(jwk.curve().unwrap(), "P-256");

    let serialized_jwk = serde_json::to_string(&jwk).unwrap();

    let parsed_jwk: serde_json::Value = serde_json::from_str(&serialized_jwk).unwrap();
    assert_eq!(
        parsed_jwk["x"],
        "8juOBvTjX_Z23rca_uGth7I8LkuKhnX-pFZq78Se678"
    );
    assert_eq!(
        parsed_jwk["y"],
        // cspell:disable-next-line
        "gTiQ48ta6SA8QwCYFzMu0Gym87WlBjiK0okQnjHPJYY"
    );
}

#[test]
fn test_generate_key_sign_and_verify_with_jwk() {
    todo!("todo");
}

#[test]
fn test_pad_left() {
    let mut v = vec![5, 6, 7];
    pad_left(&mut v, 3);
    assert_eq!(v, [5, 6, 7]);
    pad_left(&mut v, 8);
    assert_eq!(v, [0, 0, 0, 0, 0, 5, 6, 7]);
}
