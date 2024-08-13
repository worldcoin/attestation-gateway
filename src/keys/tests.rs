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
