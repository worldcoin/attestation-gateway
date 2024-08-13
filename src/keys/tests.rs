use josekit::{
    jws::{self, JwsHeader},
    jwt::{self, JwtPayload},
};
use serial_test::serial;
use std::sync::{Arc, Mutex};
use tokio::task;
use tracing::Instrument;

use crate::kms_jws::EcdsaJwsSignerWithKms;

use super::*;

// NOTE: Generally all of these are integration tests (requires docker-compose.test.yml to be running)

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

#[tokio::test]
#[serial]
async fn test_fetch_all_keys_valid_for_verifying() {
    let mut redis = get_redis_client().await;
    let aws_config = get_aws_config().await;

    // create a valid key for signing
    let signing_key = kms_generate_new_key_and_store(&mut redis, &get_aws_config().await)
        .await
        .unwrap();

    // create a key that is no longer valid for signing but is valid for verifying
    let verifying_key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_123".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_123".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp() - SIGNING_CONFIG.key_ttl_signing - 10,
    };
    // note we add at the end of the list
    redis
        .rpush::<_, _, ()>(
            SIGNING_KEYS_REDIS_KEY,
            serde_json::to_vec(&verifying_key).unwrap(),
        )
        .await
        .unwrap();

    // create a key that is completely expired
    let key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_123".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_123".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp() - SIGNING_CONFIG.key_ttl_verification - 10,
    };
    // note we add at the end of the list
    redis
        .rpush::<_, _, ()>(SIGNING_KEYS_REDIS_KEY, serde_json::to_vec(&key).unwrap())
        .await
        .unwrap();

    let keys = fetch_all(&mut redis, &aws_config).await.unwrap();
    assert_eq!(keys.len(), 2); // both signing and verifying keys are returned
    assert_eq!(keys[0].key_definition.id, signing_key.key_definition.id);
    assert_eq!(keys[1].key_definition.id, verifying_key.key_definition.id);
}

#[tokio::test]
#[serial]
async fn test_fetch_already_existing_active_key() {
    let mut redis = get_redis_client().await;
    let aws_config = get_aws_config().await;

    // Create a key in Redis
    let key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_123".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_123".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp(),
    };

    redis
        .lpush::<_, _, ()>(
            SIGNING_KEYS_REDIS_KEY,
            serde_json::to_vec(&key.clone()).unwrap(),
        )
        .await
        .unwrap();

    let fetched_key = fetch_active_key(&mut redis, &get_aws_config().await)
        .await
        .unwrap();
    assert_eq!(key.key_definition.id, fetched_key.key_definition.id);

    let key_list = fetch_all(&mut redis, &aws_config).await.unwrap();
    assert_eq!(key_list.len(), 1);
    assert_eq!(key_list[0].key_definition.id, key.key_definition.id);
}

#[tokio::test]
#[serial]
async fn test_fetch_active_key_creating_a_new_one() {
    let mut redis = get_redis_client().await;
    let aws_config = get_aws_config().await;

    // Check there aren't any keys created
    let len = redis
        .llen::<_, usize>(SIGNING_KEYS_REDIS_KEY)
        .await
        .unwrap();
    assert_eq!(len, 0);

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // Check the key was created in Redis
    let len = redis
        .llen::<_, usize>(SIGNING_KEYS_REDIS_KEY)
        .await
        .unwrap();
    assert_eq!(len, 1);

    // assert key.created_at is close to the current time
    let now = chrono::Utc::now().timestamp();
    assert!(key.created_at - now < 3);

    // Check the key was created in AWS
    let kms_client = aws_sdk_kms::Client::new(&aws_config);
    let key_metadata = kms_client
        .describe_key()
        .key_id(key.key_definition.arn.clone())
        .send()
        .await
        .unwrap()
        .key_metadata
        .unwrap();

    assert_eq!(
        key_metadata.key_state.unwrap(),
        aws_sdk_kms::types::KeyState::Enabled
    );

    assert_eq!(key_metadata.key_spec.unwrap(), SIGNING_CONFIG.key_spec);

    // ensure the same key is returned again
    let key_second_time = fetch_active_key(&mut redis, &aws_config).await.unwrap();
    assert_eq!(key.key_definition.id, key_second_time.key_definition.id);
}

#[tokio::test]
#[serial]
async fn test_fetch_active_key_expired_key_creates_a_new_one() {
    let mut redis = get_redis_client().await;
    let aws_config = get_aws_config().await;

    // Create an expired key
    let expired_key = SigningKey {
        key_definition: KMSKeyDefinition {
            id: "key_123".to_string(),
            arn: "arn:aws:kms:us-west-2:123456789012:key/key_123".to_string(),
        },
        jwk: Jwk::new("EC"),
        created_at: chrono::Utc::now().timestamp() - SIGNING_CONFIG.key_ttl_signing - 10,
    };
    // note we add at the end of the list
    redis
        .rpush::<_, _, ()>(
            SIGNING_KEYS_REDIS_KEY,
            serde_json::to_vec(&expired_key).unwrap(),
        )
        .await
        .unwrap();

    let len = redis
        .llen::<_, usize>(SIGNING_KEYS_REDIS_KEY)
        .await
        .unwrap();

    let new_key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    assert_ne!(new_key.key_definition.id, expired_key.key_definition.id);

    // Check that a new key was created in Redis
    let new_len = redis
        .llen::<_, usize>(SIGNING_KEYS_REDIS_KEY)
        .await
        .unwrap();
    assert_eq!(new_len, len + 1);

    // assert key.created_at is close to the current time
    let now = chrono::Utc::now().timestamp();
    assert!(new_key.created_at - now < 3);

    // Check the key was created in AWS
    let kms_client = aws_sdk_kms::Client::new(&aws_config);
    let key_metadata = kms_client
        .describe_key()
        .key_id(new_key.key_definition.arn.clone())
        .send()
        .await
        .unwrap()
        .key_metadata
        .unwrap();

    assert_eq!(
        key_metadata.key_state.unwrap(),
        aws_sdk_kms::types::KeyState::Enabled
    );

    assert_eq!(key_metadata.key_spec.unwrap(), SIGNING_CONFIG.key_spec);
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

#[tokio::test]
#[serial]
async fn test_generate_key_sign_and_verify_with_jwk() {
    let mut redis = get_redis_client().await;
    let aws_config = get_aws_config().await;

    let key = fetch_active_key(&mut redis, &aws_config).await.unwrap();

    // Generate a JWS token
    let kms_client = aws_sdk_kms::Client::new(&aws_config);
    let signer = EcdsaJwsSignerWithKms {
        key: key.key_definition,
        kms_client,
    };
    let header = JwsHeader::new();
    let mut payload = JwtPayload::new();
    payload.set_subject("whoami");
    let jwt =
        tokio::task::spawn_blocking(move || jwt::encode_with_signer(&payload, &header, &signer))
            .await
            .unwrap()
            .unwrap();

    // Verify with the JWK
    let verifier = jws::ES256.verifier_from_jwk(&key.jwk).unwrap();
    let decoded = jwt::decode_with_verifier(jwt, &verifier).unwrap();
    assert_eq!(decoded.0.subject().unwrap(), "whoami");
}

#[test]
fn test_pad_left() {
    let mut v = vec![5, 6, 7];
    pad_left(&mut v, 3);
    assert_eq!(v, [5, 6, 7]);
    pad_left(&mut v, 8);
    assert_eq!(v, [0, 0, 0, 0, 0, 5, 6, 7]);
}
