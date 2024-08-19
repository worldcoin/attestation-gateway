use std::time::{Duration, Instant};

use aws_sdk_kms::types::{KeySpec, Tag};
use base64::{engine::general_purpose, Engine};
use der_parser::nom::ToUsize;
use eyre::OptionExt;
use openssl::{
    bn::{BigNum, BigNumContext},
    pkey::{PKey, Public},
};
use redis::{aio::ConnectionManager, AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};

use josekit::{jwk::Jwk, Value};
use serde::{Deserialize, Serialize};

use crate::{kms_jws::KMSKeyDefinition, utils::SIGNING_CONFIG};

const SIGNING_KEYS_REDIS_KEY: &str = "signing-keys";
const CREATING_KEY_LOCK_KEY: &str = "lock-signing-key-creation";

// TODO: Implement a worker that cleans up old keys from Redis & KMS

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigningKey {
    pub key_definition: KMSKeyDefinition,
    pub jwk: Jwk,
    pub created_at: i64,
}

impl SigningKey {
    /// Returns whether the key is valid for signing.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        self.created_at + SIGNING_CONFIG.key_ttl_signing > chrono::Utc::now().timestamp()
    }

    /// Returns whether the key is valid for verification.
    /// All keys which are valid for signing are valid for verification, but not vice versa.
    #[must_use]
    pub fn can_verify(&self) -> bool {
        self.created_at + SIGNING_CONFIG.key_ttl_verification > chrono::Utc::now().timestamp()
    }
}

/// Fetches all keys available for signing or verifying.
/// Will generate a new key if none are available.
///
/// # Errors
/// Will return an error if the key generation process fails or if there is a problem fetching/updating data from Redis.
pub async fn fetch_all(
    redis: &mut ConnectionManager,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<Vec<SigningKey>> {
    let mut keys = fetch_keys_from_redis(redis).await?;

    if keys.is_empty() {
        return Ok(vec![generate_new_key(redis, aws_config).await?]);
    }

    // check the latest key is valid for signing, otherwise generate a new one
    if !keys[0].can_sign() {
        keys.insert(0, generate_new_key(redis, aws_config).await?);
        return Ok(keys);
    }

    Ok(keys)
}

/// Fetches the current active key for signing or generates a new one if none are available or all are expired.
///
/// # Errors
/// Will return an error if the key generation process fails or if there is a problem fetching/updating data from Redis.
pub async fn fetch_active_key(
    redis: &mut ConnectionManager,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<SigningKey> {
    let key = fetch_all(redis, aws_config)
        .await?
        .first()
        .ok_or_eyre("Unexpected state with no valid keys")?
        .clone();

    if !key.can_sign() {
        return generate_new_key(redis, aws_config).await;
    }

    Ok(key)
}

async fn fetch_keys_from_redis(redis: &mut ConnectionManager) -> eyre::Result<Vec<SigningKey>> {
    let keys: Vec<Vec<u8>> = redis.lrange(SIGNING_KEYS_REDIS_KEY, 0, 1).await?; // maximum retrieve two keys

    let keys: Vec<SigningKey> = keys
        .into_iter()
        .filter_map(|item| {
            let key = serde_json::from_slice::<SigningKey>(&item)
                .map_err(|e| {
                    tracing::error!(
                        "Unexpected Error. Failed to deserialize key from Redis: {:?}",
                        e
                    );
                    e
                })
                .ok()?;
            // Exclude keys which are unsuitable for verification anymore
            if !key.can_verify() {
                return None;
            }
            Some(key)
        })
        .collect();

    Ok(keys)
}

fn key_tags() -> eyre::Result<Option<Vec<Tag>>> {
    let app_tag = Tag::builder()
        .set_tag_key(Some("app".to_string()))
        .set_tag_value(Some("attestation-gateway".to_string()))
        .build()?;

    Ok(Some(vec![app_tag]))
}

async fn generate_new_key(
    redis: &mut ConnectionManager,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<SigningKey> {
    tracing::info!("No suitable signing keys found. Generating a new key");

    if acquire_lock_with_backoff(redis).await? {
        let (key_definition, public_key_der) = kms_generate_new_key(aws_config).await?;

        let public_key = PKey::public_key_from_der(&public_key_der)?;

        let jwk = public_key_to_jwk(&public_key, key_definition.id.clone())?;

        let signing_key = SigningKey {
            key_definition,
            jwk,
            created_at: chrono::Utc::now().timestamp(),
        };

        store_new_key_in_redis(redis, &signing_key).await?;

        // Release the lock. Intentionally ignore result because failure is not critical (key expires automatically)
        let _ = release_lock(redis).await;

        return Ok(signing_key);
    }

    // If the lock was not acquired, likely the key was created by another instance, try to retrieve it
    let mut keys = fetch_keys_from_redis(redis).await?;
    if !keys.is_empty() {
        return Ok(keys.remove(0));
    }
    eyre::bail!("DEADLOCK. Failed to acquire lock for key generation and key was never created.");
}

async fn kms_generate_new_key(
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<(KMSKeyDefinition, Vec<u8>)> {
    tracing::info!("Generating new key in KMS.");

    let kms_client = aws_sdk_kms::Client::new(aws_config);
    let key = kms_client
        .create_key()
        .key_spec(SIGNING_CONFIG.key_spec)
        .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
        .set_tags(key_tags()?)
        .send()
        .await?;

    let key_metadata = key
        .key_metadata
        .as_ref()
        .ok_or_else(|| eyre::eyre!("Key metadata is missing"))?;

    let key_arn = key_metadata
        .arn
        .as_ref()
        .ok_or_else(|| eyre::eyre!("ARN is missing"))?
        .clone();

    let key_definition = KMSKeyDefinition::from_arn(key_arn);

    // Fetch public key
    let public_key = kms_client
        .get_public_key()
        .key_id(key_definition.arn.clone())
        .send()
        .await?;

    let public_key_der = public_key.public_key().ok_or_else(|| {
        eyre::eyre!(
            "Public key not found for newly created key: {:?}",
            key_definition.arn
        )
    })?;

    let public_key_der = public_key_der.as_ref().to_vec();

    tracing::info!("New KMS key generated: {}", key_definition.arn);

    Ok((key_definition, public_key_der))
}

async fn store_new_key_in_redis(
    redis: &mut ConnectionManager,
    key: &SigningKey,
) -> eyre::Result<()> {
    redis
        .lpush(SIGNING_KEYS_REDIS_KEY, serde_json::to_vec(key)?)
        .await?;
    tracing::info!("New key stored in Redis: {}", key.key_definition.id);
    Ok(())
}

async fn acquire_lock_with_backoff(redis: &mut ConnectionManager) -> eyre::Result<bool> {
    let mut backoff_ms = 2_000; // 2 seconds
    let max_retry_timeout: u64 = 15; // 15 seconds
    let start_time = Instant::now();

    let key_count = redis.llen::<_, usize>(SIGNING_KEYS_REDIS_KEY).await?;

    let opts = SetOptions::default()
        .conditional_set(ExistenceCheck::NX)
        .with_expiration(SetExpiry::EX(max_retry_timeout.to_usize()));

    tracing::info!(
        "Attempting to acquire lock for key generation. Current key count: {}",
        key_count
    );

    while start_time.elapsed().as_secs() < max_retry_timeout {
        let acquired_lock = redis
            .set_options::<_, _, String>(CREATING_KEY_LOCK_KEY, "1", opts)
            .await;

        if acquired_lock.is_ok() {
            tracing::info!("Lock acquired.");
            return Ok(true);
        }

        tracing::info!("Lock NOT acquired. Retrying in {}ms", backoff_ms);

        // Exponential backoff
        let sleep_duration = Duration::from_millis(backoff_ms);
        tokio::time::sleep(sleep_duration).await;

        // Check if a key was created while waiting
        let new_key = redis
            .lindex::<_, Option<Vec<u8>>>(SIGNING_KEYS_REDIS_KEY, 0)
            .await?;

        if let Some(new_key) = new_key {
            let new_key: SigningKey = serde_json::from_slice(&new_key)?;
            if new_key.can_sign() {
                tracing::info!(
                    "A new key has been created while waiting for the lock. Exiting wait."
                );
                return Ok(false);
            }
        }

        // Increase the backoff for the next retry
        backoff_ms = (backoff_ms * 2).min(max_retry_timeout * 1000);
    }
    tracing::error!(
        "Failed to acquire lock within the maximum retry timeout. Time elapsed: {:?}",
        start_time.elapsed().as_secs()
    );
    Ok(false) // Failed to acquire the lock within the maximum retry timeout
}

async fn release_lock(redis: &mut ConnectionManager) -> eyre::Result<()> {
    redis.del(CREATING_KEY_LOCK_KEY).await?;
    Ok(())
}

/// Converts a DER public key to a JWK.
/// Forked from `josekit::jwk::alg::ec::EcKeyPair.to_jwk` because the original function does not support using public-only keys.
fn public_key_to_jwk(public_key: &PKey<Public>, key_id: String) -> eyre::Result<josekit::jwk::Jwk> {
    let mut jwk = josekit::jwk::Jwk::new("EC");

    let ec_key = public_key.ec_key()?;

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    let mut ctx = BigNumContext::new()?;
    ec_key
        .public_key()
        .affine_coordinates(ec_key.group(), &mut x, &mut y, &mut ctx)?;

    let (mut x, mut y) = (x.to_vec(), y.to_vec());
    pad_left(&mut x, SIGNING_CONFIG.signature_len / 2);
    pad_left(&mut y, SIGNING_CONFIG.signature_len / 2);

    jwk.set_parameter(
        "x",
        Some(Value::String(general_purpose::URL_SAFE_NO_PAD.encode(x))),
    )?;

    jwk.set_parameter(
        "y",
        Some(Value::String(general_purpose::URL_SAFE_NO_PAD.encode(y))),
    )?;

    let key = KeySpec::EccNistP256;
    key.as_str();

    jwk.set_algorithm("ES256");
    jwk.set_key_id(key_id);
    jwk.set_parameter(
        "crv",
        Some(Value::String(SIGNING_CONFIG.curve_str.to_string())),
    )?;

    Ok(jwk)
}

/// Adds padding to the left of a vector to make it the specified length.
/// Forked from <https://github.com/blckngm/jwtk/blob/9cd5cc1e345ecccc3c9f5d2618d03afbde34e54f/src/ecdsa.rs#L223>
fn pad_left(v: &mut Vec<u8>, len: usize) {
    debug_assert!(v.len() <= len);
    if v.len() == len {
        return;
    }
    let old_len = v.len();
    v.resize(len, 0);
    v.copy_within(0..old_len, len - old_len);
    v[..(len - old_len)].fill(0);
}

#[cfg(test)]
mod tests;
