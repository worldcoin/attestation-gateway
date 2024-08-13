use aws_sdk_kms::types::{KeySpec, Tag};
use base64::{engine::general_purpose, Engine};
use openssl::{
    bn::{BigNum, BigNumContext},
    pkey::{PKey, Public},
};
use redis::{aio::ConnectionManager, AsyncCommands};

use josekit::{jwk::Jwk, Value};
use serde::{Deserialize, Serialize};

use crate::{kms_jws::KMSKeyDefinition, utils::SIGNING_CONFIG};

const SIGNING_KEYS_REDIS_KEY: &str = "signing-keys";

// FIXME: key clean up from Redis and AWS

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigningKey {
    pub key_definition: KMSKeyDefinition,
    pub jwk: Jwk,
    pub created_at: u64,
}

pub async fn fetch_keys(
    redis: &mut ConnectionManager,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<Vec<SigningKey>> {
    let keys: Vec<Vec<u8>> = redis.lrange(SIGNING_KEYS_REDIS_KEY, 0, -1).await?;

    let objects: Vec<SigningKey> = keys
        .into_iter()
        .map(|item| serde_json::from_slice(&item).unwrap())
        .collect();

    if objects.is_empty() {
        return Ok(vec![generate_new_key(redis, aws_config).await?]);
    }

    Ok(objects)
}

pub async fn fetch_active_key(
    redis: &mut ConnectionManager,
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<SigningKey> {
    let key = fetch_keys(redis, aws_config).await?.remove(0);

    if key.created_at + SIGNING_CONFIG.key_ttl_signing < chrono::Utc::now().timestamp() as u64 {
        return generate_new_key(redis, aws_config).await;
    }

    Ok(key)
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
    // FIXME: Lock mechanism to prevent multiple key generation at the same time

    let kms_client = aws_sdk_kms::Client::new(aws_config);
    let key = kms_client
        .create_key()
        .key_spec(SIGNING_CONFIG.key_spec)
        .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
        .set_tags(key_tags()?)
        .send()
        .await?;

    let key_definition = KMSKeyDefinition::from_arn(key.key_metadata.unwrap().arn.unwrap());

    // Fetch public key
    let public_key = kms_client
        .get_public_key()
        .key_id(key_definition.arn.clone())
        .send()
        .await?;

    let public_key = public_key.public_key().ok_or_else(|| {
        eyre::eyre!(
            "Public key not found for newly created key: {:?}",
            key_definition.arn
        )
    })?;

    let public_key = PKey::public_key_from_der(&public_key.clone().into_inner())?;

    let jwk = public_key_to_jwk(&public_key, key_definition.id.clone())?;

    let signing_key = SigningKey {
        key_definition,
        jwk,
        created_at: chrono::Utc::now().timestamp() as u64,
    };

    // FIXME: append to the list of keys, not replace
    redis
        .lpush(
            SIGNING_KEYS_REDIS_KEY,
            serde_json::to_vec(&signing_key.clone())?,
        )
        .await?;

    Ok(signing_key)
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
    )
    .unwrap();
    jwk.set_parameter(
        "y",
        Some(Value::String(general_purpose::URL_SAFE_NO_PAD.encode(y))),
    )
    .unwrap();

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

#[test]
fn test_pad_left() {
    let mut v = vec![5, 6, 7];
    pad_left(&mut v, 3);
    assert_eq!(v, [5, 6, 7]);
    pad_left(&mut v, 8);
    assert_eq!(v, [0, 0, 0, 0, 0, 5, 6, 7]);
}
