use std::time::SystemTime;

use josekit::{
    jws::{JwsSigner, ES256},
    jwt,
};

use crate::utils::{OutEnum, OutputTokenPayload};

/// This public key is the pair for the test private key set in `/tests/kms-seed.yml`
static PUBLIC_KEY_FOR_TESTS: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94U
N71quXN3f0P/tprs2Fp2FEasM7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
-----END PUBLIC KEY-----
";

/// This key ID is set in `/tests/kms-seed.yml`
static TEST_KEY_ARN: &str =
    "arn:aws:kms:us-east-1:000000001111:key/c7956b9c-5235-4e8e-bb35-7310fb80f4ca";

async fn get_aws_config() -> aws_config::SdkConfig {
    // Required to load default AWS Config variables
    dotenvy::from_filename(".env.example").unwrap();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    aws_config
        .into_builder()
        .endpoint_url("http://localhost:4566")
        .build()
}

async fn get_kms_client() -> aws_sdk_kms::Client {
    let aws_config = get_aws_config().await;
    aws_sdk_kms::Client::new(&aws_config)
}

#[tokio::test]
async fn test_key_id_extraction() {
    let key_arn = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789013";

    let signer = super::EcdsaJwsSignerWithKms::new(key_arn.to_string(), get_kms_client().await);

    assert_eq!(
        signer.key_id(),
        // cspell:disable-next-line
        Some("key_8tiTdqKEcoAl61KmnoyvtNf5IXz9SdyEI9XFjQ")
    );

    assert_eq!(signer.algorithm().name(), "ES256");

    assert_eq!(signer.signature_len(), 64);
}

#[tokio::test]
#[should_panic(expected = "index out of bounds: the len is 1 but the index is 1")]
async fn test_invalid_key_arn_in_extraction() {
    let key_arn = "12345678-1234-1234-1234-123456789012";

    let signer = super::EcdsaJwsSignerWithKms::new(key_arn.to_string(), get_kms_client().await);

    signer.key_id(); // This should panic
}

#[tokio::test]
/// Integration test (requires docker-compose.test.yml to be running)
async fn test_sign_with_kms() {
    let message = b"hello, world!";

    let signature = super::sign_with_kms(&get_kms_client().await, TEST_KEY_ARN, message).await;

    assert!(signature.is_ok());
    let signature = signature.unwrap();

    // `secp256r1` curve with ASN.1 DER encoding
    assert!(70 <= signature.len() && signature.len() <= 72);
}

#[tokio::test]
/// Integration test (requires docker-compose.test.yml to be running)
async fn test_generate_output_token() {
    let aws_config = get_aws_config().await;

    let output_token_payload = OutputTokenPayload {
        aud: "example.worldcoin.org".to_string(),
        request_hash: "a_sample_request_hash".to_string(),
        pass: true,
        out: OutEnum::Pass,
        error: None,
    }
    .generate()
    .unwrap();

    let jwt =
        super::generate_output_token(&aws_config, TEST_KEY_ARN.to_string(), output_token_payload)
            .await
            .unwrap();

    // Verify and parse the JWT

    let verifier = ES256.verifier_from_pem(PUBLIC_KEY_FOR_TESTS).unwrap();
    let (payload, header) = jwt::decode_with_verifier(jwt, &verifier).unwrap();

    assert_eq!(header.token_type(), Some("JWT"));
    assert_eq!(header.algorithm(), Some("ES256"));

    assert_eq!(
        header.key_id(),
        // cspell:disable-next-line
        Some("key_xiJPC077-jQBVU_WMLNPYlEKnFh4abA0t1mkWg")
    );

    // Assert expiration
    assert!(
        payload.expires_at().unwrap()
            < (SystemTime::now() +
                // expiration time (this is set in utils.rs)
                std::time::Duration::from_secs(600) +
                // tolerance time
                std::time::Duration::from_secs(5))
    );

    assert_eq!(payload.issuer(), Some("attestation.worldcoin.org"));
    assert_eq!(
        payload.claim("aud"),
        Some(&josekit::Value::String("example.worldcoin.org".to_string()))
    );
    assert_eq!(
        payload.claim("jti"),
        Some(&josekit::Value::String("a_sample_request_hash".to_string()))
    );
    assert_eq!(payload.claim("pass"), Some(&josekit::Value::Bool(true)));
    assert_eq!(
        payload.claim("out"),
        Some(&josekit::Value::String("pass".to_string()))
    );
    assert_eq!(payload.claim("error"), None);
}
