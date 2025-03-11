use chrono::{TimeZone, Utc};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Private, Public},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Name,
    },
};

use super::*;

// NOTE: the attestation below is a valid attestation that was generated in World App Staging,
// the certificate is valid until **Oct 5, 2025** after which it has to be replaced
const TEST_VALID_ATTESTATION: &str = "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";
const TEST_REQUEST_HASH: &str = "02072cdf5e347d876a89949e6c11febb55716e3e7026e76b7d90d0bed6cf28e9";

fn helper_create_fake_root_ca() -> (X509, PKey<Private>) {
    // create an EC key pair to sign the fake root CA
    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let secret_key = PKey::from_ec_key(ec_key).unwrap();
    let pk: PKey<Public> =
        PKey::public_key_from_der(&secret_key.public_key_to_der().unwrap()).unwrap();

    // create a new fake root CA
    let mut ca_cert_builder = X509::builder().unwrap();
    ca_cert_builder.set_version(2).unwrap();

    // Set the subject & issuer name
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "Apple App Attestation Root CA") // NOTE: this is the name for Apple's Root CA
        .unwrap();
    let name = name.build();
    ca_cert_builder.set_subject_name(&name).unwrap();
    ca_cert_builder.set_issuer_name(&name).unwrap(); // Self-signed, so issuer is the same as subject

    // Set the public key for the certificate
    ca_cert_builder.set_pubkey(&pk).unwrap();

    ca_cert_builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    ca_cert_builder
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();

    ca_cert_builder
        .sign(&secret_key, MessageDigest::sha384())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    ca_cert_builder.append_extension(basic_constraints).unwrap();

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    ca_cert_builder.append_extension(key_usage).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&ca_cert_builder.x509v3_context(None, None))
        .unwrap();
    ca_cert_builder
        .append_extension(subject_key_identifier)
        .unwrap();

    let ca_cert = ca_cert_builder.build();

    (ca_cert, secret_key)
}

fn helper_create_fake_cert(
    issuer: &X509Name,
    issuer_key: &PKey<Private>,
    common_name: &str,
    is_expired: bool,
) -> (X509, PKey<Private>) {
    // create an EC key pair to be attested in the certificate
    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let secret_key = PKey::from_ec_key(ec_key).unwrap();
    let pk: PKey<Public> =
        PKey::public_key_from_der(&secret_key.public_key_to_der().unwrap()).unwrap();

    let mut ca_cert_builder = X509::builder().unwrap();
    ca_cert_builder.set_version(2).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    name.append_entry_by_text("O", "AAA Certification").unwrap();
    let name = name.build();
    ca_cert_builder.set_subject_name(&name).unwrap();
    ca_cert_builder.set_issuer_name(issuer).unwrap();

    ca_cert_builder.set_pubkey(&pk).unwrap();

    ca_cert_builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    if is_expired {
        let two_minutes_ago = Utc::now() - chrono::Duration::minutes(2);
        ca_cert_builder
            .set_not_after(
                Asn1Time::from_unix(two_minutes_ago.timestamp())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
    } else {
        ca_cert_builder
            .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
    }

    ca_cert_builder
        .sign(issuer_key, MessageDigest::sha384())
        .unwrap();

    (ca_cert_builder.build(), secret_key)
}

// SECTION --- initial attestation ---

#[test]
fn test_verify_initial_attestation_success_real_attestation() {
    // REFERENCE below contains an example attestation to verify proper implementation, however it cannot be used with our code
    // because the server challenge is not hashed which causes a discrepancy in step 2
    // https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
    let oct_5_2025 = Utc.with_ymd_and_hms(2025, 10, 5, 0, 0, 0).unwrap();
    assert!(
        Utc::now() <= oct_5_2025,
        "this test is only valid until Oct 5, 2025. Please replace the attestation."
    );

    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        TEST_REQUEST_HASH,
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert_eq!(
        result.key_id,
        "us1sMB71A6ffTbD5UdkeevxwPIFyFEuI3vNc8R/jiBw="
    );
}

/// This is a test case of the test mechanism to use a fake root CA to sign the attestation.
/// This test helps gurantee the validity of other failure test cases relying on a fake root CA.
#[test]
fn test_verify_initial_attestation_success_on_different_root_ca() {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    let (cert, _) = helper_create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "testhash",
        false,
    );

    let attestation_statement = AttestationStatement {
        x5c: vec![
            cert.to_der().unwrap().into(),
            root_cert.to_der().unwrap().into(),
        ],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(root_cert).unwrap();
    let store = store_builder.build();

    let result = internal_verify_cert_chain_with_store(&attestation, &store);
    assert!(result.is_ok());
}

/// Tests an attestation from a different root CA which is not Apple's Root CA
#[test]
fn test_verify_initial_attestation_failure_on_attestation_not_signed_from_expected_apple_root_ca() {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    let (cert, _) = helper_create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "testhash",
        false,
    );

    let attestation_statement = AttestationStatement {
        // chain is root CA -> cert (total 2)
        x5c: vec![
            cert.to_der().unwrap().into(),
            root_cert.to_der().unwrap().into(),
        ],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let result = verify_cert_chain(&attestation).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate in certificate chain)"
    );
}

#[test]
fn test_verify_cert_chain_failure_cert_not_signed_by_apple_root_ca() {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    let (intermediate_cert, intermediate_key) = helper_create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "Apple App Attestation CA 1",
        false,
    );

    let (cert, _) = helper_create_fake_cert(
        &intermediate_cert.issuer_name().to_owned().unwrap(),
        &intermediate_key,
        "testhash",
        false,
    );

    let attestation_statement = AttestationStatement {
        // chain is root CA -> intermediate cert -> cert (total 3)
        x5c: vec![
            cert.to_der().unwrap().into(),
            intermediate_cert.to_der().unwrap().into(),
            root_cert.to_der().unwrap().into(),
        ],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let result = verify_cert_chain(&attestation).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate in certificate chain)"
    );
}

#[test]
fn test_verify_cert_chain_failure_with_invalid_root_ca() {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    let (intermediate_cert, intermediate_key) = helper_create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "Apple App Attestation CA 1",
        false,
    );

    let (cert, _) = helper_create_fake_cert(
        &intermediate_cert.issuer_name().to_owned().unwrap(),
        &intermediate_key,
        "testhash",
        false,
    );

    let attestation_statement = AttestationStatement {
        // chain is root CA -> intermediate cert -> cert but root CA is not Apple's Root CA and is also not included in the chain
        // note: test where root CA is included in the chain can be found in `test_verify_cert_chain_failure_cert_not_signed_by_apple_root_ca`
        x5c: vec![
            cert.to_der().unwrap().into(),
            intermediate_cert.to_der().unwrap().into(),
        ],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let result = verify_cert_chain(&attestation).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (unable to get local issuer certificate)"
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_self_signed_certificate() {
    let (ca_cert, _) = helper_create_fake_root_ca();

    let attestation_statement = AttestationStatement {
        // chain is root CA (self signed)
        x5c: vec![ca_cert.to_der().unwrap().into()],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let result = verify_cert_chain(&attestation).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate)"
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_expired_certificate() {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    let (cert, _) = helper_create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "testhash",
        true,
    );

    let attestation_statement = AttestationStatement {
        x5c: vec![
            cert.to_der().unwrap().into(),
            root_cert.to_der().unwrap().into(),
        ],
        receipt: ByteBuf::new(),
    };

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: attestation_statement,
        auth_data: ByteBuf::new(),
    };

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(root_cert).unwrap();
    let store = store_builder.build();

    let result = internal_verify_cert_chain_with_store(&attestation, &store).unwrap_err();
    assert_eq!(
        result.to_string(),
        "Certificate verification failed (certificate has expired)"
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_invalid_attestation() {
    let result = decode_and_validate_initial_attestation(
        "this_is_not_base64_encoded".to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap_err();

    // NOTE: We particularly want to make sure this returns a `ClientError` as this indicates an invalid token was provided
    let result = result.downcast_ref::<ClientError>().unwrap();

    assert_eq!(result.code, ErrorCode::InvalidToken);
    assert_eq!(
        result.internal_debug_info,
        "error decoding base64 encoded attestation.".to_string()
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_invalid_cbor_message() {
    //
    let result = decode_and_validate_initial_attestation(
        // This is a valid base64 encoded string but not a valid CBOR message
        // cspell:disable-next-line
        "dGhpcyBpcyBpbnZhbGlk".to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();

    assert_eq!(result.code, ErrorCode::InvalidToken);
    assert_eq!(
        result.internal_debug_info,
        "error decoding cbor formatted attestation.".to_string()
    );
}

#[test]
fn test_verify_initial_attestation_failure_nonce_mismatch() {
    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        "a_different_hash",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();
    assert_eq!(result.code, ErrorCode::IntegrityFailed);
    assert_eq!(
        result.internal_debug_info,
        "nonce in attestation object does not match provided nonce.".to_string()
    );
}

#[test]
fn test_verify_initial_attestation_failure_app_id_mismatch() {
    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        TEST_REQUEST_HASH,
        BundleIdentifier::IOSProdWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();
    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
        result.internal_debug_info,
        "expected `app_id` for bundle identifier and `rp_id` from attestation object do not match."
            .to_string()
    );
}

#[test]
fn test_verify_initial_attestation_failure_aaguid_mismatch() {
    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        TEST_REQUEST_HASH,
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttest),
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();
    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
    result.internal_debug_info,
    "expected `AAGUID` for bundle identifier and `AAGUID` from attestation object do not match."
        .to_string()
);
}

/// For staging apps it's useful to bypass the `AAGUID` check as the app may be running on either the development or production environment
#[test]
fn test_verify_initial_attestation_bypassing_aaguid_check_for_staging_apps() {
    let expected_aaguid =
        AAGUID::from_bundle_identifier(&BundleIdentifier::IOSStageWorldApp).unwrap();
    assert!(expected_aaguid.is_none());

    decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        TEST_REQUEST_HASH,
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        expected_aaguid,
    )
    .unwrap();
}

#[test]
fn test_ensure_production_app_does_not_bypass_aaguid_check() {
    let expected_aaguid = AAGUID::from_bundle_identifier(&BundleIdentifier::IOSProdWorldApp)
        .unwrap()
        .unwrap();
    assert_eq!(expected_aaguid, AAGUID::AppAttest);
}

// SECTION --- assertions with attested public key (after initial attestation) ---

#[test]
fn verify_assertion_success() {
    // cspell:disable-next-line
    let valid_assertion = "omlzaWduYXR1cmVYSDBGAiEA0Qs8Xf23WStR6ZhWteHd6sS6YQ14VgDrC4+8vrakNFMCIQCl8CZ2iqpujjgbWxO7vadwCy3WSSB09Mi9X3tp+97ZrHFhdXRoZW50aWNhdG9yRGF0YVgl0lgIg/cWKQldEqyGUrhbrxBv4j/WaJlzkB6N9Dmg63VAAAAAAQ==";

    let result = decode_and_validate_assertion(
        valid_assertion.to_string(),
        // notice this is the public key from test_verify_initial_attestation_success
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu5PyE6mg2JOA19zIosBmv/18/3B5ySWGLET7mQhWijPWWtKPEjdfDME7djEYaT81tvWoXXm95qfBYZw3Q2YDmQ==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        TEST_REQUEST_HASH,
        0,
    );

    assert!(result.is_ok());
}

#[test]
fn verify_assertion_success_two() {
    // cspell:disable-next-line
    let valid_assertion = "omlzaWduYXR1cmVYRjBEAiBR6EAxMJ5hyeJgItBum9qi0yNnPpl5COOw/m740jfpmQIgeoTihUfmyWMXGGMAOXq83wKD4dJ1Tv9CD1VPVFWN1DtxYXV0aGVudGljYXRvckRhdGFYJdJYCIP3FikJXRKshlK4W68Qb+I/1miZc5AejfQ5oOt1QAAAAAE=";

    let result = decode_and_validate_assertion(
        valid_assertion.to_string(),
        // notice this is the public key from test_verify_initial_attestation_success
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4Bd1IrEnNal/KNplK6VVrByUq4jsVtVVxpMI/mezeQcluflXHikUxYe+xoB/fAL3VnEA5zJlLobpHcfn/4+7w==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        "test",
        0,
    );

    assert!(result.is_ok());
}

#[test]
fn verify_assertion_failure_with_invalid_counter() {
    let valid_assertion = "omlzaWduYXR1cmVYRjBEAiBR6EAxMJ5hyeJgItBum9qi0yNnPpl5COOw/m740jfpmQIgeoTihUfmyWMXGGMAOXq83wKD4dJ1Tv9CD1VPVFWN1DtxYXV0aGVudGljYXRvckRhdGFYJdJYCIP3FikJXRKshlK4W68Qb+I/1miZc5AejfQ5oOt1QAAAAAE=";

    let result = decode_and_validate_assertion(
        valid_assertion.to_string(),
        // notice this is the public key from test_verify_initial_attestation_success
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4Bd1IrEnNal/KNplK6VVrByUq4jsVtVVxpMI/mezeQcluflXHikUxYe+xoB/fAL3VnEA5zJlLobpHcfn/4+7w==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        "test",
        1,
    ).unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();

    assert_eq!(result.code, ErrorCode::ExpiredToken);
    assert_eq!(
        result.internal_debug_info,
        "last_counter is greater than provided counter.".to_string()
    );
}

#[test]
fn verify_assertion_failure_with_invalid_hash() {
    let valid_assertion = "omlzaWduYXR1cmVYRjBEAiBR6EAxMJ5hyeJgItBum9qi0yNnPpl5COOw/m740jfpmQIgeoTihUfmyWMXGGMAOXq83wKD4dJ1Tv9CD1VPVFWN1DtxYXV0aGVudGljYXRvckRhdGFYJdJYCIP3FikJXRKshlK4W68Qb+I/1miZc5AejfQ5oOt1QAAAAAE=";

    let result = decode_and_validate_assertion(
        valid_assertion.to_string(),
        // notice this is the public key from test_verify_initial_attestation_success
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4Bd1IrEnNal/KNplK6VVrByUq4jsVtVVxpMI/mezeQcluflXHikUxYe+xoB/fAL3VnEA5zJlLobpHcfn/4+7w==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        "not_the_hash_i_expect",
        0,
    ).unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();

    assert_eq!(result.code, ErrorCode::InvalidToken);
    assert_eq!(
        result.internal_debug_info,
        "signature failed validation for public key (request_hash may be wrong)".to_string()
    );
}

#[test]
fn verify_assertion_failure_with_invalid_key() {
    let fake_authenticator_data = ByteBuf::from(
        "this_is_not_a_valid_authenticator_data_but_verification_will_not_reach_here".as_bytes(),
    );

    // Get the P-256 curve
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();

    // Generate a fake private key
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let fake_key = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();

    // Compute nonce
    let request_hash = "my_hash";
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let hashed_nonce = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&fake_authenticator_data);
    hasher.update(&hashed_nonce);
    let nonce: &[u8] = &hasher.finish();

    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &fake_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(nonce).unwrap();

    let assertion = Assertion {
        authenticator_data: fake_authenticator_data,
        signature: ByteBuf::from(signature),
    };

    let mut encoded_assertion: Vec<u8> = Vec::new();

    ciborium::into_writer(&assertion, &mut encoded_assertion).unwrap();

    let encoded_assertion = general_purpose::STANDARD.encode(encoded_assertion);
    // We also use this assertion for `test_apple_token_generation_assertion_with_an_invalidly_signed_assertion`

    let result = decode_and_validate_assertion(
         encoded_assertion,
        // notice this public key does not match the `fake_public_key` generated above
         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4Bd1IrEnNal/KNplK6VVrByUq4jsVtVVxpMI/mezeQcluflXHikUxYe+xoB/fAL3VnEA5zJlLobpHcfn/4+7w==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        request_hash,
        0,
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();

    assert_eq!(result.code, ErrorCode::InvalidToken);
    assert_eq!(
        result.internal_debug_info,
        "signature failed validation for public key (request_hash may be wrong)".to_string()
    );
}

#[test]
fn verify_assertion_failure_with_invalid_authenticator_data() {
    let fake_authenticator_data =
        ByteBuf::from("these_are_not_the_expected_bytes_of_data".as_bytes());

    // Get the P-256 curve
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();

    // Generate a fake private key
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let fake_key = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();

    // Compute nonce
    let request_hash = "my_hash";
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let hashed_nonce = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&fake_authenticator_data);
    hasher.update(&hashed_nonce);
    let nonce: &[u8] = &hasher.finish();

    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &fake_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(nonce).unwrap();

    let assertion = Assertion {
        authenticator_data: fake_authenticator_data,
        signature: ByteBuf::from(signature),
    };

    let mut encoded_assertion: Vec<u8> = Vec::new();

    ciborium::into_writer(&assertion, &mut encoded_assertion).unwrap();

    let encoded_assertion = general_purpose::STANDARD.encode(encoded_assertion);

    let result = decode_and_validate_assertion(
        encoded_assertion,
        general_purpose::STANDARD.encode(fake_key.public_key_to_der().unwrap()),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        request_hash,
        0,
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientError>().unwrap();

    // This error is returned because the first bytes of authenticator_data represent the App ID
    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
        result.internal_debug_info,
        "expected `app_id` for bundle identifier and `rp_id` from assertion object do not match."
            .to_string()
    );
}
