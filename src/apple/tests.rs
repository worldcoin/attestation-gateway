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
// the certificate is valid until **Feb 14, 2025** after which it has to be replaced
const TEST_VALID_ATTESTATION: &str = "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";

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
    let feb_1_2025 = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();
    assert!(
        Utc::now() <= feb_1_2025,
        "this test is only valid until Feb 14, 2025. Please replace the attestation."
    );

    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttestDevelop],
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert_eq!(
        result.key_id,
        "OEQf1t214ajtjlmQ29xNeMtdWYOf4dUWDJQrQFqCJIw="
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
        &[AAGUID::AppAttestDevelop],
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
        &[AAGUID::AppAttestDevelop],
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
        &[AAGUID::AppAttestDevelop],
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
        "test",
        BundleIdentifier::IOSProdWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttestDevelop],
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
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttest],
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
    let expected_aaguids =
        AAGUID::allowed_for_bundle_identifier(&BundleIdentifier::IOSStageWorldApp).unwrap();
    assert_eq!(expected_aaguids.len(), 2);

    decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &expected_aaguids,
    )
    .unwrap();
}

// TODO: This is currently allowed, uncomment the test when this changes
#[ignore = "This is currently allowed, uncomment the test when this changes"]
#[test]
fn test_ensure_production_app_does_not_bypass_aaguid_check() {
    let expected_aaguids =
        AAGUID::allowed_for_bundle_identifier(&BundleIdentifier::IOSProdWorldApp).unwrap();
    assert_eq!(expected_aaguids, [AAGUID::AppAttest]);
}

// SECTION --- assertions with attested public key (after initial attestation) ---

#[test]
fn verify_assertion_success() {
    // cspell:disable-next-line
    let valid_assertion = "omlzaWduYXR1cmVYRzBFAiBpd06ZONnjmJ2m/kD/DYQ5G5WQzEaXsuI68fo+746SRAIhAKEqmog8GorUtxeFcAHeB4yYj0xrTzQHenABYSwSDUBWcWF1dGhlbnRpY2F0b3JEYXRhWCXSWAiD9xYpCV0SrIZSuFuvEG/iP9ZomXOQHo30OaDrdUAAAAAB";

    let result = decode_and_validate_assertion(
        valid_assertion.to_string(),
        // notice this is the public key from test_verify_initial_attestation_success
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHB6lDlPsxyNES6JSYM+w5rIxF5nPeN19dwNlSLYGU9LFx5kYOKeajWrsEPT3laf1UL07S0ANVG+2Hr5lCieiDw==".to_string(),
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        "testhash",
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
