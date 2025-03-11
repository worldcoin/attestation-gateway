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
// the certificate is valid until **Sep 6, 2025** after which it has to be replaced
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
    let sep_6_2025 = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    assert!(
        Utc::now() <= sep_6_2025,
        "this test is only valid until Sep 6, 2025. Please replace the attestation."
    );

    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        Some(AAGUID::AppAttestDevelop),
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert_eq!(
        result.key_id,
        "rT9r9AjoYUEZuDc2PDlZJcF2jXwN5Zh9EUPq5kfbneY="
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
        "test",
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
        "test",
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
        "test",
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
