use chrono::{TimeZone, Utc};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Private, Public},
    x509::{
        X509Name,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};

use super::*;

// NOTE: the attestation below is a valid attestation that was generated in World App Staging,
// the certificate is valid until **Feb 28, 2026** after which it has to be replaced
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
    let feb_28_2026 = Utc.with_ymd_and_hms(2026, 2, 28, 0, 0, 0).unwrap();
    assert!(
        Utc::now() <= feb_28_2026,
        "this test is only valid until Feb 28, 2026. Please replace the attestation."
    );

    let result = decode_and_validate_initial_attestation(
        TEST_VALID_ATTESTATION.to_string(),
        TEST_REQUEST_HASH,
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttestDevelop],
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert_eq!(
        result.key_id,
        "/oFIRNfDBjjE6xk6mGWIt2p+8ZVvA8m+ILNAJgkfUwg="
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

    // NOTE: We particularly want to make sure this returns a `ClientException` as this indicates an invalid token was provided
    let result = result.downcast_ref::<ClientException>().unwrap();

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

    let result = result.downcast_ref::<ClientException>().unwrap();

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

    let result = result.downcast_ref::<ClientException>().unwrap();
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
        &[AAGUID::AppAttestDevelop],
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientException>().unwrap();
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
        &[AAGUID::AppAttest],
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientException>().unwrap();
    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
        result.internal_debug_info,
        "unexpected `AAGUID` for bundle identifier.".to_string()
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
        TEST_REQUEST_HASH,
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

    let result = result.downcast_ref::<ClientException>().unwrap();

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

    let result = result.downcast_ref::<ClientException>().unwrap();

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

    let result = result.downcast_ref::<ClientException>().unwrap();

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

    let result = result.downcast_ref::<ClientException>().unwrap();

    // This error is returned because the first bytes of authenticator_data represent the App ID
    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
        result.internal_debug_info,
        "expected `app_id` for bundle identifier and `rp_id` from assertion object do not match."
            .to_string()
    );
}
