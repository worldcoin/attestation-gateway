use super::test_helpers::{
    apple_root_ca_store, build_test_attestation, create_fake_cert, create_fake_root_ca,
};
use super::*;

// SECTION --- initial attestation ---

#[test]
fn test_verify_initial_attestation_success_with_test_attestation() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "test_request_hash";
    let test_data = build_test_attestation(app_id, request_hash, "appattestdevelop");

    let result = decode_and_validate_initial_attestation(
        test_data.attestation_base64,
        request_hash,
        app_id,
        &[AAGUID::AppAttestDevelop],
        &test_data.root_ca_pem,
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert!(!result.key_id.is_empty());
}

/// This is a test case of the test mechanism to use a fake root CA to sign the attestation.
/// This test helps gurantee the validity of other failure test cases relying on a fake root CA.
#[test]
fn test_verify_initial_attestation_success_on_different_root_ca() {
    let (root_cert, root_key) = create_fake_root_ca();

    let (cert, _) = create_fake_cert(
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
    let (root_cert, root_key) = create_fake_root_ca();

    let (cert, _) = create_fake_cert(
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

    // Use the real Apple root CA store; this chain is not signed by Apple so it should fail
    let store = apple_root_ca_store();

    let result = internal_verify_cert_chain_with_store(&attestation, &store).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate in certificate chain)"
    );
}

#[test]
fn test_verify_cert_chain_failure_cert_not_signed_by_apple_root_ca() {
    let (root_cert, root_key) = create_fake_root_ca();

    let (intermediate_cert, intermediate_key) = create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "Apple App Attestation CA 1",
        false,
    );

    let (cert, _) = create_fake_cert(
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

    let store = apple_root_ca_store();

    let result = internal_verify_cert_chain_with_store(&attestation, &store).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate in certificate chain)"
    );
}

#[test]
fn test_verify_cert_chain_failure_with_invalid_root_ca() {
    let (root_cert, root_key) = create_fake_root_ca();

    let (intermediate_cert, intermediate_key) = create_fake_cert(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        "Apple App Attestation CA 1",
        false,
    );

    let (cert, _) = create_fake_cert(
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

    let store = apple_root_ca_store();

    let result = internal_verify_cert_chain_with_store(&attestation, &store).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (unable to get local issuer certificate)"
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_self_signed_certificate() {
    let (ca_cert, _) = create_fake_root_ca();

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

    let store = apple_root_ca_store();

    let result = internal_verify_cert_chain_with_store(&attestation, &store).unwrap_err();

    assert_eq!(
        result.to_string(),
        "Certificate verification failed (self-signed certificate)"
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_expired_certificate() {
    let (root_cert, root_key) = create_fake_root_ca();

    let (cert, _) = create_fake_cert(
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
        include_bytes!("./apple_app_attestation_root_ca.pem"),
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
        include_bytes!("./apple_app_attestation_root_ca.pem"),
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
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let test_data = build_test_attestation(app_id, "hash_a", "appattestdevelop");

    let result = decode_and_validate_initial_attestation(
        test_data.attestation_base64,
        "hash_b",
        app_id,
        &[AAGUID::AppAttestDevelop],
        &test_data.root_ca_pem,
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
    let staging_app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let prod_app_id = BundleIdentifier::IOSProdWorldApp.apple_app_id().unwrap();
    let request_hash = "test_request_hash";
    // Build test attestation with staging app_id
    let test_data = build_test_attestation(staging_app_id, request_hash, "appattestdevelop");

    // Verify with prod app_id — should fail
    let result = decode_and_validate_initial_attestation(
        test_data.attestation_base64,
        request_hash,
        prod_app_id,
        &[AAGUID::AppAttestDevelop],
        &test_data.root_ca_pem,
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
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "test_request_hash";
    // Build test attestation with develop AAGUID
    let test_data = build_test_attestation(app_id, request_hash, "appattestdevelop");

    // Only allow production AAGUID — should fail
    let result = decode_and_validate_initial_attestation(
        test_data.attestation_base64,
        request_hash,
        app_id,
        &[AAGUID::AppAttest],
        &test_data.root_ca_pem,
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

    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "test_request_hash";
    // Build test attestation with develop AAGUID, but allow both
    let test_data = build_test_attestation(app_id, request_hash, "appattestdevelop");

    decode_and_validate_initial_attestation(
        test_data.attestation_base64,
        request_hash,
        app_id,
        &expected_aaguids,
        &test_data.root_ca_pem,
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
        "02072cdf5e347d876a89949e6c11febb55716e3e7026e76b7d90d0bed6cf28e9",
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
