use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    x509::{
        X509, X509Extension, X509Name,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        store::X509StoreBuilder,
    },
};

use super::*;

// ---------------------------------------------------------------------------
// Helpers: certificate generation
// ---------------------------------------------------------------------------

fn helper_create_fake_root_ca() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let secret_key = PKey::from_ec_key(ec_key).unwrap();
    let pk: PKey<Public> =
        PKey::public_key_from_der(&secret_key.public_key_to_der().unwrap()).unwrap();

    let mut ca_cert_builder = X509::builder().unwrap();
    ca_cert_builder.set_version(2).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "Apple App Attestation Root CA")
        .unwrap();
    let name = name.build();
    ca_cert_builder.set_subject_name(&name).unwrap();
    ca_cert_builder.set_issuer_name(&name).unwrap();
    ca_cert_builder.set_pubkey(&pk).unwrap();

    ca_cert_builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    ca_cert_builder
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
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

    ca_cert_builder
        .sign(&secret_key, MessageDigest::sha256())
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
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
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
        let two_minutes_ago = chrono::Utc::now() - chrono::Duration::minutes(2);
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
        .sign(issuer_key, MessageDigest::sha256())
        .unwrap();

    (ca_cert_builder.build(), secret_key)
}

/// Build a leaf certificate that embeds the given `nonce` inside extension OID 1.2.840.113635.100.8.2
/// (the Apple App Attestation nonce extension), signed by `issuer_key`.
fn helper_create_attestation_leaf_cert(
    issuer: &X509Name,
    issuer_key: &PKey<Private>,
    public_key: &PKey<Public>,
    nonce: &[u8; 32],
) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "mock-attestation-leaf")
        .unwrap();
    name.append_entry_by_text("O", "AAA Certification").unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(issuer).unwrap();
    builder.set_pubkey(public_key).unwrap();

    builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();

    // Embed nonce in Apple's custom extension (OID 1.2.840.113635.100.8.2).
    // The expected DER structure (as parsed by the verification code) is:
    //   SEQUENCE { [1] EXPLICIT { OCTET STRING <nonce> } }
    let mut ext_value: Vec<u8> = Vec::with_capacity(38);
    // SEQUENCE tag + length
    ext_value.push(0x30);
    ext_value.push(0x24);
    // Context [1] constructed explicit tag + length
    ext_value.push(0xA1);
    ext_value.push(0x22);
    // OCTET STRING tag + length (32)
    ext_value.push(0x04);
    ext_value.push(0x20);
    ext_value.extend_from_slice(nonce);

    let oid = Asn1Object::from_str("1.2.840.113635.100.8.2").unwrap();
    let octet = Asn1OctetString::new_from_bytes(&ext_value).unwrap();
    let ext = X509Extension::new_from_der(&oid, false, &octet).unwrap();
    builder.append_extension(ext).unwrap();

    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

// ---------------------------------------------------------------------------
// Helpers: mock attestation & assertion builders
// ---------------------------------------------------------------------------

struct MockAttestationOutput {
    attestation_b64: String,
    attested_private_key: PKey<Private>,
    cert_store: X509Store,
}

/// Builds a complete mock Apple attestation object (CBOR + base64) that passes all
/// verification steps when validated against the returned `cert_store`.
///
/// Returns the base64-encoded attestation, the private key for signing future assertions,
/// and the X509Store containing the mock root CA.
fn helper_build_mock_attestation(
    app_id: &str,
    request_hash: &str,
    aaguid: &AAGUID,
) -> MockAttestationOutput {
    let (root_cert, root_key) = helper_create_fake_root_ca();

    // Generate the attested device key (P-256)
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let attested_private_key = PKey::from_ec_key(ec_key).unwrap();
    let attested_public_key: PKey<Public> =
        PKey::public_key_from_der(&attested_private_key.public_key_to_der().unwrap()).unwrap();

    // Extract raw public key bytes (uncompressed EC point) from the SPKI DER encoding.
    // This matches what the verification code reads via `res.public_key().subject_public_key.data`.
    let raw_public_key = {
        use x509_parser::prelude::FromDer;
        let der = attested_public_key.public_key_to_der().unwrap();
        let (_, spki) = x509_parser::prelude::SubjectPublicKeyInfo::from_der(&der).unwrap();
        spki.subject_public_key.data.to_vec()
    };

    // credential_id = SHA256(raw_public_key)
    let mut hasher = Sha256::new();
    hasher.update(&raw_public_key);
    let credential_id: [u8; 32] = hasher.finish();

    // Build auth_data
    // [0..32]  = SHA256(app_id)
    // [32]     = flags byte (0x40 = attested credential data present)
    // [33..37] = counter (u32 BE) = 0
    // [37..53] = AAGUID (16 bytes)
    // [53..55] = credential_id length (u16 BE) = 32
    // [55..87] = credential_id
    let mut auth_data = Vec::with_capacity(87);

    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    auth_data.extend_from_slice(&hasher.finish()); // rp_id_hash [0..32]

    auth_data.push(0x40); // flags [32]
    auth_data.extend_from_slice(&0u32.to_be_bytes()); // counter [33..37]

    let aaguid_bytes: &[u8; 16] = match aaguid {
        AAGUID::AppAttest => b"appattest\0\0\0\0\0\0\0",
        AAGUID::AppAttestDevelop => b"appattestdevelop",
    };
    auth_data.extend_from_slice(aaguid_bytes); // aaguid [37..53]

    auth_data.extend_from_slice(&32u16.to_be_bytes()); // cred_id_len [53..55]
    auth_data.extend_from_slice(&credential_id); // credential_id [55..87]

    // Compute nonce = SHA256(auth_data || SHA256(request_hash))
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let client_data_hash = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&auth_data);
    hasher.update(&client_data_hash);
    let nonce: [u8; 32] = hasher.finish();

    // Build leaf certificate with the nonce extension
    let leaf_cert = helper_create_attestation_leaf_cert(
        &root_cert.subject_name().to_owned().unwrap(),
        &root_key,
        &attested_public_key,
        &nonce,
    );

    // Build Attestation CBOR object
    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: AttestationStatement {
            x5c: vec![
                leaf_cert.to_der().unwrap().into(),
                root_cert.to_der().unwrap().into(),
            ],
            receipt: ByteBuf::from(b"mock-receipt".as_slice()),
        },
        auth_data: ByteBuf::from(auth_data),
    };

    let mut cbor_bytes: Vec<u8> = Vec::new();
    ciborium::into_writer(&attestation, &mut cbor_bytes).unwrap();
    let attestation_b64 = general_purpose::STANDARD.encode(&cbor_bytes);

    // Build cert store with the mock root CA
    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(root_cert).unwrap();
    let cert_store = store_builder.build();

    MockAttestationOutput {
        attestation_b64,
        attested_private_key,
        cert_store,
    }
}

struct MockAssertionOutput {
    assertion_b64: String,
    public_key_b64: String,
}

/// Builds a complete mock Apple assertion (CBOR + base64) signed by the given private key.
fn helper_build_mock_assertion(
    private_key: &PKey<Private>,
    app_id: &str,
    request_hash: &str,
    counter: u32,
) -> MockAssertionOutput {
    // Build authenticator_data
    // [0..32]  = SHA256(app_id)
    // [32]     = flags byte
    // [33..37] = counter (u32 BE)
    let mut authenticator_data = Vec::with_capacity(37);

    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    authenticator_data.extend_from_slice(&hasher.finish());

    authenticator_data.push(0x00); // flags
    authenticator_data.extend_from_slice(&counter.to_be_bytes());

    // Compute nonce = SHA256(authenticator_data || SHA256(request_hash))
    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let hashed_request = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&authenticator_data);
    hasher.update(&hashed_request);
    let nonce: &[u8] = &hasher.finish();

    // Sign the nonce
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), private_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(nonce).unwrap();

    let assertion = Assertion {
        authenticator_data: ByteBuf::from(authenticator_data),
        signature: ByteBuf::from(signature),
    };

    let mut cbor_bytes: Vec<u8> = Vec::new();
    ciborium::into_writer(&assertion, &mut cbor_bytes).unwrap();
    let assertion_b64 = general_purpose::STANDARD.encode(&cbor_bytes);

    let public_key_b64 = general_purpose::STANDARD.encode(private_key.public_key_to_der().unwrap());

    MockAssertionOutput {
        assertion_b64,
        public_key_b64,
    }
}

// ===========================================================================
// SECTION --- initial attestation ---
// ===========================================================================

#[test]
fn test_verify_initial_attestation_success() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "mock_request_hash_for_success_test";

    let mock = helper_build_mock_attestation(app_id, request_hash, &AAGUID::AppAttestDevelop);

    let result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        request_hash,
        app_id,
        &[AAGUID::AppAttestDevelop],
        &mock.cert_store,
    )
    .unwrap();

    assert!(!result.receipt.is_empty());
    assert!(!result.public_key.is_empty());
    assert!(!result.key_id.is_empty());
}

#[test]
fn test_verify_initial_attestation_success_with_appattest_aaguid() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "test_appattest_production_aaguid";

    let mock = helper_build_mock_attestation(app_id, request_hash, &AAGUID::AppAttest);

    let result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        request_hash,
        app_id,
        &[AAGUID::AppAttest],
        &mock.cert_store,
    );

    assert!(result.is_ok());
}

/// Validates that the cert chain verification still works with a custom store
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
    let store = apple_root_ca_store().unwrap();
    let result = decode_and_validate_initial_attestation(
        "this_is_not_base64_encoded".to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttestDevelop],
        &store,
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientException>().unwrap();

    assert_eq!(result.code, ErrorCode::InvalidToken);
    assert_eq!(
        result.internal_debug_info,
        "error decoding base64 encoded attestation.".to_string()
    );
}

#[test]
fn test_verify_initial_attestation_failure_on_invalid_cbor_message() {
    let store = apple_root_ca_store().unwrap();
    let result = decode_and_validate_initial_attestation(
        // cspell:disable-next-line
        "dGhpcyBpcyBpbnZhbGlk".to_string(),
        "test",
        BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap(),
        &[AAGUID::AppAttestDevelop],
        &store,
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

    let mock = helper_build_mock_attestation(app_id, "original_hash", &AAGUID::AppAttestDevelop);

    let result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        "a_different_hash",
        app_id,
        &[AAGUID::AppAttestDevelop],
        &mock.cert_store,
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
    let request_hash = "test_app_id_mismatch";

    let mock =
        helper_build_mock_attestation(staging_app_id, request_hash, &AAGUID::AppAttestDevelop);

    let result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        request_hash,
        prod_app_id,
        &[AAGUID::AppAttestDevelop],
        &mock.cert_store,
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
    let request_hash = "test_aaguid_mismatch";

    let mock = helper_build_mock_attestation(app_id, request_hash, &AAGUID::AppAttestDevelop);

    let result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        request_hash,
        app_id,
        &[AAGUID::AppAttest], // mismatch: attestation has AppAttestDevelop
        &mock.cert_store,
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
    let request_hash = "test_bypass_aaguid";

    let mock = helper_build_mock_attestation(app_id, request_hash, &AAGUID::AppAttestDevelop);

    decode_and_validate_initial_attestation(
        mock.attestation_b64,
        request_hash,
        app_id,
        &expected_aaguids,
        &mock.cert_store,
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

// ===========================================================================
// SECTION --- assertions with attested public key (after initial attestation)
// ===========================================================================

#[test]
fn verify_assertion_success() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "assertion_success_hash";

    let mock = helper_build_mock_attestation(
        app_id,
        "initial_attestation_hash",
        &AAGUID::AppAttestDevelop,
    );

    let assertion =
        helper_build_mock_assertion(&mock.attested_private_key, app_id, request_hash, 1);

    let result = decode_and_validate_assertion(
        assertion.assertion_b64,
        assertion.public_key_b64,
        app_id,
        request_hash,
        0,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
}

#[test]
fn verify_assertion_success_with_higher_counter() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "assertion_counter_test";

    let mock = helper_build_mock_attestation(app_id, "initial", &AAGUID::AppAttestDevelop);

    let assertion =
        helper_build_mock_assertion(&mock.attested_private_key, app_id, request_hash, 5);

    let result = decode_and_validate_assertion(
        assertion.assertion_b64,
        assertion.public_key_b64,
        app_id,
        request_hash,
        4,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 5);
}

#[test]
fn verify_assertion_failure_with_invalid_counter() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "counter_fail_test";

    let mock = helper_build_mock_attestation(app_id, "initial", &AAGUID::AppAttestDevelop);

    let assertion =
        helper_build_mock_assertion(&mock.attested_private_key, app_id, request_hash, 1);

    let result = decode_and_validate_assertion(
        assertion.assertion_b64,
        assertion.public_key_b64,
        app_id,
        request_hash,
        1, // last_counter == counter → should fail
    )
    .unwrap_err();

    let result = result.downcast_ref::<ClientException>().unwrap();

    assert_eq!(result.code, ErrorCode::ExpiredToken);
    assert_eq!(
        result.internal_debug_info,
        "last_counter is greater than provided counter.".to_string()
    );
}

#[test]
fn verify_assertion_failure_with_invalid_hash() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();

    let mock = helper_build_mock_attestation(app_id, "initial", &AAGUID::AppAttestDevelop);

    let assertion =
        helper_build_mock_assertion(&mock.attested_private_key, app_id, "signed_hash", 1);

    let result = decode_and_validate_assertion(
        assertion.assertion_b64,
        assertion.public_key_b64,
        app_id,
        "not_the_hash_i_expect",
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
fn verify_assertion_failure_with_invalid_key() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let request_hash = "key_mismatch_test";

    let mock = helper_build_mock_attestation(app_id, "initial", &AAGUID::AppAttestDevelop);

    let assertion =
        helper_build_mock_assertion(&mock.attested_private_key, app_id, request_hash, 1);

    // Generate a different key pair — the public key won't match the signer
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let wrong_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let wrong_public_key_b64 =
        general_purpose::STANDARD.encode(wrong_key.public_key_to_der().unwrap());

    let result = decode_and_validate_assertion(
        assertion.assertion_b64,
        wrong_public_key_b64,
        app_id,
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

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let fake_key = PKey::from_ec_key(ec_key).unwrap();

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

    assert_eq!(result.code, ErrorCode::InvalidAttestationForApp);
    assert_eq!(
        result.internal_debug_info,
        "expected `app_id` for bundle identifier and `rp_id` from assertion object do not match."
            .to_string()
    );
}

// ===========================================================================
// SECTION --- full attestation + assertion flow
// ===========================================================================

#[test]
fn test_full_attestation_then_assertion_flow() {
    let app_id = BundleIdentifier::IOSStageWorldApp.apple_app_id().unwrap();
    let attestation_request_hash = "full_flow_attestation";

    let mock =
        helper_build_mock_attestation(app_id, attestation_request_hash, &AAGUID::AppAttestDevelop);

    // Step 1: verify initial attestation
    let attestation_result = decode_and_validate_initial_attestation(
        mock.attestation_b64,
        attestation_request_hash,
        app_id,
        &[AAGUID::AppAttestDevelop],
        &mock.cert_store,
    )
    .unwrap();

    assert!(!attestation_result.public_key.is_empty());

    // Step 2: verify assertion using the attested key
    let assertion_request_hash = "full_flow_assertion";
    let assertion = helper_build_mock_assertion(
        &mock.attested_private_key,
        app_id,
        assertion_request_hash,
        1,
    );

    let counter = decode_and_validate_assertion(
        assertion.assertion_b64,
        attestation_result.public_key,
        app_id,
        assertion_request_hash,
        0,
    )
    .unwrap();

    assert_eq!(counter, 1);
}
