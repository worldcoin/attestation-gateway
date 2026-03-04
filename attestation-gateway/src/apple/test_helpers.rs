use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sha::Sha256,
    x509::{
        X509, X509Name,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
use serde_bytes::ByteBuf;
use x509_parser::prelude::FromDer;

use super::{Attestation, AttestationStatement};

pub struct TestAttestation {
    pub attestation_base64: String,
    pub root_ca_pem: Vec<u8>,
    pub key_id: String,
    pub public_key: String,
}

pub fn create_fake_root_ca() -> (X509, PKey<Private>) {
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
        .sign(&secret_key, MessageDigest::sha384())
        .unwrap();

    let ca_cert = ca_cert_builder.build();

    (ca_cert, secret_key)
}

pub fn create_fake_cert(
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

fn create_nonce_extension_der(nonce: &[u8; 32]) -> Vec<u8> {
    let mut octet_string = vec![0x04, 0x20];
    octet_string.extend_from_slice(nonce);

    let mut tagged = vec![0xa0, octet_string.len() as u8];
    tagged.extend_from_slice(&octet_string);

    let mut seq = vec![0x30, tagged.len() as u8];
    seq.extend_from_slice(&tagged);

    seq
}

fn create_leaf_cert_with_nonce(
    issuer_name: &X509Name,
    issuer_key: &PKey<Private>,
    ec_public_key: &PKey<Public>,
    nonce: &[u8; 32],
) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "Mock Leaf Cert").unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(issuer_name).unwrap();
    builder.set_pubkey(ec_public_key).unwrap();

    builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();

    let nonce_der = create_nonce_extension_der(nonce);
    let ext = openssl::x509::X509Extension::new_from_der(
        &openssl::asn1::Asn1Object::from_str("1.2.840.113635.100.8.2").unwrap(),
        false,
        &openssl::asn1::Asn1OctetString::new_from_bytes(&nonce_der).unwrap(),
    )
    .unwrap();
    builder.append_extension(ext).unwrap();

    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();

    builder.build()
}

/// Builds a complete mock attestation that passes all verification steps.
/// Returns the base64-encoded attestation and the root CA PEM bytes.
pub fn build_test_attestation(app_id: &str, request_hash: &str, aaguid: &str) -> TestAttestation {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();
    let public_key: PKey<Public> =
        PKey::public_key_from_der(&private_key.public_key_to_der().unwrap()).unwrap();

    let public_key_der = public_key.public_key_to_der().unwrap();
    let (_, spki) = x509_parser::prelude::SubjectPublicKeyInfo::from_der(&public_key_der).unwrap();
    let raw_public_key = spki.subject_public_key.data.to_vec();

    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    let hashed_app_id = hasher.finish();

    let mut auth_data = Vec::with_capacity(87);
    auth_data.extend_from_slice(&hashed_app_id);
    auth_data.push(0x40);
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    let mut aaguid_bytes = [0u8; 16];
    let aaguid_src = aaguid.as_bytes();
    aaguid_bytes[..aaguid_src.len().min(16)]
        .copy_from_slice(&aaguid_src[..aaguid_src.len().min(16)]);
    auth_data.extend_from_slice(&aaguid_bytes);
    auth_data.extend_from_slice(&[0x00, 0x20]);

    let mut hasher = Sha256::new();
    hasher.update(&raw_public_key);
    let hashed_public_key = hasher.finish();
    auth_data.extend_from_slice(&hashed_public_key);

    let mut hasher = Sha256::new();
    hasher.update(request_hash.as_bytes());
    let client_data_hash = hasher.finish();

    let mut hasher = Sha256::new();
    hasher.update(&auth_data);
    hasher.update(&client_data_hash);
    let nonce = hasher.finish();

    let (root_cert, root_key) = create_fake_root_ca();

    let leaf_cert = create_leaf_cert_with_nonce(
        &root_cert.issuer_name().to_owned().unwrap(),
        &root_key,
        &public_key,
        &nonce,
    );

    let attestation = Attestation {
        fmt: "apple-appattest".to_string(),
        att_stmt: AttestationStatement {
            x5c: vec![
                leaf_cert.to_der().unwrap().into(),
                root_cert.to_der().unwrap().into(),
            ],
            receipt: ByteBuf::from(b"mock_receipt".to_vec()),
        },
        auth_data: ByteBuf::from(auth_data),
    };

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&attestation, &mut cbor_bytes).unwrap();
    let attestation_base64 = general_purpose::STANDARD.encode(&cbor_bytes);

    let key_id = general_purpose::STANDARD.encode(&hashed_public_key);

    let public_key_base64 = general_purpose::STANDARD.encode(&public_key_der);

    TestAttestation {
        attestation_base64,
        root_ca_pem: root_cert.to_pem().unwrap(),
        key_id,
        public_key: public_key_base64,
    }
}
