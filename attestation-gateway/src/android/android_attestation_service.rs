use std::time::{Duration, SystemTime};

use crate::{
    android::{
        android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
        android_cert_chain::{AndroidCertChain, AndroidCertChainError},
    },
    utils::BundleIdentifier,
};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, Datelike, Utc};

/// Android `KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT` — KeyMint / Keymaster in the TEE.
const KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: u32 = 1;

/// Android `KM_SECURITY_LEVEL_STRONG_BOX` — KeyMint / Keymaster in StrongBox.
const KM_SECURITY_LEVEL_STRONG_BOX: u32 = 2;

/// Android `KM_VERIFIED_BOOT_VERIFIED` — verified boot succeeded (boot hash matches expected).
const KM_VERIFIED_BOOT_VERIFIED: u32 = 0;

/// Android `KM_ORIGIN_GENERATED` — key generated inside secure KeyMint / Keymaster (TEE / StrongBox), not imported.
const KM_ORIGIN_GENERATED: u64 = 0;

#[derive(Debug)]

pub enum AndroidAttestationError {
    CaRegistry(AndroidCaRegistryError),
    CertChain(AndroidCertChainError),
    InvalidCaRoot,
    InvalidChallenge,
    LowSecurityLevel,
    InconsistentSecurityLevels,
    DeviceNotLocked,
    BootNotVerified,
    KeyNotGeneratedInSecureHardware,
    MissingRootOfTrust,
    MissingKeyOrigin,
    MissingOsPatchLevel,
    MissingAttestationSignatureDigests,
    InvalidAttestationSignatureDigest,
    InternalMissingCertificateDigest,
    InvalidOsPatchLevel,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct AndroidAttestationService {
    ca_registry: AndroidCaRegistry,
}

impl AndroidAttestationService {
    pub fn new(ca_registry: AndroidCaRegistry) -> Self {
        Self { ca_registry }
    }

    pub fn from_default_pem() -> Result<Self, AndroidAttestationError> {
        let ca_registry = AndroidCaRegistry::from_default_pem()
            .map_err(|e| AndroidAttestationError::CaRegistry(e))?;

        Ok(Self::new(ca_registry))
    }

    pub fn verify(
        self,
        base64_cert_chain: Vec<String>,
        nonce: &String,
        app_version: &String,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain)
            .map_err(|e| AndroidAttestationError::CertChain(e))?;

        if !self
            .ca_registry
            .has_public_key(cert_chain.root_ca_public_key())
        {
            return Err(AndroidAttestationError::InvalidCaRoot);
        }

        if cert_chain.attestation_challenge() != format!("n={},av={}", nonce, app_version) {
            return Err(AndroidAttestationError::InvalidChallenge);
        }

        if !matches!(
            cert_chain.device_attestation_security_level(),
            KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT | KM_SECURITY_LEVEL_STRONG_BOX
        ) {
            return Err(AndroidAttestationError::LowSecurityLevel);
        }

        if cert_chain.device_key_mint_security_level()
            != cert_chain.device_attestation_security_level()
        {
            return Err(AndroidAttestationError::InconsistentSecurityLevels);
        }

        let verified_boot_state = cert_chain
            .device_verified_boot_state()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if verified_boot_state != KM_VERIFIED_BOOT_VERIFIED {
            return Err(AndroidAttestationError::BootNotVerified);
        }

        let device_locked = cert_chain
            .device_locked()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if !device_locked {
            return Err(AndroidAttestationError::DeviceNotLocked);
        }

        let os_patch_level = cert_chain
            .device_os_patch_level()
            .ok_or(AndroidAttestationError::MissingOsPatchLevel)?;

        let year_ago = DateTime::<Utc>::from(SystemTime::now() - Duration::from_hours(24 * 365));
        let min_os_patch_level = year_ago.year() as u64 * 100 + year_ago.month() as u64;

        if os_patch_level < min_os_patch_level {
            return Err(AndroidAttestationError::InvalidOsPatchLevel);
        }

        let key_origin = cert_chain
            .device_key_origin()
            .ok_or(AndroidAttestationError::MissingKeyOrigin)?;

        if key_origin != KM_ORIGIN_GENERATED {
            return Err(AndroidAttestationError::KeyNotGeneratedInSecureHardware);
        }

        let attestation_signature_digests = cert_chain
            .device_attestation_signature_digests()
            .ok_or(AndroidAttestationError::MissingAttestationSignatureDigests)?;

        let expected_attestation_signature_digest = bundle_identifier
            .certificate_sha256_digest_base64()
            .and_then(|d| Base64.decode(d).ok())
            .ok_or(AndroidAttestationError::InternalMissingCertificateDigest)?;

        if !attestation_signature_digests.contains(&expected_attestation_signature_digest) {
            return Err(AndroidAttestationError::InvalidAttestationSignatureDigest);
        }

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.device_public_key(),
        })
    }
}
