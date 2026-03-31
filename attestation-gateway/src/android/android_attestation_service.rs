use std::time::{Duration, SystemTime};

use crate::{
    android::{
        android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
        android_cert_chain::{AndroidCertChain, AndroidCertChainError},
        android_revocation_list::{AndroidRevocationList, AndroidRevocationListError},
    },
    utils::BundleIdentifier,
};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, Datelike, Utc};
use thiserror::Error;

/// Android `KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT` — KeyMint / Keymaster in the TEE.
const KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: u32 = 1;

/// Android `KM_SECURITY_LEVEL_STRONG_BOX` — KeyMint / Keymaster in StrongBox.
const KM_SECURITY_LEVEL_STRONG_BOX: u32 = 2;

/// Android `KM_VERIFIED_BOOT_VERIFIED` — verified boot succeeded (boot hash matches expected).
const KM_VERIFIED_BOOT_VERIFIED: u32 = 0;

/// Android `KM_ORIGIN_GENERATED` — key generated inside secure KeyMint / Keymaster (TEE / StrongBox), not imported.
const KM_ORIGIN_GENERATED: u64 = 0;

#[derive(Debug, Error)]
pub enum AndroidAttestationError {
    #[error(transparent)]
    CaRegistry(#[from] AndroidCaRegistryError),
    #[error(transparent)]
    RevocationList(#[from] AndroidRevocationListError),
    #[error(transparent)]
    CertChain(#[from] AndroidCertChainError),
    #[error("device certificate is not signed by a trusted Android attestation root CA")]
    InvalidCaRoot,
    #[error("attestation challenge does not match expected nonce and app version")]
    InvalidChallenge,
    #[error("attestation or KeyMint security level is not TEE or StrongBox")]
    LowSecurityLevel,
    #[error("attestation and KeyMint security levels differ")]
    InconsistentSecurityLevels,
    #[error("device must be locked")]
    DeviceNotLocked,
    #[error("verified boot state is not verified")]
    BootNotVerified,
    #[error("key was not generated in secure hardware")]
    KeyNotGeneratedInSecureHardware,
    #[error("missing root of trust in attestation extension")]
    MissingRootOfTrust,
    #[error("missing key origin in attestation extension")]
    MissingKeyOrigin,
    #[error("missing OS patch level in attestation extension")]
    MissingOsPatchLevel,
    #[error("missing attestation signature digests in attestation extension")]
    MissingAttestationSignatureDigests,
    #[error("attestation signature digest does not match app certificate")]
    InvalidAttestationSignatureDigest,
    #[error("bundle identifier has no SHA-256 certificate digest configured")]
    InternalMissingCertificateDigest,
    #[error("OS patch level is too old")]
    InvalidOsPatchLevel,
    #[error("missing package name in attestation extension")]
    MissingPackageName,
    #[error("attestation package name does not match bundle identifier")]
    InvalidPackageName,
    #[error("certificate serial is on the revocation list")]
    CertificateRevoked,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct AndroidAttestationService {
    ca_registry: AndroidCaRegistry,
    revocation_list: AndroidRevocationList,
}

impl AndroidAttestationService {
    pub fn new(ca_registry: AndroidCaRegistry, revocation_list: AndroidRevocationList) -> Self {
        Self {
            ca_registry,
            revocation_list,
        }
    }

    /// Loads bundled Android attestation root CAs and fetches the default Google revocation feed.
    pub async fn from_defaults() -> Result<Self, AndroidAttestationError> {
        let ca_registry =
            AndroidCaRegistry::from_default_pem().map_err(AndroidAttestationError::CaRegistry)?;
        let revocation_list = AndroidRevocationList::connect_google_default()
            .await
            .map_err(AndroidAttestationError::RevocationList)?;
        Ok(Self::new(ca_registry, revocation_list))
    }

    /// Background refresh for the revocation list; see [`AndroidRevocationList::spawn_refresh_loop`].
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        self.revocation_list.spawn_refresh_loop()
    }

    pub fn verify(
        &self,
        base64_cert_chain: Vec<String>,
        nonce: &String,
        app_version: &String,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain)
            .map_err(|e| AndroidAttestationError::CertChain(e))?;

        if cert_chain
            .serials()
            .iter()
            .any(|s| s.is_revoked(&self.revocation_list))
        {
            return Err(AndroidAttestationError::CertificateRevoked);
        }

        if !self
            .ca_registry
            .has_public_key(&cert_chain.root_certificate().public_key)
        {
            return Err(AndroidAttestationError::InvalidCaRoot);
        }

        if cert_chain.device_certificate().attestation_challenge()
            != format!("n={},av={}", nonce, app_version)
        {
            return Err(AndroidAttestationError::InvalidChallenge);
        }

        if !matches!(
            cert_chain.device_certificate().attestation_security_level(),
            KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT | KM_SECURITY_LEVEL_STRONG_BOX
        ) {
            return Err(AndroidAttestationError::LowSecurityLevel);
        }

        if cert_chain.device_certificate().key_mint_security_level()
            != cert_chain.device_certificate().attestation_security_level()
        {
            return Err(AndroidAttestationError::InconsistentSecurityLevels);
        }

        let verified_boot_state = cert_chain
            .device_certificate()
            .verified_boot_state()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if verified_boot_state != KM_VERIFIED_BOOT_VERIFIED {
            return Err(AndroidAttestationError::BootNotVerified);
        }

        let device_locked = cert_chain
            .device_certificate()
            .device_locked()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if !device_locked {
            return Err(AndroidAttestationError::DeviceNotLocked);
        }

        let os_patch_level = cert_chain
            .device_certificate()
            .os_patch_level()
            .ok_or(AndroidAttestationError::MissingOsPatchLevel)?;

        let year_ago = DateTime::<Utc>::from(SystemTime::now() - Duration::from_hours(24 * 365));
        let min_os_patch_level = year_ago.year() as u64 * 100 + year_ago.month() as u64;

        if os_patch_level < min_os_patch_level {
            return Err(AndroidAttestationError::InvalidOsPatchLevel);
        }

        let key_origin = cert_chain
            .device_certificate()
            .key_origin()
            .ok_or(AndroidAttestationError::MissingKeyOrigin)?;

        if key_origin != KM_ORIGIN_GENERATED {
            return Err(AndroidAttestationError::KeyNotGeneratedInSecureHardware);
        }

        let attestation_signature_digests = cert_chain
            .device_certificate()
            .attestation_signature_digests()
            .ok_or(AndroidAttestationError::MissingAttestationSignatureDigests)?;

        let expected_attestation_signature_digest = bundle_identifier
            .certificate_sha256_digest_base64()
            .and_then(|d| Base64.decode(d).ok())
            .ok_or(AndroidAttestationError::InternalMissingCertificateDigest)?;

        if !attestation_signature_digests.contains(&expected_attestation_signature_digest) {
            return Err(AndroidAttestationError::InvalidAttestationSignatureDigest);
        }

        let attestation_package_name = cert_chain
            .device_certificate()
            .package_name()
            .ok_or(AndroidAttestationError::MissingPackageName)?;

        if attestation_package_name != bundle_identifier.to_string() {
            return Err(AndroidAttestationError::InvalidPackageName);
        }

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.device_certificate().public_key(),
        })
    }
}
