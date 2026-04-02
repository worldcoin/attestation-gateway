use crate::{
    android::{
        android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
        android_cert_chain::{AndroidCertChain, AndroidCertChainError},
        android_revocation_list::{AndroidRevocationList, AndroidRevocationListError},
    },
    utils::BundleIdentifier,
};
use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
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
    #[error("ca registry: {0}")]
    CaRegistry(#[source] AndroidCaRegistryError),

    #[error("revocation list: {0}")]
    RevocationList(#[source] AndroidRevocationListError),

    #[error("cert chain: {0}")]
    CertChain(#[source] AndroidCertChainError),

    #[error("invalid ca root")]
    InvalidCaRoot,

    #[error("invalid challenge")]
    InvalidChallenge,

    #[error("low security level")]
    LowSecurityLevel,

    #[error("inconsistent security levels")]
    InconsistentSecurityLevels,

    #[error("device not locked")]
    DeviceNotLocked,

    #[error("boot not verified")]
    BootNotVerified,

    #[error("key not generated in secure hardware")]
    KeyNotGeneratedInSecureHardware,

    #[error("missing root of trust")]
    MissingRootOfTrust,

    #[error("missing key origin")]
    MissingKeyOrigin,

    #[error("missing attestation signature digests")]
    MissingAttestationSignatureDigests,

    #[error("invalid attestation signature digest")]
    InvalidAttestationSignatureDigest,

    #[error("missing package name")]
    MissingPackageName,

    #[error("invalid package name")]
    InvalidPackageName,

    #[error("certificate revoked")]
    CertificateRevoked,

    #[error("missing certificate digest")]
    MissingCertificateDigest,

    #[error("bad certificate digest encoding: {0}")]
    BadCertificateDigestEncoding(#[source] DecodeError),
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
    pub os_patch_level: Option<u64>,
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
            .ok_or(AndroidAttestationError::MissingCertificateDigest)?;

        let expected_attestation_signature_digest = Base64
            .decode(expected_attestation_signature_digest)
            .map_err(AndroidAttestationError::BadCertificateDigestEncoding)?;

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
            os_patch_level: cert_chain.device_certificate().os_patch_level(),
        })
    }
}

impl AndroidAttestationError {
    pub fn reason_tag(&self) -> String {
        match self {
            AndroidAttestationError::CaRegistry(e) => {
                format!("ca_registry_{}", e.reason_tag())
            }
            AndroidAttestationError::RevocationList(e) => {
                format!("revocation_list_{}", e.reason_tag())
            }
            AndroidAttestationError::CertChain(e) => {
                format!("cert_chain_{}", e.reason_tag())
            }
            AndroidAttestationError::InvalidCaRoot => "invalid_ca_root".to_string(),
            AndroidAttestationError::InvalidChallenge => "invalid_challenge".to_string(),
            AndroidAttestationError::LowSecurityLevel => "low_security_level".to_string(),
            AndroidAttestationError::InconsistentSecurityLevels => {
                "inconsistent_security_levels".to_string()
            }
            AndroidAttestationError::DeviceNotLocked => "device_not_locked".to_string(),
            AndroidAttestationError::BootNotVerified => "boot_not_verified".to_string(),
            AndroidAttestationError::KeyNotGeneratedInSecureHardware => {
                "key_not_generated_in_secure_hardware".to_string()
            }
            AndroidAttestationError::MissingRootOfTrust => "missing_root_of_trust".to_string(),
            AndroidAttestationError::MissingKeyOrigin => "missing_key_origin".to_string(),
            AndroidAttestationError::MissingAttestationSignatureDigests => {
                "missing_attestation_signature_digests".to_string()
            }
            AndroidAttestationError::InvalidAttestationSignatureDigest => {
                "invalid_attestation_signature_digest".to_string()
            }
            AndroidAttestationError::MissingPackageName => "missing_package_name".to_string(),
            AndroidAttestationError::InvalidPackageName => "invalid_package_name".to_string(),
            AndroidAttestationError::CertificateRevoked => "certificate_revoked".to_string(),
            AndroidAttestationError::MissingCertificateDigest => {
                "missing_certificate_digest".to_string()
            }
            AndroidAttestationError::BadCertificateDigestEncoding(_) => {
                "bad_certificate_digest_encoding".to_string()
            }
        }
    }

    pub fn is_internal_error(&self) -> bool {
        match self {
            AndroidAttestationError::CaRegistry(e) => e.is_internal_error(),
            AndroidAttestationError::RevocationList(e) => e.is_internal_error(),
            AndroidAttestationError::CertChain(e) => e.is_internal_error(),
            AndroidAttestationError::InvalidCaRoot => false,
            AndroidAttestationError::InvalidChallenge => false,
            AndroidAttestationError::LowSecurityLevel => false,
            AndroidAttestationError::InconsistentSecurityLevels => false,
            AndroidAttestationError::DeviceNotLocked => false,
            AndroidAttestationError::BootNotVerified => false,
            AndroidAttestationError::KeyNotGeneratedInSecureHardware => false,
            AndroidAttestationError::MissingRootOfTrust => false,
            AndroidAttestationError::MissingKeyOrigin => false,
            AndroidAttestationError::MissingAttestationSignatureDigests => false,
            AndroidAttestationError::InvalidAttestationSignatureDigest => false,
            AndroidAttestationError::MissingPackageName => false,
            AndroidAttestationError::InvalidPackageName => false,
            AndroidAttestationError::CertificateRevoked => false,
            AndroidAttestationError::MissingCertificateDigest => true,
            AndroidAttestationError::BadCertificateDigestEncoding(_) => true,
        }
    }
}
