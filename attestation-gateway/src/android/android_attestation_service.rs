use std::time::SystemTime;

use crate::{
    android::{
        android_ca_registry::{AndroidCaRegistry, AndroidCaRegistryError},
        android_cert_chain::{AndroidCertChain, AndroidCertChainError},
        android_revocation_list::{AndroidRevocationList, AndroidRevocationListError},
    },
    utils::BundleIdentifier,
};
use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, Datelike, Utc};
use thiserror::Error;

/// Android `KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT` — `KeyMint` / Keymaster in the TEE.
const KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: u32 = 1;

/// Android `KM_SECURITY_LEVEL_STRONG_BOX` — `KeyMint` / Keymaster in `StrongBox`.
const KM_SECURITY_LEVEL_STRONG_BOX: u32 = 2;

/// Android `KM_VERIFIED_BOOT_VERIFIED` — verified boot succeeded (boot hash matches expected).
const KM_VERIFIED_BOOT_VERIFIED: u32 = 0;

/// Android `KM_ORIGIN_GENERATED` — key generated inside secure `KeyMint` / Keymaster (TEE / `StrongBox`), not imported.
const KM_ORIGIN_GENERATED: u64 = 0;

/// Android `KM_PURPOSE_SIGN` — key purpose: signing.
const KM_PURPOSE_SIGN: u64 = 2;

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

/// Signals extracted from the attestation chain that indicate how confident we
/// are that the chain was produced by genuine, uncompromised hardware.
/// None of these cause a hard rejection -- they are purely informational and
/// emitted as metrics + structured logs so the caller can decide policy.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityConfidence {
    /// Chain roots in a 2026 RKP-provisioned certificate (keybox bypass impossible).
    pub rkp_rooted: bool,
    /// StrongBox device-unique attestation key (tag 720); per-device, no batch key.
    pub device_unique_attestation: bool,
    /// True when at least brand + manufacturer + model are present in teeEnforced.
    pub has_id_attestation: bool,
    /// Set when purpose contains unexpected values (e.g. VERIFY in addition to SIGN).
    pub unexpected_purpose: bool,
    /// Hex-encoded verifiedBootKey from rootOfTrust (for allowlist checks / logging).
    pub verified_boot_key_hex: Option<String>,
    /// Hex-encoded verifiedBootHash.
    pub verified_boot_hash_hex: Option<String>,
    /// Batch (intermediate) certificate serial hex -- for cross-request anomaly tracking.
    pub batch_cert_serial_hex: Option<String>,
    /// Module hash hex (KeyMint v4+ / attestation v400+).
    pub module_hash_hex: Option<String>,
    /// creationDateTime delta in milliseconds (server_now - creation_date_time). Large
    /// negative values or exact-zero deltas may indicate a forged timestamp.
    pub creation_time_delta_ms: Option<i64>,
    /// Device identity fields when present (UTF-8 best-effort).
    pub attestation_id_brand: Option<String>,
    pub attestation_id_manufacturer: Option<String>,
    pub attestation_id_model: Option<String>,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
    pub os_patch_level_delta: Option<u32>,
    pub integrity_confidence: IntegrityConfidence,
    /// SHA-256 fingerprint of the intermediate (batch) cert DER for rate limiting.
    pub batch_cert_fingerprint: Option<String>,
}

#[derive(Clone)]
pub struct AndroidAttestationService {
    ca_registry: AndroidCaRegistry,
    revocation_list: AndroidRevocationList,
}

impl AndroidAttestationService {
    #[must_use]
    pub const fn new(
        ca_registry: AndroidCaRegistry,
        revocation_list: AndroidRevocationList,
    ) -> Self {
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
    #[must_use]
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        self.revocation_list.spawn_refresh_loop()
    }

    pub fn verify(
        &self,
        base64_cert_chain: &[String],
        nonce: &String,
        app_version: &String,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain, &self.ca_registry)
            .map_err(AndroidAttestationError::CertChain)?;

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
            != format!("n={nonce},av={app_version}")
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

        let package_names = cert_chain.device_certificate().package_names();
        if package_names.is_empty() {
            return Err(AndroidAttestationError::MissingPackageName);
        }

        let expected = bundle_identifier.to_string();
        if !package_names.iter().any(|name| name == &expected) {
            return Err(AndroidAttestationError::InvalidPackageName);
        }

        let os_patch_level_delta =
            cert_chain
                .device_certificate()
                .os_patch_level()
                .map(|os_patch_level| {
                    let now = DateTime::<Utc>::from(SystemTime::now());
                    let now = now.year_ce().1 * 100 + now.month();
                    now - os_patch_level
                });

        let dev = cert_chain.device_certificate();

        // --- Integrity confidence signals (informational, never blocking) ---

        let rkp_rooted = self
            .ca_registry
            .is_rkp_root(&cert_chain.root_certificate().public_key);

        let device_unique_attestation = dev.device_unique_attestation();

        let has_id_attestation = dev.attestation_id_brand().is_some()
            && dev.attestation_id_manufacturer().is_some()
            && dev.attestation_id_model().is_some();

        let expected_purpose: &[u64] = &[KM_PURPOSE_SIGN];
        let unexpected_purpose = !dev.purpose().is_empty() && dev.purpose() != expected_purpose;

        let verified_boot_key_hex = dev.verified_boot_key().map(hex::encode);
        let verified_boot_hash_hex = dev.verified_boot_hash().map(hex::encode);

        let batch_cert_serial_hex = cert_chain
            .serials()
            .get(1)
            .map(|s| s.hex.clone());

        let module_hash_hex = dev.module_hash().map(hex::encode);

        let creation_time_delta_ms = dev.creation_date_time().map(|ct| {
            let now_ms = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            now_ms - ct as i64
        });

        let to_utf8 = |b: Option<&[u8]>| -> Option<String> {
            b.and_then(|v| std::str::from_utf8(v).ok().map(String::from))
        };

        let integrity_confidence = IntegrityConfidence {
            rkp_rooted,
            device_unique_attestation,
            has_id_attestation,
            unexpected_purpose,
            verified_boot_key_hex,
            verified_boot_hash_hex,
            batch_cert_serial_hex,
            module_hash_hex,
            creation_time_delta_ms,
            attestation_id_brand: to_utf8(dev.attestation_id_brand()),
            attestation_id_manufacturer: to_utf8(dev.attestation_id_manufacturer()),
            attestation_id_model: to_utf8(dev.attestation_id_model()),
        };

        // Emit structured metrics for every signal so dashboards can track distribution.
        metrics::counter!(
            "attestation_gateway.confidence",
            "rkp_rooted" => rkp_rooted.to_string(),
            "device_unique" => device_unique_attestation.to_string(),
            "has_id_attestation" => has_id_attestation.to_string(),
            "unexpected_purpose" => unexpected_purpose.to_string(),
        )
        .increment(1);

        if let Some(ref key_hex) = integrity_confidence.verified_boot_key_hex {
            tracing::info!(
                verified_boot_key = %key_hex,
                rkp_rooted = rkp_rooted,
                has_id_attestation = has_id_attestation,
                device_unique = device_unique_attestation,
                batch_serial = ?integrity_confidence.batch_cert_serial_hex,
                "android attestation confidence signals"
            );
        }

        let batch_cert_fingerprint = cert_chain
            .intermediate_cert_der()
            .map(|der| {
                use super::keybox_defense::KeyboxDefense;
                KeyboxDefense::fingerprint(der)
            });

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.device_certificate().public_key(),
            os_patch_level_delta,
            integrity_confidence,
            batch_cert_fingerprint,
        })
    }
}

impl AndroidAttestationError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::CaRegistry(e) => {
                format!("ca_registry_{}", e.reason_tag())
            }
            Self::RevocationList(e) => {
                format!("revocation_list_{}", e.reason_tag())
            }
            Self::CertChain(e) => {
                format!("cert_chain_{}", e.reason_tag())
            }
            Self::InvalidCaRoot => "invalid_ca_root".to_string(),
            Self::InvalidChallenge => "invalid_challenge".to_string(),
            Self::LowSecurityLevel => "low_security_level".to_string(),
            Self::InconsistentSecurityLevels => "inconsistent_security_levels".to_string(),
            Self::DeviceNotLocked => "device_not_locked".to_string(),
            Self::BootNotVerified => "boot_not_verified".to_string(),
            Self::KeyNotGeneratedInSecureHardware => {
                "key_not_generated_in_secure_hardware".to_string()
            }
            Self::MissingRootOfTrust => "missing_root_of_trust".to_string(),
            Self::MissingKeyOrigin => "missing_key_origin".to_string(),
            Self::MissingAttestationSignatureDigests => {
                "missing_attestation_signature_digests".to_string()
            }
            Self::InvalidAttestationSignatureDigest => {
                "invalid_attestation_signature_digest".to_string()
            }
            Self::MissingPackageName => "missing_package_name".to_string(),
            Self::InvalidPackageName => "invalid_package_name".to_string(),
            Self::CertificateRevoked => "certificate_revoked".to_string(),
            Self::MissingCertificateDigest => "missing_certificate_digest".to_string(),
            Self::BadCertificateDigestEncoding(_) => "bad_certificate_digest_encoding".to_string(),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::CaRegistry(e) => e.is_internal_error(),
            Self::RevocationList(e) => e.is_internal_error(),
            Self::CertChain(e) => e.is_internal_error(),
            Self::InvalidCaRoot
            | Self::InvalidChallenge
            | Self::LowSecurityLevel
            | Self::InconsistentSecurityLevels
            | Self::DeviceNotLocked
            | Self::BootNotVerified
            | Self::KeyNotGeneratedInSecureHardware
            | Self::MissingRootOfTrust
            | Self::MissingKeyOrigin
            | Self::MissingAttestationSignatureDigests
            | Self::InvalidAttestationSignatureDigest
            | Self::MissingPackageName
            | Self::InvalidPackageName
            | Self::CertificateRevoked => false,
            Self::MissingCertificateDigest | Self::BadCertificateDigestEncoding(_) => true,
        }
    }
}
