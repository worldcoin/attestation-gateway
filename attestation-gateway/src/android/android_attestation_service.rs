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
    /// Hardware-bound unique ID (HMAC_SHA256 with device secret). 128-bit, rotates every 30 days.
    /// Empty when the app doesn't request INCLUDE_UNIQUE_ID.
    pub unique_id_hex: Option<String>,
    /// Device identity fields when present (UTF-8 best-effort).
    pub attestation_id_brand: Option<String>,
    pub attestation_id_device: Option<String>,
    pub attestation_id_product: Option<String>,
    pub attestation_id_serial: Option<String>,
    pub attestation_id_imei: Option<String>,
    pub attestation_id_meid: Option<String>,
    pub attestation_id_manufacturer: Option<String>,
    pub attestation_id_model: Option<String>,
    pub attestation_id_second_imei: Option<String>,
    /// Android OS version as encoded integer (e.g. 160000 = Android 16.0.0).
    pub os_version: Option<u64>,
    /// Vendor-specific patch level (YYYYMMDD).
    pub vendor_patch_level: Option<u64>,
    /// Boot image patch level (YYYYMMDD).
    pub boot_patch_level: Option<u64>,
    /// Maximum number of times the key can be used.
    pub usage_count_limit: Option<u64>,
    /// Key algorithm (1=RSA, 3=EC).
    pub algorithm: Option<u64>,
    /// Key size in bits.
    pub key_size: Option<u64>,
    /// EC curve (0=P-224, 1=P-256, 2=P-384, 3=P-521).
    pub ec_curve: Option<u64>,
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
    pub os_patch_level_delta: Option<u32>,
    pub integrity_confidence: IntegrityConfidence,
    /// SHA-256 fingerprint of the intermediate (batch) certificate. Used by
    /// the keybox-defense layer for rate limiting and blocklisting.
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
        tracing::info!(
            cert_chain_len = base64_cert_chain.len(),
            bundle_identifier = %bundle_identifier,
            "android verify: starting verification"
        );

        let cert_chain = AndroidCertChain::from_base64(base64_cert_chain, &self.ca_registry)
            .map_err(AndroidAttestationError::CertChain)?;

        let revoked = cert_chain
            .serials()
            .iter()
            .any(|s| s.is_revoked(&self.revocation_list));
        tracing::info!(
            revoked = revoked,
            serial_count = cert_chain.serials().len(),
            "android verify: revocation check"
        );
        if revoked {
            return Err(AndroidAttestationError::CertificateRevoked);
        }

        let has_valid_root = self
            .ca_registry
            .has_public_key(&cert_chain.root_certificate().public_key);
        let is_rkp = self
            .ca_registry
            .is_rkp_root(&cert_chain.root_certificate().public_key);
        tracing::info!(
            has_valid_root = has_valid_root,
            is_rkp_root = is_rkp,
            "android verify: CA root check"
        );
        if !has_valid_root {
            return Err(AndroidAttestationError::InvalidCaRoot);
        }

        let expected_challenge = format!("n={nonce},av={app_version}");
        let actual_challenge = cert_chain.device_certificate().attestation_challenge();
        tracing::info!(
            expected_challenge = %expected_challenge,
            actual_challenge = %actual_challenge,
            "android verify: challenge comparison"
        );
        if actual_challenge != expected_challenge {
            return Err(AndroidAttestationError::InvalidChallenge);
        }

        let attestation_security_level =
            cert_chain.device_certificate().attestation_security_level();
        let key_mint_security_level = cert_chain.device_certificate().key_mint_security_level();
        tracing::info!(
            attestation_security_level = attestation_security_level,
            key_mint_security_level = key_mint_security_level,
            levels_match = (attestation_security_level == key_mint_security_level),
            "android verify: security levels"
        );

        if !matches!(
            attestation_security_level,
            KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT | KM_SECURITY_LEVEL_STRONG_BOX
        ) {
            return Err(AndroidAttestationError::LowSecurityLevel);
        }

        if key_mint_security_level != attestation_security_level {
            return Err(AndroidAttestationError::InconsistentSecurityLevels);
        }

        let verified_boot_state = cert_chain
            .device_certificate()
            .verified_boot_state()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        let device_locked = cert_chain
            .device_certificate()
            .device_locked()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        tracing::info!(
            verified_boot_state = verified_boot_state,
            device_locked = device_locked,
            "android verify: boot state and device lock"
        );

        if verified_boot_state != KM_VERIFIED_BOOT_VERIFIED {
            return Err(AndroidAttestationError::BootNotVerified);
        }

        if !device_locked {
            return Err(AndroidAttestationError::DeviceNotLocked);
        }

        let key_origin = cert_chain
            .device_certificate()
            .key_origin()
            .ok_or(AndroidAttestationError::MissingKeyOrigin)?;

        tracing::info!(
            key_origin = key_origin,
            expected = KM_ORIGIN_GENERATED,
            "android verify: key origin"
        );

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

        let expected = Base64
            .decode(expected_attestation_signature_digest)
            .map_err(AndroidAttestationError::BadCertificateDigestEncoding)?;

        let digests_hex: Vec<String> = attestation_signature_digests
            .iter()
            .map(|d| Base64.encode(d))
            .collect();
        tracing::info!(
            found_digests = ?digests_hex,
            expected_digest = %expected_attestation_signature_digest,
            "android verify: signature digest comparison"
        );

        let prod_match = attestation_signature_digests.contains(&expected);

        // Optional staging affordance: when
        // `ATTESTATION_GATEWAY_ACCEPT_ALT_SIGNING_CERT=1` is set on the
        // staging gateway, also accept the debug/dev World App signing cert
        // for the staging bundle. Disabled by default; bundles other than
        // `AndroidStageWorldApp` are unaffected.
        let alt_match = if std::env::var("ATTESTATION_GATEWAY_ACCEPT_ALT_SIGNING_CERT")
            .ok()
            .as_deref()
            == Some("1")
        {
            bundle_identifier
                .certificate_sha256_digest_base64_alt()
                .and_then(|alt| Base64.decode(alt).ok())
                .map_or(false, |alt_decoded| {
                    attestation_signature_digests.contains(&alt_decoded)
                })
        } else {
            false
        };

        if prod_match {
            tracing::info!("android verify: production signature digest matched");
        } else if alt_match {
            tracing::info!("android verify: alt/debug signature digest matched");
        } else {
            tracing::warn!(
                found_digests = ?digests_hex,
                expected_digest = %expected_attestation_signature_digest,
                alt_digest = ?bundle_identifier.certificate_sha256_digest_base64_alt(),
                "android verify: no signature digest matched"
            );
            return Err(AndroidAttestationError::InvalidAttestationSignatureDigest);
        }

        let package_names = cert_chain.device_certificate().package_names();
        tracing::info!(
            package_names = ?package_names,
            "android verify: package names in cert"
        );
        if package_names.is_empty() {
            return Err(AndroidAttestationError::MissingPackageName);
        }

        let expected_pkg = bundle_identifier.to_string();
        if !package_names.iter().any(|name| name == &expected_pkg) {
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

        let attestation_version = dev.attestation_version();
        tracing::info!(
            attestation_version = attestation_version,
            os_patch_level = ?dev.os_patch_level(),
            os_patch_level_delta = ?os_patch_level_delta,
            "android verify: attestation version and patch level"
        );

        // --- Integrity confidence signals (informational, never blocking) ---

        let rkp_rooted = is_rkp;

        let device_unique_attestation = dev.device_unique_attestation();

        let has_id_attestation = dev.attestation_id_brand().is_some()
            && dev.attestation_id_manufacturer().is_some()
            && dev.attestation_id_model().is_some();

        let expected_purpose: &[u64] = &[KM_PURPOSE_SIGN];
        let unexpected_purpose = !dev.purpose().is_empty() && dev.purpose() != expected_purpose;

        let verified_boot_key_hex = dev.verified_boot_key().map(hex::encode);
        let verified_boot_hash_hex = dev.verified_boot_hash().map(hex::encode);

        let batch_cert_serial_hex = cert_chain.serials().get(1).map(|s| s.hex.clone());

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

        let unique_id_hex = dev.unique_id().map(hex::encode);

        let attestation_id_brand = to_utf8(dev.attestation_id_brand());
        let attestation_id_device = to_utf8(dev.attestation_id_device());
        let attestation_id_product = to_utf8(dev.attestation_id_product());
        let attestation_id_serial = to_utf8(dev.attestation_id_serial());
        let attestation_id_imei = to_utf8(dev.attestation_id_imei());
        let attestation_id_meid = to_utf8(dev.attestation_id_meid());
        let attestation_id_manufacturer = to_utf8(dev.attestation_id_manufacturer());
        let attestation_id_model = to_utf8(dev.attestation_id_model());
        let attestation_id_second_imei = to_utf8(dev.attestation_id_second_imei());

        tracing::info!(
            rkp_rooted = rkp_rooted,
            device_unique_attestation = device_unique_attestation,
            has_id_attestation = has_id_attestation,
            unexpected_purpose = unexpected_purpose,
            unique_id = ?unique_id_hex,
            purpose = ?dev.purpose(),
            verified_boot_key = ?verified_boot_key_hex,
            verified_boot_hash = ?verified_boot_hash_hex,
            batch_cert_serial = ?batch_cert_serial_hex,
            module_hash = ?module_hash_hex,
            creation_time_delta_ms = ?creation_time_delta_ms,
            attestation_id_brand = ?attestation_id_brand,
            attestation_id_device = ?attestation_id_device,
            attestation_id_product = ?attestation_id_product,
            attestation_id_manufacturer = ?attestation_id_manufacturer,
            attestation_id_model = ?attestation_id_model,
            "android verify: integrity confidence signals"
        );

        // Compute vendor/boot patch level staleness (YYYYMMDD format -> months delta)
        let vendor_patch_level_stale = dev
            .vendor_patch_level()
            .map(|vpl| {
                let now = DateTime::<Utc>::from(SystemTime::now());
                let now_yyyymm = now.year_ce().1 * 100 + now.month();
                let vpl_yyyymm = (vpl / 100) as u32; // YYYYMMDD -> YYYYMM
                now_yyyymm.saturating_sub(vpl_yyyymm) > 18
            })
            .unwrap_or(false);

        let boot_patch_level_stale = dev
            .boot_patch_level()
            .map(|bpl| {
                let now = DateTime::<Utc>::from(SystemTime::now());
                let now_yyyymm = now.year_ce().1 * 100 + now.month();
                let bpl_yyyymm = (bpl / 100) as u32;
                now_yyyymm.saturating_sub(bpl_yyyymm) > 18
            })
            .unwrap_or(false);

        let os_patch_level_stale = os_patch_level_delta.map(|d| d > 12).unwrap_or(false);

        tracing::info!(
            os_version = ?dev.os_version(),
            vendor_patch_level = ?dev.vendor_patch_level(),
            boot_patch_level = ?dev.boot_patch_level(),
            usage_count_limit = ?dev.usage_count_limit(),
            algorithm = ?dev.algorithm(),
            key_size = ?dev.key_size(),
            ec_curve = ?dev.ec_curve(),
            attestation_id_serial = ?attestation_id_serial,
            attestation_id_imei = ?attestation_id_imei,
            attestation_id_meid = ?attestation_id_meid,
            attestation_id_second_imei = ?attestation_id_second_imei,
            os_patch_level_stale = os_patch_level_stale,
            vendor_patch_level_stale = vendor_patch_level_stale,
            boot_patch_level_stale = boot_patch_level_stale,
            "android verify: extended device metadata"
        );

        let integrity_confidence = IntegrityConfidence {
            rkp_rooted,
            device_unique_attestation,
            has_id_attestation,
            unexpected_purpose,
            unique_id_hex,
            verified_boot_key_hex,
            verified_boot_hash_hex,
            batch_cert_serial_hex,
            module_hash_hex,
            creation_time_delta_ms,
            attestation_id_brand,
            attestation_id_device,
            attestation_id_product,
            attestation_id_serial,
            attestation_id_imei,
            attestation_id_meid,
            attestation_id_manufacturer,
            attestation_id_model,
            attestation_id_second_imei,
            os_version: dev.os_version(),
            vendor_patch_level: dev.vendor_patch_level(),
            boot_patch_level: dev.boot_patch_level(),
            usage_count_limit: dev.usage_count_limit(),
            algorithm: dev.algorithm(),
            key_size: dev.key_size(),
            ec_curve: dev.ec_curve(),
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

        tracing::info!("android verify: verification complete, all checks passed");

        let batch_cert_fingerprint = cert_chain.intermediate_cert_der().map(|der| {
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
