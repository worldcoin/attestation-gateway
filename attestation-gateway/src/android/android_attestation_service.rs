use std::time::SystemTime;

use crate::{
    android::{
        analytics_service::{AnalyticsService, AnalyticsServiceNewError},
        cert_chain_builder::{
            CertChainBuilder, CertChainBuilderBuildChainError, CertChainBuilderNewError,
        },
        key_description::{SecurityLevel, VerifiedBootState},
        rate_limit_service::{RateLimitService, RateLimitServiceTryIncrError},
        revocation_list::{RevocationList, RevocationListError},
    },
    utils::BundleIdentifier,
};
use base64::{DecodeError, Engine, engine::general_purpose::STANDARD as Base64};
use chrono::{DateTime, Datelike, Utc};
use redis::aio::ConnectionManager;
use thiserror::Error;

/// Android `KM_ORIGIN_GENERATED` — key generated inside secure `KeyMint` / Keymaster (TEE / `StrongBox`), not imported.
const KM_ORIGIN_GENERATED: u64 = 0;

#[derive(Debug, Error)]
pub enum AndroidAttestationError {
    #[error("rate limit service try incr error: {0}")]
    InternalRateLimitServiceTryIncr(#[source] RateLimitServiceTryIncrError),

    #[error("cert chain builder new error: {0}")]
    CertChainBuilderNew(#[source] CertChainBuilderNewError),

    #[error("analytics service new error: {0}")]
    AnalyticsServiceNew(#[source] AnalyticsServiceNewError),

    #[error("revocation list: {0}")]
    RevocationList(#[source] RevocationListError),

    #[error("rate limit exceeded")]
    RateLimitExceeded,

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

    #[error("invalid attestation signature digest")]
    InvalidAttestationSignatureDigest,

    #[error("invalid package name")]
    InvalidPackageName,

    #[error("certificate revoked")]
    CertificateRevoked,

    #[error("missing certificate digest")]
    MissingCertificateDigest,

    #[error("bad certificate digest encoding: {0}")]
    BadCertificateDigestEncoding(#[source] DecodeError),

    #[error("build chain error: {0}")]
    CertChainBuilderBuildChain(#[source] CertChainBuilderBuildChainError),
}

pub struct AndroidAttestationOutput {
    pub device_public_key: Vec<u8>,
    pub os_patch_level_delta: Option<u32>,
}

#[derive(Clone)]
pub struct AndroidAttestationService {
    cert_chain_builder: CertChainBuilder,
    revocation_list: RevocationList,
    rate_limit_service: RateLimitService,
    analytics_service: AnalyticsService,
}

impl AndroidAttestationService {
    #[must_use]
    pub fn new(
        cert_chain_builder: CertChainBuilder,
        revocation_list: RevocationList,
        rate_limit_service: RateLimitService,
        analytics_service: AnalyticsService,
    ) -> Self {
        Self {
            cert_chain_builder,
            revocation_list,
            rate_limit_service,
            analytics_service,
        }
    }

    /// Loads bundled Android attestation root CAs and fetches the default Google revocation feed.
    pub async fn from_defaults(
        redis: ConnectionManager,
        limit_per_day: Option<isize>,
        analytics_kinesis_stream_arn: String,
    ) -> Result<Self, AndroidAttestationError> {
        let cert_chain_builder = CertChainBuilder::new_from_default_pem()
            .map_err(AndroidAttestationError::CertChainBuilderNew)?;

        let revocation_list = RevocationList::connect_google_default()
            .await
            .map_err(AndroidAttestationError::RevocationList)?;

        let rate_limit_service = RateLimitService::new(redis, limit_per_day);
        let analytics_service = AnalyticsService::new(analytics_kinesis_stream_arn)
            .await
            .map_err(AndroidAttestationError::AnalyticsServiceNew)?;

        Ok(Self::new(
            cert_chain_builder,
            revocation_list,
            rate_limit_service,
            analytics_service,
        ))
    }

    /// Background refresh for the revocation list; see [`AndroidRevocationList::spawn_refresh_loop`].
    #[must_use]
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        self.revocation_list.spawn_refresh_loop()
    }

    pub async fn verify(
        &mut self,
        base64_cert_chain: &[String],
        aud: &str,
        nonce: &String,
        app_version: &String,
        bundle_identifier: &BundleIdentifier,
    ) -> Result<AndroidAttestationOutput, AndroidAttestationError> {
        let cert_chain = self
            .cert_chain_builder
            .build_chain_from_base64(base64_cert_chain)
            .map_err(AndroidAttestationError::CertChainBuilderBuildChain)?;

        let rate_limit_passed = self
            .rate_limit_service
            .try_incr(aud, &cert_chain)
            .await
            .map_err(AndroidAttestationError::InternalRateLimitServiceTryIncr)?;

        if !rate_limit_passed {
            return Err(AndroidAttestationError::RateLimitExceeded);
        }

        if cert_chain.any_serial_revoked(&self.revocation_list) {
            return Err(AndroidAttestationError::CertificateRevoked);
        }

        if cert_chain.session_cert().attestation_challenge()
            != format!("n={nonce},av={app_version}")
        {
            return Err(AndroidAttestationError::InvalidChallenge);
        }

        if !matches!(
            cert_chain.session_cert().attestation_security_level(),
            SecurityLevel::TrustedEnvironment | SecurityLevel::StrongBox
        ) {
            return Err(AndroidAttestationError::LowSecurityLevel);
        }

        if cert_chain.session_cert().key_mint_security_level()
            != cert_chain.session_cert().attestation_security_level()
        {
            return Err(AndroidAttestationError::InconsistentSecurityLevels);
        }

        let verified_boot_state = cert_chain
            .session_cert()
            .verified_boot_state()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if verified_boot_state != VerifiedBootState::Verified {
            return Err(AndroidAttestationError::BootNotVerified);
        }

        let device_locked = cert_chain
            .session_cert()
            .device_locked()
            .ok_or(AndroidAttestationError::MissingRootOfTrust)?;

        if !device_locked {
            return Err(AndroidAttestationError::DeviceNotLocked);
        }

        let key_origin = cert_chain
            .session_cert()
            .key_origin()
            .ok_or(AndroidAttestationError::MissingKeyOrigin)?;

        if key_origin != KM_ORIGIN_GENERATED {
            return Err(AndroidAttestationError::KeyNotGeneratedInSecureHardware);
        }

        let expected_attestation_signature_digest = bundle_identifier
            .certificate_sha256_digest_base64()
            .ok_or(AndroidAttestationError::MissingCertificateDigest)?;

        let expected_attestation_signature_digest = Base64
            .decode(expected_attestation_signature_digest)
            .map_err(AndroidAttestationError::BadCertificateDigestEncoding)?;

        if !cert_chain
            .session_cert()
            .contains_attestation_signature_digests(&expected_attestation_signature_digest)
        {
            return Err(AndroidAttestationError::InvalidAttestationSignatureDigest);
        }

        if !cert_chain
            .session_cert()
            .contains_package_name(&bundle_identifier.to_string())
        {
            return Err(AndroidAttestationError::InvalidPackageName);
        }

        let os_patch_level_delta =
            cert_chain
                .session_cert()
                .os_patch_level()
                .map(|os_patch_level| {
                    let now = DateTime::<Utc>::from(SystemTime::now());
                    let now = now.year_ce().1 * 100 + now.month();
                    now - os_patch_level
                });

        Ok(AndroidAttestationOutput {
            device_public_key: cert_chain.session_cert().public_key(),
            os_patch_level_delta,
        })
    }
}

impl AndroidAttestationError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::InternalRateLimitServiceTryIncr(e) => {
                format!("rate_limit_service_try_incr_{}", e.reason_tag())
            }
            Self::CertChainBuilderNew(_) => "cert_chain_builder_new".to_string(),
            Self::AnalyticsServiceNew(e) => {
                format!("analytics_service_new_{}", e.reason_tag())
            }
            Self::RevocationList(e) => {
                format!("revocation_list_{}", e.reason_tag())
            }
            Self::RateLimitExceeded => "rate_limit_exceeded".to_string(),
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
            Self::InvalidAttestationSignatureDigest => {
                "invalid_attestation_signature_digest".to_string()
            }
            Self::InvalidPackageName => "invalid_package_name".to_string(),
            Self::CertificateRevoked => "certificate_revoked".to_string(),
            Self::MissingCertificateDigest => "missing_certificate_digest".to_string(),
            Self::BadCertificateDigestEncoding(_) => "bad_certificate_digest_encoding".to_string(),
            Self::CertChainBuilderBuildChain(e) => {
                format!("cert_chain_builder_build_chain_{}", e.reason_tag())
            }
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::InternalRateLimitServiceTryIncr(_)
            | Self::CertChainBuilderNew(_)
            | Self::AnalyticsServiceNew(_) => true,
            Self::RevocationList(e) => e.is_internal_error(),
            Self::CertChainBuilderBuildChain(e) => e.is_internal_error(),
            Self::RateLimitExceeded
            | Self::InvalidChallenge
            | Self::LowSecurityLevel
            | Self::InconsistentSecurityLevels
            | Self::DeviceNotLocked
            | Self::BootNotVerified
            | Self::KeyNotGeneratedInSecureHardware
            | Self::MissingRootOfTrust
            | Self::MissingKeyOrigin
            | Self::InvalidAttestationSignatureDigest
            | Self::InvalidPackageName
            | Self::CertificateRevoked => false,
            Self::MissingCertificateDigest | Self::BadCertificateDigestEncoding(_) => true,
        }
    }
}
