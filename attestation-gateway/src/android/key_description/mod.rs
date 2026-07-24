use std::string::FromUtf8Error;

use serde::Serialize;
use thiserror::Error;

use crate::android::key_description::key_description_asn1::{
    AttestationApplicationIdAsn1, AttestationPackageInfoAsn1, AuthorizationListAsn1,
    KeyDescriptionAsn1, RootOfTrustAsn1,
};

mod key_description_asn1;
mod unordered_set_of_u64;

#[derive(Debug, Error)]
pub enum KeyDescriptionError {
    #[error("asn1 parse error: {0}")]
    Asn1(#[source] Box<asn1::ParseError>),

    #[error("utf8 parse error: {0}")]
    ParseUtf8(#[source] FromUtf8Error),

    #[error("unknown security level: {0}")]
    UnknownSecurityLevel(u32),

    #[error("unknown verified boot state: {0}")]
    UnknownVerifiedBootState(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyDescription {
    pub attestation_version: u64,
    pub attestation_security_level: SecurityLevel,
    pub key_security_version: u64,
    pub key_security_level: SecurityLevel,
    pub attestation_challenge: String,
    #[serde(with = "crate::android::serde_hex")]
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationList {
    pub purpose: Option<Vec<u64>>,
    pub algorithm: Option<u64>,
    pub key_size: Option<u64>,
    pub block_mode: Option<Vec<u64>>,
    pub digest: Option<Vec<u64>>,
    pub padding: Option<Vec<u64>>,
    pub caller_nonce: bool,
    pub min_mac_length: Option<u64>,
    pub ec_curve: Option<u64>,

    pub rsa_public_exponent: Option<u64>,
    pub mgf_digest: Option<Vec<u64>>,

    pub rollback_resistance: bool,
    pub early_boot_only: bool,

    pub active_date_time: Option<u64>,
    pub origination_expire_date_time: Option<u64>,
    pub usage_expire_date_time: Option<u64>,
    pub usage_count_limit: Option<u64>,

    pub user_secure_id: Option<u64>,
    pub no_auth_required: bool,
    pub user_auth_type: Option<u64>,
    pub auth_timeout: Option<u64>,
    pub allow_while_on_body: bool,
    pub trusted_user_presence_req: bool,
    pub trusted_confirmation_req: bool,
    pub unlocked_device_req: bool,

    pub all_applications: bool,

    pub creation_date_time: Option<u64>,
    pub origin: Option<u64>,
    pub rollback_resistant: bool,
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<u64>,
    pub os_patch_level: Option<u32>,

    pub attestation_application_id: Option<AttestationApplicationId>,
    pub attestation_id_brand: Option<String>,
    pub attestation_id_device: Option<String>,
    pub attestation_id_product: Option<String>,
    pub attestation_id_serial: Option<String>,
    pub attestation_id_imei: Option<String>,
    pub attestation_id_meid: Option<String>,
    pub attestation_id_manufacturer: Option<String>,
    pub attestation_id_model: Option<String>,
    pub vendor_patch_level: Option<u64>,
    pub boot_patch_level: Option<u64>,
    pub device_unique_attestation: bool,
    pub attestation_id_second_imei: Option<String>,
    #[serde(with = "crate::android::serde_hex::option")]
    pub module_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootOfTrust {
    #[serde(with = "crate::android::serde_hex")]
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    #[serde(with = "crate::android::serde_hex::option")]
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestationApplicationId {
    pub package_infos: Vec<AttestationPackageInfo>,
    #[serde(with = "crate::android::serde_hex::vec")]
    pub signature_digests: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestationPackageInfo {
    pub package_name: String,
    pub version: u64,
}

impl KeyDescription {
    pub fn from_der(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescriptionAsn1>(der)
            .map_err(|e| KeyDescriptionError::Asn1(Box::new(e)))?;

        Self::from_asn1(&key_description)
    }

    pub fn from_asn1(v: &KeyDescriptionAsn1) -> Result<Self, KeyDescriptionError> {
        Ok(Self {
            attestation_version: v.attestation_version,
            attestation_security_level: SecurityLevel::from_asn1(&v.attestation_security_level)?,
            key_security_version: v.key_security_version,
            key_security_level: SecurityLevel::from_asn1(&v.key_security_level)?,
            attestation_challenge: parse_utf8(v.attestation_challenge)?,
            unique_id: v.unique_id.to_vec(),
            software_enforced: AuthorizationList::from_asn1(&v.software_enforced)?,
            hardware_enforced: AuthorizationList::from_asn1(&v.hardware_enforced)?,
        })
    }

    pub fn attestation_application_id(&self) -> Option<&AttestationApplicationId> {
        self.hardware_enforced
            .attestation_application_id
            .as_ref()
            .or(self.software_enforced.attestation_application_id.as_ref())
    }
}

impl SecurityLevel {
    pub fn from_asn1(v: &asn1::Enumerated) -> Result<Self, KeyDescriptionError> {
        let v = v.value();

        match v {
            0 => Ok(SecurityLevel::Software),
            1 => Ok(SecurityLevel::TrustedEnvironment),
            2 => Ok(SecurityLevel::StrongBox),
            _ => Err(KeyDescriptionError::UnknownSecurityLevel(v)),
        }
    }
}

impl AuthorizationList {
    pub fn from_asn1(v: &AuthorizationListAsn1) -> Result<Self, KeyDescriptionError> {
        let root_of_trust = v
            .root_of_trust
            .as_ref()
            .map(RootOfTrust::from_asn1)
            .transpose()?;

        let attestation_application_id = v
            .try_parse_attestation_application_id()?
            .map(|id| AttestationApplicationId::from_asn1(&id))
            .transpose()?;

        let attestation_id_manufacturer =
            v.attestation_id_manufacturer.map(parse_utf8).transpose()?;

        Ok(Self {
            purpose: v.purpose.as_ref().map(extract_u64_set),
            algorithm: v.algorithm,
            key_size: v.key_size,
            block_mode: v.block_mode.as_ref().map(extract_u64_set),
            digest: v.digest.clone().map(|v| v.into()),
            padding: v.padding.as_ref().map(extract_u64_set),
            caller_nonce: v.caller_nonce.is_some(),
            min_mac_length: v.min_mac_length,
            ec_curve: v.ec_curve,

            rsa_public_exponent: v.rsa_public_exponent,
            mgf_digest: v.mgf_digest.as_ref().map(extract_u64_set),

            rollback_resistance: v.rollback_resistance.is_some(),
            early_boot_only: v.early_boot_only.is_some(),

            active_date_time: v.active_date_time,
            origination_expire_date_time: v.origination_expire_date_time,
            usage_expire_date_time: v.usage_expire_date_time,
            usage_count_limit: v.usage_count_limit,

            user_secure_id: v.user_secure_id,
            no_auth_required: v.no_auth_required.is_some(),
            user_auth_type: v.user_auth_type,
            auth_timeout: v.auth_timeout,
            allow_while_on_body: v.allow_while_on_body.is_some(),
            trusted_user_presence_req: v.trusted_user_presence_req.is_some(),
            trusted_confirmation_req: v.trusted_confirmation_req.is_some(),
            unlocked_device_req: v.unlocked_device_req.is_some(),

            all_applications: v.all_applications.is_some(),

            creation_date_time: v.creation_date_time,
            origin: v.origin,
            rollback_resistant: v.rollback_resistant.is_some(),
            root_of_trust,
            os_version: v.os_version,
            os_patch_level: v.os_patch_level,

            attestation_application_id: attestation_application_id,
            attestation_id_brand: v.attestation_id_brand.map(parse_utf8).transpose()?,
            attestation_id_device: v.attestation_id_device.map(parse_utf8).transpose()?,
            attestation_id_product: v.attestation_id_product.map(parse_utf8).transpose()?,
            attestation_id_serial: v.attestation_id_serial.map(parse_utf8).transpose()?,
            attestation_id_imei: v.attestation_id_imei.map(parse_utf8).transpose()?,
            attestation_id_meid: v.attestation_id_meid.map(parse_utf8).transpose()?,
            attestation_id_manufacturer: attestation_id_manufacturer,
            attestation_id_model: v.attestation_id_model.map(parse_utf8).transpose()?,
            vendor_patch_level: v.vendor_patch_level,
            boot_patch_level: v.boot_patch_level,
            device_unique_attestation: v.device_unique_attestation.is_some(),
            attestation_id_second_imei: v.attestation_id_second_imei.map(parse_utf8).transpose()?,
            module_hash: v.module_hash.map(|h| h.to_vec()),
        })
    }
}

impl RootOfTrust {
    pub fn from_asn1(v: &RootOfTrustAsn1) -> Result<Self, KeyDescriptionError> {
        Ok(Self {
            verified_boot_key: v.verified_boot_key.to_vec(),
            device_locked: v.device_locked.0,
            verified_boot_state: VerifiedBootState::from_asn1(&v.verified_boot_state)?,
            verified_boot_hash: v.verified_boot_hash.map(|h| h.to_vec()),
        })
    }
}

impl VerifiedBootState {
    pub fn from_asn1(v: &asn1::Enumerated) -> Result<Self, KeyDescriptionError> {
        let v = v.value();

        match v {
            0 => Ok(VerifiedBootState::Verified),
            1 => Ok(VerifiedBootState::SelfSigned),
            2 => Ok(VerifiedBootState::Unverified),
            3 => Ok(VerifiedBootState::Failed),
            _ => Err(KeyDescriptionError::UnknownVerifiedBootState(v)),
        }
    }
}

impl AttestationApplicationId {
    pub fn from_asn1(v: &AttestationApplicationIdAsn1) -> Result<Self, KeyDescriptionError> {
        let package_infos = v
            .package_infos
            .clone()
            .into_iter()
            .map(|pkg| AttestationPackageInfo::from_asn1(&pkg))
            .collect::<Result<Vec<AttestationPackageInfo>, KeyDescriptionError>>()?;

        let signature_digests = v
            .signature_digests
            .clone()
            .into_iter()
            .map(|digest| digest.to_vec())
            .collect();

        Ok(Self {
            package_infos,
            signature_digests,
        })
    }

    pub fn package_names(&self) -> Vec<String> {
        self.package_infos
            .iter()
            .map(|pkg| pkg.package_name.clone())
            .collect()
    }
}

impl AttestationPackageInfo {
    pub fn from_asn1(v: &AttestationPackageInfoAsn1) -> Result<Self, KeyDescriptionError> {
        Ok(Self {
            package_name: parse_utf8(v.package_name)?,
            version: v.version,
        })
    }
}

impl KeyDescriptionError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::Asn1(_) => "asn1".to_string(),
            Self::ParseUtf8(_) => "parse_utf8".to_string(),
            Self::UnknownSecurityLevel(e) => format!("unknown_security_level_{}", e),
            Self::UnknownVerifiedBootState(e) => format!("unknown_verified_boot_state_{}", e),
        }
    }
}

fn parse_utf8(value: &[u8]) -> Result<String, KeyDescriptionError> {
    String::from_utf8(value.to_vec()).map_err(KeyDescriptionError::ParseUtf8)
}

fn extract_u64_set(value: &asn1::SetOf<u64>) -> Vec<u64> {
    value.clone().into_iter().collect()
}
