mod key_description_1;
mod key_description_100;
mod key_description_2;
mod key_description_200;
mod key_description_3;
mod key_description_300;
mod key_description_4;
mod key_description_400;
mod unordered_set_of_u64;

use std::string::FromUtf8Error;

use thiserror::Error;

use crate::android::key_description::key_description_1::KeyDescription1;
use crate::android::key_description::key_description_2::KeyDescription2;
use crate::android::key_description::key_description_3::KeyDescription3;
use crate::android::key_description::key_description_4::KeyDescription4;
use crate::android::key_description::key_description_100::KeyDescription100;
use crate::android::key_description::key_description_200::KeyDescription200;
use crate::android::key_description::key_description_300::KeyDescription300;
use crate::android::key_description::key_description_400::KeyDescription400;

/// Converts the raw `_unique_id` bytes into an `Option<Vec<u8>>` (None when empty).
fn unique_id_from_raw(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_vec())
    }
}

/// Populates the common new fields from a parsed key description's hardware_enforced auth list.
/// Use `$kd` for the parsed key description, `$hw` for `$kd.hardware_enforced`, and `$sw` for
/// `$kd.software_enforced`. Fields not present in a given schema version should be set to None
/// before this macro is invoked.
macro_rules! extract_common_fields {
    ($hw:expr, $sw:expr) => {{
        let os_version = $hw.os_version.or($sw.os_version);
        let algorithm = $hw.algorithm.or($sw.algorithm);
        let key_size = $hw.key_size.or($sw.key_size);
        let ec_curve = $hw.ec_curve.or($sw.ec_curve);
        (os_version, algorithm, key_size, ec_curve)
    }};
}

/// Reads the leading `attestation_version` INTEGER without parsing the rest of the SEQUENCE.
///
/// `asn1::parse` / [`asn1::Sequence::parse`] require the entire SEQUENCE body to be consumed;
/// different attestation versions use different schemas, so we peel the first TLV with
/// [`asn1::strip_tlv`] (which allows trailing data) and only then [`asn1::parse_single`] the INTEGER.
/// Collects all UTF-8 package names from an optional attestation application id.
macro_rules! package_names_from_app_id {
    ($app_id:expr) => {
        $app_id
            .as_ref()
            .map(|aid| {
                aid.package_infos
                    .clone()
                    .filter_map(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
}

fn attestation_version_from_der(der: &[u8]) -> Result<u64, Box<asn1::ParseError>> {
    let (outer, rest) = asn1::strip_tlv(der)?;
    if !rest.is_empty() {
        return Err(Box::new(asn1::ParseError::new(
            asn1::ParseErrorKind::ExtraData,
        )));
    }
    let (version_tlv, _rest_of_sequence) = asn1::strip_tlv(outer.data())?;
    asn1::parse_single::<u64>(version_tlv.full_data()).map_err(Box::new)
}

#[derive(Debug, Error)]
pub enum KeyDescriptionError {
    #[error("parse_version")]
    ParseVersion(#[source] Box<asn1::ParseError>),

    #[error("parsing")]
    Parsing(#[source] Box<asn1::ParseError>),

    #[error("parse_challenge")]
    ParseChallenge(#[source] FromUtf8Error),

    #[error("invalid_version_{0}")]
    InvalidVersion(u64),
}

pub struct KeyDescription {
    pub unique_id: Option<Vec<u8>>,
    pub attestation_challenge: String,
    pub attestation_security_level: u32,
    pub key_mint_security_level: u32,
    pub os_patch_level: Option<u32>,
    pub device_locked: Option<bool>,
    pub verified_boot_state: Option<u32>,
    pub key_origin: Option<u64>,
    pub package_names: Vec<String>,
    pub attestation_signature_digests: Option<Vec<Vec<u8>>>,
    pub attestation_version: u64,
    pub purpose: Vec<u64>,
    pub verified_boot_key: Option<Vec<u8>>,
    pub verified_boot_hash: Option<Vec<u8>>,
    pub creation_date_time: Option<u64>,
    pub attestation_id_brand: Option<Vec<u8>>,
    pub attestation_id_device: Option<Vec<u8>>,
    pub attestation_id_product: Option<Vec<u8>>,
    pub attestation_id_serial: Option<Vec<u8>>,
    pub attestation_id_imei: Option<Vec<u8>>,
    pub attestation_id_meid: Option<Vec<u8>>,
    pub attestation_id_manufacturer: Option<Vec<u8>>,
    pub attestation_id_model: Option<Vec<u8>>,
    pub attestation_id_second_imei: Option<Vec<u8>>,
    pub device_unique_attestation: bool,
    pub module_hash: Option<Vec<u8>>,
    pub vendor_patch_level: Option<u64>,
    pub boot_patch_level: Option<u64>,
    pub os_version: Option<u64>,
    pub usage_count_limit: Option<u64>,
    pub algorithm: Option<u64>,
    pub key_size: Option<u64>,
    pub ec_curve: Option<u64>,
}

impl KeyDescription {
    pub fn from_der(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let version =
            attestation_version_from_der(der).map_err(KeyDescriptionError::ParseVersion)?;

        match version {
            1 => Self::from_key_description_1(der),
            2 => Self::from_key_description_2(der),
            3 => Self::from_key_description_3(der),
            4 => Self::from_key_description_4(der),
            100 => Self::from_key_description_100(der),
            200 => Self::from_key_description_200(der),
            300 => Self::from_key_description_300(der),
            400 => Self::from_key_description_400(der),
            _ => Err(KeyDescriptionError::InvalidVersion(version)),
        }
    }

    fn from_key_description_1(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription1>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.keymaster_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        let (os_version, algorithm, key_size, ec_curve) = extract_common_fields!(
            key_description.hardware_enforced,
            key_description.software_enforced
        );

        Ok(Self {
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names: vec![],
            attestation_signature_digests: None,
            attestation_version: 1,
            purpose,
            verified_boot_key,
            verified_boot_hash: None,
            creation_date_time,
            attestation_id_brand: None,
            attestation_id_device: None,
            attestation_id_product: None,
            attestation_id_serial: None,
            attestation_id_imei: None,
            attestation_id_meid: None,
            attestation_id_manufacturer: None,
            attestation_id_model: None,
            attestation_id_second_imei: None,
            device_unique_attestation: false,
            module_hash: None,
            vendor_patch_level: None,
            boot_patch_level: None,
            os_version,
            usage_count_limit: None,
            algorithm,
            key_size,
            ec_curve,
        })
    }

    fn from_key_description_2(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription2>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.keymaster_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            attestation_version: 2,
            purpose,
            verified_boot_key,
            verified_boot_hash: None,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: None,
            device_unique_attestation: false,
            module_hash: None,
            vendor_patch_level: None,
            boot_patch_level: None,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: None,
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_3(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription3>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.keymaster_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 3,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: None,
            device_unique_attestation: false,
            module_hash: None,
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: None,
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_4(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription4>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.keymaster_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 4,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: None,
            device_unique_attestation: key_description
                .hardware_enforced
                ._device_unique_attestation
                .is_some(),
            module_hash: None,
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: None,
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_100(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription100>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.key_mint_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 100,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: None,
            device_unique_attestation: key_description
                .hardware_enforced
                ._device_unique_attestation
                .is_some(),
            module_hash: None,
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: key_description
                .hardware_enforced
                ._usage_count_limit
                .or(key_description.software_enforced._usage_count_limit),
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_200(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription200>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.key_mint_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 200,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: None,
            device_unique_attestation: key_description
                .hardware_enforced
                ._device_unique_attestation
                .is_some(),
            module_hash: None,
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: key_description
                .hardware_enforced
                ._usage_count_limit
                .or(key_description.software_enforced._usage_count_limit),
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_300(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription300>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.key_mint_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 300,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: key_description
                .hardware_enforced
                ._attestation_id_second_imei
                .map(<[u8]>::to_vec),
            device_unique_attestation: key_description
                .hardware_enforced
                ._device_unique_attestation
                .is_some(),
            module_hash: None,
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: key_description
                .hardware_enforced
                ._usage_count_limit
                .or(key_description.software_enforced._usage_count_limit),
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }

    fn from_key_description_400(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription400>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(KeyDescriptionError::ParseChallenge)?;

        let attestation_security_level = key_description.attestation_security_level.value();
        let key_mint_security_level = key_description.key_mint_security_level.value();
        let os_patch_level = key_description
            .hardware_enforced
            .os_patch_level
            .or(key_description.software_enforced.os_patch_level);

        let device_locked = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);

        let verified_boot_state = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());

        let key_origin = key_description.hardware_enforced.origin;

        let app_id = key_description.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());

        let purpose = key_description
            .hardware_enforced
            ._purpose
            .map(|s| s.collect())
            .unwrap_or_default();

        let verified_boot_key = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());

        let verified_boot_hash = key_description
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());

        let creation_date_time = key_description
            .hardware_enforced
            ._creation_date_time
            .or(key_description.software_enforced._creation_date_time);

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names,
            attestation_signature_digests,
            unique_id: unique_id_from_raw(key_description._unique_id),
            attestation_version: 400,
            purpose,
            verified_boot_key,
            verified_boot_hash,
            creation_date_time,
            attestation_id_brand: key_description
                .hardware_enforced
                ._attestation_id_brand
                .map(<[u8]>::to_vec),
            attestation_id_device: key_description
                .hardware_enforced
                ._attestation_id_device
                .map(<[u8]>::to_vec),
            attestation_id_product: key_description
                .hardware_enforced
                ._attestation_id_product
                .map(<[u8]>::to_vec),
            attestation_id_serial: key_description
                .hardware_enforced
                ._attestation_id_serial
                .map(<[u8]>::to_vec),
            attestation_id_imei: key_description
                .hardware_enforced
                ._attestation_id_imei
                .map(<[u8]>::to_vec),
            attestation_id_meid: key_description
                .hardware_enforced
                ._attestation_id_meid
                .map(<[u8]>::to_vec),
            attestation_id_manufacturer: key_description
                .hardware_enforced
                ._attestation_id_manufacturer
                .map(<[u8]>::to_vec),
            attestation_id_model: key_description
                .hardware_enforced
                ._attestation_id_model
                .map(<[u8]>::to_vec),
            attestation_id_second_imei: key_description
                .hardware_enforced
                ._attestation_id_second_imei
                .map(<[u8]>::to_vec),
            device_unique_attestation: key_description
                .hardware_enforced
                ._device_unique_attestation
                .is_some(),
            module_hash: key_description
                .hardware_enforced
                ._module_hash
                .map(<[u8]>::to_vec),
            vendor_patch_level: key_description.hardware_enforced._vendor_patch_level,
            boot_patch_level: key_description.hardware_enforced._boot_patch_level,
            os_version: key_description
                .hardware_enforced
                .os_version
                .or(key_description.software_enforced.os_version),
            usage_count_limit: key_description
                .hardware_enforced
                ._usage_count_limit
                .or(key_description.software_enforced._usage_count_limit),
            algorithm: key_description
                .hardware_enforced
                .algorithm
                .or(key_description.software_enforced.algorithm),
            key_size: key_description
                .hardware_enforced
                .key_size
                .or(key_description.software_enforced.key_size),
            ec_curve: key_description
                .hardware_enforced
                .ec_curve
                .or(key_description.software_enforced.ec_curve),
        })
    }
}

impl KeyDescriptionError {
    pub fn reason_tag(&self) -> String {
        match self {
            Self::ParseVersion(_) => "attestation_version".to_string(),
            Self::Parsing(_) => "parsing".to_string(),
            Self::ParseChallenge(_) => "parse_challenge".to_string(),
            Self::InvalidVersion(v) => format!("invalid_version_{v}"),
        }
    }

    pub const fn is_internal_error(&self) -> bool {
        match self {
            Self::ParseVersion(_)
            | Self::Parsing(_)
            | Self::ParseChallenge(_)
            | Self::InvalidVersion(_) => false,
        }
    }
}
