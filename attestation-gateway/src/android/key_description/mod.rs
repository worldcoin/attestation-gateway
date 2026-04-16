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
    pub attestation_challenge: String,
    pub attestation_security_level: u32,
    pub key_mint_security_level: u32,
    pub os_patch_level: Option<u32>,
    pub device_locked: Option<bool>,
    pub verified_boot_state: Option<u32>,
    pub key_origin: Option<u64>,
    pub package_names: Vec<String>,
    pub attestation_signature_digests: Option<Vec<Vec<u8>>>,
    pub verified_boot_key: Option<Vec<u8>>,
    pub verified_boot_hash: Option<Vec<u8>>,
    pub device_unique_attestation: bool,
    pub attestation_id_brand: Option<Vec<u8>>,
    pub attestation_id_device: Option<Vec<u8>>,
    pub attestation_id_product: Option<Vec<u8>>,
    pub attestation_id_manufacturer: Option<Vec<u8>>,
    pub attestation_id_model: Option<Vec<u8>>,
    pub module_hash: Option<Vec<u8>>,
    pub purpose: Vec<u64>,
    pub creation_date_time: Option<u64>,
    pub batch_cert_serial_hex: Option<String>,
}

/// Default values for the new integrity-analysis fields, used by older attestation
/// versions that do not carry these tags.
impl KeyDescription {
    fn integrity_defaults() -> IntegrityFieldDefaults {
        IntegrityFieldDefaults {
            verified_boot_key: None,
            verified_boot_hash: None,
            device_unique_attestation: false,
            attestation_id_brand: None,
            attestation_id_device: None,
            attestation_id_product: None,
            attestation_id_manufacturer: None,
            attestation_id_model: None,
            module_hash: None,
            purpose: vec![],
            creation_date_time: None,
        }
    }
}

struct IntegrityFieldDefaults {
    verified_boot_key: Option<Vec<u8>>,
    verified_boot_hash: Option<Vec<u8>>,
    device_unique_attestation: bool,
    attestation_id_brand: Option<Vec<u8>>,
    attestation_id_device: Option<Vec<u8>>,
    attestation_id_product: Option<Vec<u8>>,
    attestation_id_manufacturer: Option<Vec<u8>>,
    attestation_id_model: Option<Vec<u8>>,
    module_hash: Option<Vec<u8>>,
    purpose: Vec<u64>,
    creation_date_time: Option<u64>,
}

macro_rules! extract_root_of_trust_fields {
    ($hw:expr) => {{
        let verified_boot_key = $hw
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());
        let verified_boot_hash = $hw
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_hash.to_vec());
        (verified_boot_key, verified_boot_hash)
    }};
}

macro_rules! extract_root_of_trust_fields_no_hash {
    ($hw:expr) => {{
        let verified_boot_key = $hw
            .root_of_trust
            .as_ref()
            .map(|r| r._verified_boot_key.to_vec());
        (verified_boot_key, None::<Vec<u8>>)
    }};
}

macro_rules! extract_id_attestation {
    ($hw:expr) => {{
        let brand = $hw._attestation_id_brand.map(<[u8]>::to_vec);
        let device = $hw._attestation_id_device.map(<[u8]>::to_vec);
        let product = $hw._attestation_id_product.map(<[u8]>::to_vec);
        let manufacturer = $hw._attestation_id_manufacturer.map(<[u8]>::to_vec);
        let model = $hw._attestation_id_model.map(<[u8]>::to_vec);
        (brand, device, product, manufacturer, model)
    }};
}

macro_rules! extract_purpose {
    ($hw:expr, $sw:expr) => {{
        $hw._purpose
            .as_ref()
            .map(|s| s.clone().collect::<Vec<_>>())
            .or_else(|| $sw._purpose.as_ref().map(|s| s.clone().collect::<Vec<_>>()))
            .unwrap_or_default()
    }};
}

macro_rules! extract_creation_date_time {
    ($hw:expr, $sw:expr) => {
        $hw._creation_date_time.or($sw._creation_date_time)
    };
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

        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields_no_hash!(key_description.hardware_enforced);
        let defaults = Self::integrity_defaults();

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_names: vec![],
            attestation_signature_digests: None,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: defaults.device_unique_attestation,
            attestation_id_brand: defaults.attestation_id_brand,
            attestation_id_device: defaults.attestation_id_device,
            attestation_id_product: defaults.attestation_id_product,
            attestation_id_manufacturer: defaults.attestation_id_manufacturer,
            attestation_id_model: defaults.attestation_id_model,
            module_hash: defaults.module_hash,
            purpose: extract_purpose!(
                key_description.hardware_enforced,
                key_description.software_enforced
            ),
            creation_date_time: extract_creation_date_time!(
                key_description.hardware_enforced,
                key_description.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_2(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription2>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields_no_hash!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.keymaster_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: false,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_3(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription3>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.keymaster_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: false,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_4(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription4>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);
        let device_unique = kd.hardware_enforced._device_unique_attestation.is_some();

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.keymaster_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: device_unique,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_100(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription100>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);
        let device_unique = kd.hardware_enforced._device_unique_attestation.is_some();

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.key_mint_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: device_unique,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_200(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription200>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);
        let device_unique = kd.hardware_enforced._device_unique_attestation.is_some();

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.key_mint_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: device_unique,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_300(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription300>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);
        let device_unique = kd.hardware_enforced._device_unique_attestation.is_some();

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.key_mint_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: device_unique,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: None,
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
        })
    }

    fn from_key_description_400(der: &[u8]) -> Result<Self, KeyDescriptionError> {
        let kd = asn1::parse_single::<KeyDescription400>(der)
            .map_err(|e| KeyDescriptionError::Parsing(Box::new(e)))?;
        let attestation_challenge = String::from_utf8(kd.attestation_challenge.to_vec())
            .map_err(KeyDescriptionError::ParseChallenge)?;
        let os_patch_level = kd
            .hardware_enforced
            .os_patch_level
            .or(kd.software_enforced.os_patch_level);
        let device_locked = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.device_locked);
        let verified_boot_state = kd
            .hardware_enforced
            .root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state.value());
        let app_id = kd.try_parse_attestation_application_id();
        let package_names = package_names_from_app_id!(app_id);
        let attestation_signature_digests =
            app_id.map(|aid| aid.signature_digests.map(<[u8]>::to_vec).collect());
        let (verified_boot_key, verified_boot_hash) =
            extract_root_of_trust_fields!(kd.hardware_enforced);
        let (brand, device, product, manufacturer, model) =
            extract_id_attestation!(kd.hardware_enforced);
        let device_unique = kd.hardware_enforced._device_unique_attestation.is_some();

        Ok(Self {
            attestation_challenge,
            attestation_security_level: kd.attestation_security_level.value(),
            key_mint_security_level: kd.key_mint_security_level.value(),
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin: kd.hardware_enforced.origin,
            package_names,
            attestation_signature_digests,
            verified_boot_key,
            verified_boot_hash,
            device_unique_attestation: device_unique,
            attestation_id_brand: brand,
            attestation_id_device: device,
            attestation_id_product: product,
            attestation_id_manufacturer: manufacturer,
            attestation_id_model: model,
            module_hash: kd.hardware_enforced._module_hash.map(<[u8]>::to_vec),
            purpose: extract_purpose!(kd.hardware_enforced, kd.software_enforced),
            creation_date_time: extract_creation_date_time!(
                kd.hardware_enforced,
                kd.software_enforced
            ),
            batch_cert_serial_hex: None,
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
