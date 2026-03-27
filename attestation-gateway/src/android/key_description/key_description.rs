use std::string::FromUtf8Error;

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
fn attestation_version_from_der(der: &[u8]) -> Result<u64, asn1::ParseError> {
    let (outer, rest) = asn1::strip_tlv(der)?;
    if !rest.is_empty() {
        return Err(asn1::ParseError::new(asn1::ParseErrorKind::ExtraData));
    }
    let (version_tlv, _rest_of_sequence) = asn1::strip_tlv(outer.data())?;
    asn1::parse_single::<u64>(version_tlv.full_data())
}

#[derive(Debug)]
pub enum KeyDescriptionError {
    ParseVersion(asn1::ParseError),
    ParseError(asn1::ParseError),
    ParseChallenge(FromUtf8Error),
    InvalidVersion(u64),
}

pub struct KeyDescription {
    pub attestation_challenge: String,
    pub attestation_security_level: u32,
    pub key_mint_security_level: u32,
    pub os_patch_level: Option<u64>,
    pub device_locked: Option<bool>,
    pub verified_boot_state: Option<u32>,
    pub key_origin: Option<u64>,
    pub package_name: Option<String>,
    pub attestation_signature_digests: Option<Vec<Vec<u8>>>,
}

impl KeyDescription {
    pub fn from_der(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let version =
            attestation_version_from_der(&der).map_err(KeyDescriptionError::ParseVersion)?;

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

    fn from_key_description_1(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription1>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name: None,
            attestation_signature_digests: None,
        })
    }

    fn from_key_description_2(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription2>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_3(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription3>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_4(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription4>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_100(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription100>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_200(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription200>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_300(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription300>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }

    fn from_key_description_400(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let key_description = asn1::parse_single::<KeyDescription400>(&der)
            .map_err(|e| KeyDescriptionError::ParseError(e))?;

        let attestation_challenge =
            String::from_utf8(key_description.attestation_challenge.to_vec())
                .map_err(|e| KeyDescriptionError::ParseChallenge(e))?;

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
        let package_name = app_id.as_ref().and_then(|aid| {
            aid.package_infos
                .clone()
                .next()
                .and_then(|pkg| std::str::from_utf8(pkg.package_name).ok().map(String::from))
        });
        let attestation_signature_digests = app_id.map(|aid| {
            aid.signature_digests
                .into_iter()
                .map(|d| d.to_vec())
                .collect()
        });

        Ok(Self {
            attestation_challenge,
            attestation_security_level,
            key_mint_security_level,
            os_patch_level,
            device_locked,
            verified_boot_state,
            key_origin,
            package_name,
            attestation_signature_digests,
        })
    }
}
