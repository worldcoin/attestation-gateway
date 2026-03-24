use crate::android::key_description::key_description_400::KeyDescription400;

#[derive(Debug)]
pub enum KeyDescriptionError {
    ParseVersion(asn1::ParseError),
    ParseError(asn1::ParseError),
    InvalidVersion(u64),
    MissingApplicationId,
}

pub struct KeyDescription {
    pub security_level: u32,
    pub device_locked: bool,
    pub package_name: String,
}

impl KeyDescription {
    pub fn from_der(der: Vec<u8>) -> Result<Self, KeyDescriptionError> {
        let version = asn1::parse(&der, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let version = d.read_element::<u64>()?;
                Ok(version)
            });
        })
        .map_err(|e| KeyDescriptionError::ParseVersion(e))?;

        match version {
            400 => {
                let key_description = asn1::parse_single::<KeyDescription400>(&der)
                    .map_err(|e| KeyDescriptionError::ParseError(e))?;

                let security_level = key_description.attestation_security_level.value();
                let device_locked = match &key_description.hardware_enforced.root_of_trust {
                    Some(root_of_trust) => root_of_trust.device_locked,
                    None => false,
                };
                let package_name = key_description
                    .try_parse_attestation_application_id()
                    .and_then(|app_id| {
                        app_id.package_infos.clone().next().and_then(|pkg| {
                            std::str::from_utf8(pkg.package_name).ok().map(String::from)
                        })
                    })
                    .ok_or(KeyDescriptionError::MissingApplicationId)?;

                Ok(Self {
                    security_level,
                    device_locked,
                    package_name,
                })
            }
            _ => Err(KeyDescriptionError::InvalidVersion(version)),
        }
    }
}
