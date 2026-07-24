use crate::android::key_description::{
    KeyDescriptionError, unordered_set_of_u64::UnorderedSetOfU64,
};

#[derive(asn1::Asn1Read)]
pub struct KeyDescriptionAsn1<'a> {
    pub attestation_version: u64,
    pub attestation_security_level: asn1::Enumerated,
    pub key_security_version: u64,
    pub key_security_level: asn1::Enumerated,
    pub attestation_challenge: &'a [u8],
    pub unique_id: &'a [u8],
    pub software_enforced: AuthorizationListAsn1<'a>,
    pub hardware_enforced: AuthorizationListAsn1<'a>,
}

#[derive(Default)]
pub struct AuthorizationListAsn1<'a> {
    pub purpose: Option<asn1::SetOf<'a, u64>>,
    pub algorithm: Option<u64>,
    pub key_size: Option<u64>,
    pub block_mode: Option<asn1::SetOf<'a, u64>>,
    pub digest: Option<UnorderedSetOfU64>,
    pub padding: Option<asn1::SetOf<'a, u64>>,
    pub caller_nonce: Option<asn1::Null>,
    pub min_mac_length: Option<u64>,
    pub ec_curve: Option<u64>,

    pub rsa_public_exponent: Option<u64>,
    pub mgf_digest: Option<asn1::SetOf<'a, u64>>,

    pub rollback_resistance: Option<asn1::Null>,
    pub early_boot_only: Option<asn1::Null>,

    pub active_date_time: Option<u64>,
    pub origination_expire_date_time: Option<u64>,
    pub usage_expire_date_time: Option<u64>,
    pub usage_count_limit: Option<u64>,

    pub user_secure_id: Option<u64>,
    pub no_auth_required: Option<asn1::Null>,
    pub user_auth_type: Option<u64>,
    pub auth_timeout: Option<u64>,
    pub allow_while_on_body: Option<asn1::Null>,
    pub trusted_user_presence_req: Option<asn1::Null>,
    pub trusted_confirmation_req: Option<asn1::Null>,
    pub unlocked_device_req: Option<asn1::Null>,

    pub all_applications: Option<asn1::Null>,

    pub creation_date_time: Option<u64>,
    pub origin: Option<u64>,
    pub rollback_resistant: Option<asn1::Null>,
    pub root_of_trust: Option<RootOfTrustAsn1<'a>>,
    pub os_version: Option<u64>,
    pub os_patch_level: Option<u32>,

    pub attestation_application_id: Option<&'a [u8]>,
    pub attestation_id_brand: Option<&'a [u8]>,
    pub attestation_id_device: Option<&'a [u8]>,
    pub attestation_id_product: Option<&'a [u8]>,
    pub attestation_id_serial: Option<&'a [u8]>,
    pub attestation_id_imei: Option<&'a [u8]>,
    pub attestation_id_meid: Option<&'a [u8]>,
    pub attestation_id_manufacturer: Option<&'a [u8]>,
    pub attestation_id_model: Option<&'a [u8]>,
    pub vendor_patch_level: Option<u64>,
    pub boot_patch_level: Option<u64>,
    pub device_unique_attestation: Option<asn1::Null>,
    pub attestation_id_second_imei: Option<&'a [u8]>,
    pub module_hash: Option<&'a [u8]>,
}

impl<'a> asn1::Asn1Readable<'a> for AuthorizationListAsn1<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let sequence = parser.read_element::<asn1::Sequence<'a>>()?;
        sequence.parse(|parser| {
            let mut result = Self::default();

            macro_rules! read_field {
                ($field:ident, $tag:literal) => {{
                    let value = parser.read_explicit_element($tag)?;
                    if result.$field.replace(value).is_some() {
                        return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }};
            }

            while !parser.is_empty() {
                let tag = parser
                    .peek_tag()
                    .ok_or_else(|| asn1::ParseError::new(asn1::ParseErrorKind::InvalidTag))?;

                match tag.value() {
                    1 => read_field!(purpose, 1),
                    2 => read_field!(algorithm, 2),
                    3 => read_field!(key_size, 3),
                    4 => read_field!(block_mode, 4),
                    5 => read_field!(digest, 5),
                    6 => read_field!(padding, 6),
                    7 => read_field!(caller_nonce, 7),
                    8 => read_field!(min_mac_length, 8),
                    10 => read_field!(ec_curve, 10),
                    200 => read_field!(rsa_public_exponent, 200),
                    203 => read_field!(mgf_digest, 203),
                    303 => read_field!(rollback_resistance, 303),
                    305 => read_field!(early_boot_only, 305),
                    400 => read_field!(active_date_time, 400),
                    401 => read_field!(origination_expire_date_time, 401),
                    402 => read_field!(usage_expire_date_time, 402),
                    405 => read_field!(usage_count_limit, 405),
                    502 => read_field!(user_secure_id, 502),
                    503 => read_field!(no_auth_required, 503),
                    504 => read_field!(user_auth_type, 504),
                    505 => read_field!(auth_timeout, 505),
                    506 => read_field!(allow_while_on_body, 506),
                    507 => read_field!(trusted_user_presence_req, 507),
                    508 => read_field!(trusted_confirmation_req, 508),
                    509 => read_field!(unlocked_device_req, 509),
                    600 => read_field!(all_applications, 600),
                    701 => read_field!(creation_date_time, 701),
                    702 => read_field!(origin, 702),
                    703 => read_field!(rollback_resistant, 703),
                    704 => read_field!(root_of_trust, 704),
                    705 => read_field!(os_version, 705),
                    706 => read_field!(os_patch_level, 706),
                    709 => read_field!(attestation_application_id, 709),
                    710 => read_field!(attestation_id_brand, 710),
                    711 => read_field!(attestation_id_device, 711),
                    712 => read_field!(attestation_id_product, 712),
                    713 => read_field!(attestation_id_serial, 713),
                    714 => read_field!(attestation_id_imei, 714),
                    715 => read_field!(attestation_id_meid, 715),
                    716 => read_field!(attestation_id_manufacturer, 716),
                    717 => read_field!(attestation_id_model, 717),
                    718 => read_field!(vendor_patch_level, 718),
                    719 => read_field!(boot_patch_level, 719),
                    720 => read_field!(device_unique_attestation, 720),
                    723 => read_field!(attestation_id_second_imei, 723),
                    724 => read_field!(module_hash, 724),
                    _ => {
                        return Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                            actual: tag,
                        }));
                    }
                }
            }

            Ok(result)
        })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == <asn1::Sequence<'_> as asn1::SimpleAsn1Readable<'_>>::TAG
    }
}

#[derive(Debug)]
pub struct RelaxedBoolean(pub bool);

impl asn1::SimpleAsn1Readable<'_> for RelaxedBoolean {
    const TAG: asn1::Tag = <bool as asn1::SimpleAsn1Readable<'static>>::TAG;

    fn parse_data(data: &[u8]) -> asn1::ParseResult<Self> {
        match data {
            [value] => Ok(Self(*value != 0)),
            _ => Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue)),
        }
    }
}

#[derive(asn1::Asn1Read, Debug)]
pub struct RootOfTrustAsn1<'a> {
    pub verified_boot_key: &'a [u8],
    pub device_locked: RelaxedBoolean,
    pub verified_boot_state: asn1::Enumerated,
    pub verified_boot_hash: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, Clone, PartialEq, Eq)]
pub struct AttestationApplicationIdAsn1<'a> {
    pub package_infos: asn1::SetOf<'a, AttestationPackageInfoAsn1<'a>>,
    pub signature_digests: asn1::SetOf<'a, &'a [u8]>,
}

#[derive(asn1::Asn1Read, Debug, Clone, PartialEq, Eq)]
pub struct AttestationPackageInfoAsn1<'a> {
    pub package_name: &'a [u8],
    pub version: u64,
}

impl<'a> AuthorizationListAsn1<'a> {
    pub fn try_parse_attestation_application_id(
        &self,
    ) -> Result<Option<AttestationApplicationIdAsn1<'a>>, KeyDescriptionError> {
        match self.attestation_application_id {
            None => Ok(None),
            Some(bytes) => {
                let id = asn1::parse_single::<AttestationApplicationIdAsn1>(bytes)
                    .map_err(|e| KeyDescriptionError::Asn1(Box::new(e)))?;
                Ok(Some(id))
            }
        }
    }
}
