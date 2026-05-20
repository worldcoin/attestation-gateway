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

#[derive(asn1::Asn1Read)]
pub struct AuthorizationListAsn1<'a> {
    #[explicit(1)]
    pub purpose: Option<asn1::SetOf<'a, u64>>,
    #[explicit(2)]
    pub algorithm: Option<u64>,
    #[explicit(3)]
    pub key_size: Option<u64>,
    #[explicit(4)]
    pub block_mode: Option<asn1::SetOf<'a, u64>>,
    #[explicit(5)]
    pub digest: Option<UnorderedSetOfU64>,
    #[explicit(6)]
    pub padding: Option<asn1::SetOf<'a, u64>>,
    #[explicit(7)]
    pub caller_nonce: Option<asn1::Null>,
    #[explicit(8)]
    pub min_mac_length: Option<u64>,
    #[explicit(10)]
    pub ec_curve: Option<u64>,

    #[explicit(200)]
    pub rsa_public_exponent: Option<u64>,
    #[explicit(203)]
    pub mgf_digest: Option<asn1::SetOf<'a, u64>>,

    #[explicit(303)]
    pub rollback_resistance: Option<asn1::Null>,
    #[explicit(305)]
    pub early_boot_only: Option<asn1::Null>,

    #[explicit(400)]
    pub active_date_time: Option<u64>,
    #[explicit(401)]
    pub origination_expire_date_time: Option<u64>,
    #[explicit(402)]
    pub usage_expire_date_time: Option<u64>,
    #[explicit(405)]
    pub usage_count_limit: Option<u64>,

    #[explicit(502)]
    pub user_secure_id: Option<u64>,
    #[explicit(503)]
    pub no_auth_required: Option<asn1::Null>,
    #[explicit(504)]
    pub user_auth_type: Option<u64>,
    #[explicit(505)]
    pub auth_timeout: Option<u64>,
    #[explicit(506)]
    pub allow_while_on_body: Option<asn1::Null>,
    #[explicit(507)]
    pub trusted_user_presence_req: Option<asn1::Null>,
    #[explicit(508)]
    pub trusted_confirmation_req: Option<asn1::Null>,
    #[explicit(509)]
    pub unlocked_device_req: Option<asn1::Null>,

    #[explicit(600)]
    pub all_applications: Option<asn1::Null>,

    #[explicit(701)]
    pub creation_date_time: Option<u64>,
    #[explicit(702)]
    pub origin: Option<u64>,
    #[explicit(703)]
    pub rollback_resistant: Option<asn1::Null>,
    #[explicit(704)]
    pub root_of_trust: Option<RootOfTrustAsn1<'a>>,
    #[explicit(705)]
    pub os_version: Option<u64>,
    #[explicit(706)]
    pub os_patch_level: Option<u32>,

    #[explicit(709)]
    pub attestation_application_id: Option<&'a [u8]>,
    #[explicit(710)]
    pub attestation_id_brand: Option<&'a [u8]>,
    #[explicit(711)]
    pub attestation_id_device: Option<&'a [u8]>,
    #[explicit(712)]
    pub attestation_id_product: Option<&'a [u8]>,
    #[explicit(713)]
    pub attestation_id_serial: Option<&'a [u8]>,
    #[explicit(714)]
    pub attestation_id_imei: Option<&'a [u8]>,
    #[explicit(715)]
    pub attestation_id_meid: Option<&'a [u8]>,
    #[explicit(716)]
    pub attestation_id_manufacturer: Option<&'a [u8]>,
    #[explicit(717)]
    pub attestation_id_model: Option<&'a [u8]>,
    #[explicit(718)]
    pub vendor_patch_level: Option<u64>,
    #[explicit(719)]
    pub boot_patch_level: Option<u64>,
    #[explicit(720)]
    pub device_unique_attestation: Option<asn1::Null>,
    #[explicit(723)]
    pub attestation_id_second_imei: Option<&'a [u8]>,
    #[explicit(724)]
    pub module_hash: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, Debug)]
pub struct RootOfTrustAsn1<'a> {
    pub verified_boot_key: &'a [u8],
    pub device_locked: bool,
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
