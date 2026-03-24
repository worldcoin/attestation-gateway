// https://source.android.com/docs/security/features/keystore/attestation#attestation-v1

use crate::android::key_description::unordered_set_of_u64::UnorderedSetOfU64;

#[derive(asn1::Asn1Read)]
pub struct KeyDescription1<'a> {
    pub attestation_version: u64,
    pub attestation_security_level: asn1::Enumerated,
    /// Keymaster 1.0 reports schema version `2` here (see Android docs).
    pub keymaster_version: u64,
    pub keymaster_security_level: asn1::Enumerated,
    pub attestation_challenge: &'a [u8],
    pub unique_id: &'a [u8],
    pub software_enforced: AuthorizationList<'a>,
    pub hardware_enforced: AuthorizationList<'a>,
}

#[derive(asn1::Asn1Read)]
pub struct AuthorizationList<'a> {
    #[explicit(1)]
    pub purpose: Option<asn1::SetOf<'a, u64>>,
    #[explicit(2)]
    pub algorithm: Option<u64>,
    #[explicit(3)]
    pub key_size: Option<u64>,
    #[explicit(5)]
    pub digest: Option<UnorderedSetOfU64>,
    #[explicit(6)]
    pub padding: Option<asn1::SetOf<'a, u64>>,
    #[explicit(10)]
    pub ec_curve: Option<u64>,
    #[explicit(200)]
    pub rsa_public_exponent: Option<u64>,
    #[explicit(400)]
    pub active_date_time: Option<u64>,
    #[explicit(401)]
    pub origination_expire_date_time: Option<u64>,
    #[explicit(402)]
    pub usage_expire_date_time: Option<u64>,
    #[explicit(503)]
    pub no_auth_required: Option<asn1::Null>,
    #[explicit(504)]
    pub user_auth_type: Option<u64>,
    #[explicit(505)]
    pub auth_timeout: Option<u64>,
    #[explicit(506)]
    pub allow_while_on_body: Option<asn1::Null>,
    #[explicit(600)]
    pub all_applications: Option<asn1::Null>,
    #[explicit(701)]
    pub creation_date_time: Option<u64>,
    #[explicit(702)]
    pub origin: Option<u64>,
    #[explicit(703)]
    pub rollback_resistant: Option<asn1::Null>,
    #[explicit(704)]
    pub root_of_trust: Option<RootOfTrust<'a>>,
    #[explicit(705)]
    pub os_version: Option<u64>,
    #[explicit(706)]
    pub os_patch_level: Option<u64>,
}

/// Root of trust for attestation schema versions 1 and 2 (no `verified_boot_hash`).
#[derive(asn1::Asn1Read, Debug)]
pub struct RootOfTrust<'a> {
    pub verified_boot_key: &'a [u8],
    pub device_locked: bool,
    pub verified_boot_state: asn1::Enumerated,
}
