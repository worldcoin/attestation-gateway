//! WIP-106 Authenticator Assertion Token (AAT) issuance.
//!
//! Keys rotate in fixed slots (see [`KeySchedule`]) and live in an [`AatKeyStore`]. Like the JWT
//! signing keys in `keys`, they are created and loaded lazily on requests, through a short cache.
//! The secret is decrypted in this process; it should move to a TEE before production (§3.2.7).

use std::{env, sync::Arc};

use arc_swap::ArcSwap;
use eddsa_babyjubjub::EdDSAPrivateKey;
use schemars::JsonSchema;
use serde::Serialize;
use world_id_primitives::FieldElement;
use world_id_primitives::authenticator_assertion::{
    AuthenticatorAssertionToken, MAX_AAT_LIFETIME_SECS, SecFlags,
};

use crate::aat_keys::{AatKeyStore, StoredKey};

/// Longest validity window of one key (WIP-106 §3.2.5).
const MAX_KEY_VALIDITY_SECS: u64 = 15_552_000;
/// Default AAT lifetime, below `MAX_AAT_LIFETIME_SECS` so verifier clocks running behind do not
/// reject fresh tokens.
const DEFAULT_AAT_LIFETIME_SECS: u32 = 1200;
/// Keys rotate every 90 days (WIP-106 §3.2.5 recommendation).
const SLOT_SECS: u64 = 90 * 24 * 60 * 60;
/// A key is published this long before it signs; WIP-106 §3.2.4 requires at least 24h.
const PUBLISH_LEAD_SECS: u64 = 48 * 60 * 60;
/// The next slot's key is created from this long before the slot starts. Creation is lazy, so the
/// margin over `PUBLISH_LEAD_SECS` covers days without requests.
const CREATE_LEAD_SECS: u64 = 7 * 24 * 60 * 60;
const CACHE_TTL_SECS: u64 = 5 * 60;
/// How often the refresh task checks the cache, so keys are created and reloaded without traffic.
const REFRESH_TICK: std::time::Duration = std::time::Duration::from_mins(1);
/// Delay before retrying a failed reload, so an outage is not retried on every request.
const RELOAD_BACKOFF_SECS: u64 = 30;

/// Why an AAT could not be issued.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// No unrevoked key may sign at this time.
    #[error("no AAT key may sign at this time")]
    KeyNotValid,
    #[error(transparent)]
    Token(#[from] eyre::Report),
}

/// When each slot's key is published, signs and expires.
#[derive(Debug, Clone, Copy)]
pub struct KeySchedule {
    pub epoch: u64,
    pub slot_secs: u64,
    pub publish_lead_secs: u64,
    pub create_lead_secs: u64,
    pub lifetime_secs: u32,
}

impl KeySchedule {
    /// # Panics
    /// If a key could sign for more than 180 days (§3.2.5), the lifetime breaks §3.6.3, or keys
    /// would be created after they must be published.
    #[must_use]
    pub fn new(
        epoch: u64,
        slot_secs: u64,
        publish_lead_secs: u64,
        create_lead_secs: u64,
        lifetime_secs: u32,
    ) -> Self {
        assert!(
            slot_secs > 0
                && slot_secs + publish_lead_secs + u64::from(lifetime_secs)
                    <= MAX_KEY_VALIDITY_SECS,
            "an AAT key must be valid for at most 180 days, including its overlap and AAT lifetime"
        );
        assert!(
            lifetime_secs > 0 && lifetime_secs <= MAX_AAT_LIFETIME_SECS,
            "`AAT_LIFETIME_SECS` must be in (0, {MAX_AAT_LIFETIME_SECS}]"
        );
        assert!(
            publish_lead_secs <= create_lead_secs && create_lead_secs < slot_secs,
            "keys must be created after the previous slot starts and before they must be published"
        );
        Self {
            epoch,
            slot_secs,
            publish_lead_secs,
            create_lead_secs,
            lifetime_secs,
        }
    }

    const fn start(&self, slot: u64) -> u64 {
        self.epoch + slot * self.slot_secs
    }

    fn slot_at(&self, now: u64) -> Option<u64> {
        now.checked_sub(self.epoch)
            .map(|since| since / self.slot_secs)
    }

    /// Slots whose key should exist at `now`: the current one, and the next once it is due.
    fn due_slots(&self, now: u64) -> Vec<u64> {
        let Some(current) = self.slot_at(now) else {
            return Vec::new();
        };
        let mut slots = vec![current];
        if now + self.create_lead_secs >= self.start(current + 1) {
            slots.push(current + 1);
        }
        slots
    }

    /// A new key for `slot`, created at `now`. It is published at once and signs no earlier than
    /// `publish_lead_secs` later, also when it is created late (e.g. on first start). It may sign
    /// until `publish_lead_secs` into the next slot, so a late next key never leaves a gap.
    fn new_key(&self, slot: u64, now: u64, key: EdDSAPrivateKey) -> StoredKey {
        StoredKey {
            slot,
            key,
            not_before: self.start(slot).max(now + self.publish_lead_secs),
            not_after: self.start(slot + 1)
                + self.publish_lead_secs
                + u64::from(self.lifetime_secs),
            revoked: false,
        }
    }
}

/// The keys loaded at one point in time.
pub struct KeySet {
    keys: Vec<StoredKey>,
    lifetime_secs: u32,
}

impl KeySet {
    /// The key stops signing one AAT lifetime before `not_after`, so its tokens expire in time.
    fn signing_end(&self, key: &StoredKey) -> u64 {
        key.not_after - u64::from(self.lifetime_secs)
    }

    /// The newest unrevoked key that may sign at `now`: once a slot's key may sign, it takes over
    /// from the previous one, which may still sign until its own window ends.
    fn signing_key(&self, now: u64) -> Option<&StoredKey> {
        self.keys
            .iter()
            .filter(|k| !k.revoked && k.not_before <= now && now < self.signing_end(k))
            .max_by_key(|k| k.slot)
    }

    /// Whether `key` no longer signs: its window ended, or a newer key took over.
    fn is_retired(&self, key: &StoredKey, now: u64) -> bool {
        now >= self.signing_end(key) || self.signing_key(now).is_some_and(|k| k.slot > key.slot)
    }

    /// Signs an AAT for `aat_commitment` and returns its CWT encoding.
    ///
    /// # Errors
    /// [`IssueError::KeyNotValid`] if no key may sign at `now`; [`IssueError::Token`] if the token
    /// can not be built or encoded.
    pub fn issue(
        &self,
        aat_commitment: FieldElement,
        sec_flags: SecFlags,
        now: u64,
    ) -> Result<Vec<u8>, IssueError> {
        let key = self.signing_key(now).ok_or(IssueError::KeyNotValid)?;
        let exp = u32::try_from(now)
            .ok()
            .and_then(|now| now.checked_add(self.lifetime_secs))
            .ok_or_else(|| eyre::eyre!("AAT expiry does not fit in a u32"))?;
        let token = AuthenticatorAssertionToken::new(exp, aat_commitment, sec_flags)
            .map_err(eyre::Report::from)?;
        Ok(token.sign(&key.key).map_err(eyre::Report::from)?)
    }

    /// The Authenticator Metadata document (WIP-106 §3.8). A key stays listed until its last AAT
    /// has expired plus `MAX_AAT_LIFETIME_SECS` (§3.2.6).
    ///
    /// # Errors
    /// If a public key can not be encoded.
    pub fn metadata(&self, provider_id: &str, now: u64) -> eyre::Result<AuthenticatorMetadata> {
        let mut keys: Vec<_> = self
            .keys
            .iter()
            .filter(|k| now < k.not_after + u64::from(MAX_AAT_LIFETIME_SECS))
            .collect();
        keys.sort_by_key(|k| k.slot);
        let authenticator_provider_keys = keys
            .into_iter()
            .map(|k| {
                let public = k.key.public();
                Ok(AuthenticatorProviderKey {
                    kid: hex::encode(public.to_compressed_bytes()?),
                    x: FieldElement::from(public.pk.x).to_string(),
                    y: FieldElement::from(public.pk.y).to_string(),
                    status: if k.revoked {
                        "revoked"
                    } else if self.is_retired(k, now) {
                        "retired"
                    } else {
                        "active"
                    },
                    not_before: k.not_before,
                    not_after: k.not_after,
                })
            })
            .collect::<eyre::Result<_>>()?;
        Ok(AuthenticatorMetadata {
            version: 1,
            provider_id: provider_id.to_string(),
            authenticator_provider_keys,
            sec_meta: serde_json::Map::new(),
        })
    }
}

struct Cache {
    keys: Arc<KeySet>,
    refresh_at: u64,
    loaded_at: u64,
}

/// Issues AATs with the Authenticator Provider's rotating keys.
pub struct AatIssuer {
    store: AatKeyStore,
    schedule: KeySchedule,
    provider_id: String,
    cache: ArcSwap<Cache>,
    reload: tokio::sync::Mutex<()>,
}

impl AatIssuer {
    /// Loads the issuer from the environment. Returns `None` if `AAT_KEYS_TABLE` is unset, which
    /// disables the `/aat` routes.
    ///
    /// # Panics
    /// If any `AAT_*` variable is malformed, or the keys can not be loaded, so a misconfigured
    /// issuer fails at startup.
    pub async fn from_env(aws_config: &aws_config::SdkConfig, now: u64) -> Option<Self> {
        let table = env::var("AAT_KEYS_TABLE").ok()?;
        let required = |name: &str| {
            env::var(name).unwrap_or_else(|_| panic!("`{name}` is required with `AAT_KEYS_TABLE`"))
        };
        let epoch = env::var("AAT_SLOT_EPOCH").map_or(0, |v| {
            v.parse()
                .expect("`AAT_SLOT_EPOCH` must be seconds since the Unix epoch")
        });
        let lifetime_secs = env::var("AAT_LIFETIME_SECS").map_or(DEFAULT_AAT_LIFETIME_SECS, |v| {
            v.parse().expect("`AAT_LIFETIME_SECS` must be a u32")
        });
        let store = AatKeyStore::new(
            aws_config,
            table,
            required("AAT_KEY_ENCRYPTION_KMS_KEY_ARN"),
        );
        let schedule = KeySchedule::new(
            epoch,
            SLOT_SECS,
            PUBLISH_LEAD_SECS,
            CREATE_LEAD_SECS,
            lifetime_secs,
        );
        Some(
            Self::new(store, schedule, required("AAT_PROVIDER_ID"), now)
                .await
                .expect("AAT keys could not be loaded"),
        )
    }

    /// Creates the issuer and loads its keys once, creating any that are due.
    ///
    /// # Errors
    /// If the keys can not be loaded or created.
    pub async fn new(
        store: AatKeyStore,
        schedule: KeySchedule,
        provider_id: String,
        now: u64,
    ) -> eyre::Result<Self> {
        let keys = reload_keys(&store, &schedule, now).await?;
        Ok(Self {
            store,
            schedule,
            provider_id,
            cache: ArcSwap::from_pointee(Cache {
                keys: Arc::new(keys),
                refresh_at: now + CACHE_TTL_SECS,
                loaded_at: now,
            }),
            reload: tokio::sync::Mutex::new(()),
        })
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Spawns a task that keeps the keys fresh without traffic: it creates the next slot's key on
    /// time and reloads revocations, through the same path as requests.
    pub fn spawn_refresh(self: &Arc<Self>) {
        let issuer = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REFRESH_TICK);
            loop {
                tick.tick().await;
                if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                {
                    issuer.keys(now.as_secs()).await;
                }
            }
        });
    }

    /// The current keys, reloaded when the cache has expired. A failed reload keeps the last keys,
    /// with no age limit so an outage does not stop issuance, and is retried after
    /// `RELOAD_BACKOFF_SECS`; only one caller reloads at a time.
    pub async fn keys(&self, now: u64) -> Arc<KeySet> {
        let cache = self.cache.load();
        if now < cache.refresh_at {
            return cache.keys.clone();
        }
        let Ok(_guard) = self.reload.try_lock() else {
            return cache.keys.clone();
        };
        let (keys, refresh_at, loaded_at, outcome) =
            match reload_keys(&self.store, &self.schedule, now).await {
                Ok(keys) => (Arc::new(keys), now + CACHE_TTL_SECS, now, "ok"),
                Err(e) => {
                    tracing::warn!(error = ?e, "Failed to reload AAT keys; keeping the last ones");
                    (
                        cache.keys.clone(),
                        now + RELOAD_BACKOFF_SECS,
                        cache.loaded_at,
                        "error",
                    )
                }
            };
        metrics::counter!("aat.keys.refresh", "outcome" => outcome).increment(1);
        // Alert on a growing age: revocations are not seen while reloads fail.
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!("aat.keys.age").set(now.saturating_sub(loaded_at) as f64);
        metrics::gauge!("aat.keys.signable").set(if keys.signing_key(now).is_some() {
            1.0
        } else {
            0.0
        });
        self.cache.store(Arc::new(Cache {
            keys: keys.clone(),
            refresh_at,
            loaded_at,
        }));
        keys
    }
}

/// Loads the keys and creates those that are due but missing. A conditional put makes one
/// instance win each slot; the others reload its key.
async fn reload_keys(
    store: &AatKeyStore,
    schedule: &KeySchedule,
    now: u64,
) -> eyre::Result<KeySet> {
    let since = now.saturating_sub(u64::from(MAX_AAT_LIFETIME_SECS));
    let mut keys = store.load(since).await?;
    for slot in schedule.due_slots(now) {
        if keys.iter().any(|k| k.slot == slot) {
            continue;
        }
        let key = schedule.new_key(slot, now, random_key()?);
        if store.create(&key).await? {
            metrics::counter!("aat.keys.created").increment(1);
            keys.push(key);
        } else {
            keys = store.load(since).await?;
        }
    }
    Ok(KeySet {
        keys,
        lifetime_secs: schedule.lifetime_secs,
    })
}

fn random_key() -> eyre::Result<EdDSAPrivateKey> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(EdDSAPrivateKey::from_bytes(bytes))
}

/// `/.well-known/world-id-authenticator.json` (WIP-106 Appendix A2).
#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthenticatorMetadata {
    pub version: u32,
    pub provider_id: String,
    pub authenticator_provider_keys: Vec<AuthenticatorProviderKey>,
    /// No `sec_meta` bits are defined, so none are ever set.
    pub sec_meta: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthenticatorProviderKey {
    pub kid: String,
    pub x: String,
    pub y: String,
    pub status: &'static str,
    pub not_before: u64,
    pub not_after: u64,
}

#[cfg(test)]
mod tests {
    use world_id_primitives::authenticator_assertion::{
        Platform, SecLevel, SignedAuthenticatorAssertionToken, UserPresence,
    };

    use super::*;

    const DAY: u64 = 24 * 60 * 60;
    const EPOCH: u64 = 1_700_000_000;
    const LIFETIME: u32 = DEFAULT_AAT_LIFETIME_SECS;

    fn schedule() -> KeySchedule {
        KeySchedule::new(
            EPOCH,
            SLOT_SECS,
            PUBLISH_LEAD_SECS,
            CREATE_LEAD_SECS,
            LIFETIME,
        )
    }

    fn flags() -> SecFlags {
        SecFlags::new(
            Platform::Ios.into(),
            SecLevel::HardwareKey.into(),
            2006,
            0,
            UserPresence::Undetermined,
        )
        .unwrap()
    }

    /// Keys for slots 0 and 1, both created well ahead of their slot.
    fn key_set() -> KeySet {
        let s = schedule();
        KeySet {
            keys: vec![
                s.new_key(0, EPOCH - 3 * DAY, EdDSAPrivateKey::from_bytes([7u8; 32])),
                s.new_key(
                    1,
                    s.start(1) - 3 * DAY,
                    EdDSAPrivateKey::from_bytes([8u8; 32]),
                ),
            ],
            lifetime_secs: LIFETIME,
        }
    }

    #[test]
    fn next_slot_is_due_only_within_the_create_lead() {
        let s = schedule();
        assert!(s.due_slots(EPOCH - 1).is_empty());
        assert_eq!(s.due_slots(EPOCH), vec![0]);
        assert_eq!(s.due_slots(s.start(1) - CREATE_LEAD_SECS - 1), vec![0]);
        assert_eq!(s.due_slots(s.start(1) - CREATE_LEAD_SECS), vec![0, 1]);
        assert_eq!(s.due_slots(s.start(1)), vec![1]);
    }

    #[test]
    fn a_late_key_is_published_before_it_signs() {
        let s = schedule();
        let on_time = s.new_key(
            1,
            s.start(1) - CREATE_LEAD_SECS,
            EdDSAPrivateKey::from_bytes([1; 32]),
        );
        assert_eq!(on_time.not_before, s.start(1));
        assert_eq!(
            on_time.not_after,
            s.start(2) + PUBLISH_LEAD_SECS + u64::from(LIFETIME)
        );

        let late = s.new_key(1, s.start(1) + 10, EdDSAPrivateKey::from_bytes([1; 32]));
        assert_eq!(late.not_before, s.start(1) + 10 + PUBLISH_LEAD_SECS);
    }

    #[test]
    fn signing_hands_over_at_the_slot_boundary() {
        let s = schedule();
        let keys = key_set();
        assert_eq!(keys.signing_key(EPOCH).unwrap().slot, 0);
        assert_eq!(keys.signing_key(s.start(1) - 1).unwrap().slot, 0);
        assert_eq!(keys.signing_key(s.start(1)).unwrap().slot, 1);
        assert!(keys.signing_key(EPOCH - 1).is_none());
        // Slot 1 overlaps into slot 2 by the publish lead, then stops.
        assert_eq!(keys.signing_key(s.start(2)).unwrap().slot, 1);
        assert!(keys.signing_key(s.start(2) + PUBLISH_LEAD_SECS).is_none());
    }

    #[test]
    fn a_late_next_key_leaves_no_gap() {
        let s = schedule();
        // Slot 1's key is created only at the boundary, so it signs 48h later.
        let keys = KeySet {
            keys: vec![
                s.new_key(0, EPOCH - 3 * DAY, EdDSAPrivateKey::from_bytes([7u8; 32])),
                s.new_key(1, s.start(1), EdDSAPrivateKey::from_bytes([8u8; 32])),
            ],
            lifetime_secs: LIFETIME,
        };
        for at in [s.start(1), s.start(1) + PUBLISH_LEAD_SECS - 1] {
            assert_eq!(keys.signing_key(at).unwrap().slot, 0);
        }
        assert_eq!(
            keys.signing_key(s.start(1) + PUBLISH_LEAD_SECS)
                .unwrap()
                .slot,
            1
        );
    }

    #[test]
    fn revoked_keys_do_not_sign_and_are_listed_as_revoked() {
        let mut keys = key_set();
        keys.keys[0].revoked = true;
        assert!(keys.signing_key(EPOCH).is_none());
        let metadata = keys.metadata("test", EPOCH).unwrap();
        assert_eq!(metadata.authenticator_provider_keys[0].status, "revoked");
    }

    #[test]
    fn metadata_lists_the_next_key_and_retires_the_previous_one() {
        let s = schedule();
        let keys = key_set();

        let before = keys.metadata("test", s.start(1) - 1).unwrap();
        let statuses: Vec<_> = before
            .authenticator_provider_keys
            .iter()
            .map(|k| k.status)
            .collect();
        assert_eq!(statuses, ["active", "active"]);

        let after = keys.metadata("test", s.start(1)).unwrap();
        let statuses: Vec<_> = after
            .authenticator_provider_keys
            .iter()
            .map(|k| k.status)
            .collect();
        assert_eq!(statuses, ["retired", "active"]);

        // Dropped once its window and last AAT have ended plus `MAX_AAT_LIFETIME_SECS`.
        let gone =
            s.start(1) + PUBLISH_LEAD_SECS + u64::from(LIFETIME) + u64::from(MAX_AAT_LIFETIME_SECS);
        assert_eq!(
            keys.metadata("test", gone)
                .unwrap()
                .authenticator_provider_keys
                .len(),
            1
        );
    }

    #[test]
    fn issued_token_decodes_and_verifies() {
        let keys = key_set();
        let commitment = FieldElement::from(42u64);
        let cwt = keys.issue(commitment, flags(), EPOCH).unwrap();

        let decoded = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();
        assert_eq!(decoded.token.aat_commitment(), commitment);
        assert_eq!(decoded.token.sec_flags(), flags());
        assert_eq!(u64::from(decoded.token.exp()), EPOCH + u64::from(LIFETIME));
        assert!(
            keys.keys[0]
                .key
                .public()
                .verify(*decoded.token.message_hash(), &decoded.signature)
        );
        assert!(matches!(
            keys.issue(commitment, flags(), EPOCH - 1),
            Err(IssueError::KeyNotValid)
        ));
    }

    #[test]
    fn metadata_matches_spec_test_vector_key() {
        // WIP-106 Appendix A1 uses the slot 0 key.
        let key = &key_set()
            .metadata("test", EPOCH)
            .unwrap()
            .authenticator_provider_keys[0];
        assert_eq!(
            key.kid,
            "2d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987"
        );
    }

    #[test]
    #[should_panic(expected = "at most 180 days")]
    fn rejects_slots_longer_than_180_days() {
        let _ = KeySchedule::new(0, MAX_KEY_VALIDITY_SECS, 0, 0, LIFETIME);
    }
}
