use std::sync::{Arc, Mutex, PoisonError};

use keyroost_openpgp::{AlgorithmAttributes, KeyCrt};
use keyroost_piv::{KeyAlg, Slot};
use ssh_agent_lib::{proto::PublicCredential, ssh_key::Signature};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PivCachedIdentity {
    pub(crate) slot: Slot,
    pub(crate) key_alg: KeyAlg,
    pub(crate) serial: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenPgpCachedIdentity {
    pub(crate) slot: KeyCrt,
    pub(crate) attrs: AlgorithmAttributes,
    pub(crate) serial: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedIdentity {
    Piv(PivCachedIdentity),
    OpenPgp(OpenPgpCachedIdentity),
}

#[derive(Debug)]
pub(crate) enum SignOutcome {
    /// Successfully produced an SSH signature.
    Signed(Signature),
    /// Matching key was found, but the user cancelled the PIN prompt.
    UserCancelled,
    /// No matching key was found on this backend.
    NotFound,
}

#[derive(Debug)]
pub(crate) struct SignResult<T> {
    /// Freshly scanned identities when a slot scan occurred (`None` on a cache hit).
    pub(crate) discovered: Option<Vec<(PublicCredential, T)>>,
    pub(crate) outcome: SignOutcome,
}

#[derive(Clone, Default)]
pub(crate) struct IdentityCache {
    entries: Arc<Mutex<Vec<(PublicCredential, CachedIdentity)>>>,
}

impl IdentityCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, credential: &PublicCredential) -> Option<CachedIdentity> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .find(|(cred, _)| cred == credential)
            .map(|(_, cached)| *cached)
    }

    pub(crate) fn replace_piv(
        &self,
        items: impl IntoIterator<Item = (PublicCredential, PivCachedIdentity)>,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|(_, cached)| !matches!(cached, CachedIdentity::Piv(_)));
        entries.extend(
            items
                .into_iter()
                .map(|(cred, piv)| (cred, CachedIdentity::Piv(piv))),
        );
    }

    pub(crate) fn replace_openpgp(
        &self,
        items: impl IntoIterator<Item = (PublicCredential, OpenPgpCachedIdentity)>,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|(_, cached)| !matches!(cached, CachedIdentity::OpenPgp(_)));
        entries.extend(
            items
                .into_iter()
                .map(|(cred, pgp)| (cred, CachedIdentity::OpenPgp(pgp))),
        );
    }

    pub(crate) fn evict(&self, credential: &PublicCredential) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|(cred, _)| cred != credential);
    }

    pub(crate) fn clear(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedIdentity, IdentityCache, OpenPgpCachedIdentity, PivCachedIdentity};
    use keyroost_openpgp::{AlgorithmAttributes, Curve, EccKind, KeyCrt};
    use keyroost_piv::{KeyAlg, Slot};
    use ssh_agent_lib::{
        proto::PublicCredential,
        ssh_key::public::{Ed25519PublicKey, KeyData},
    };

    fn cred(byte: u8) -> PublicCredential {
        PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([byte; 32])))
    }

    fn piv_meta(slot: Slot, serial: Option<u128>) -> PivCachedIdentity {
        PivCachedIdentity {
            slot,
            key_alg: KeyAlg::Ed25519,
            serial,
        }
    }

    fn pgp_meta(slot: KeyCrt, serial: Option<u128>) -> OpenPgpCachedIdentity {
        OpenPgpCachedIdentity {
            slot,
            attrs: AlgorithmAttributes::Ecc {
                kind: EccKind::EdDsa,
                curve: Curve::Ed25519,
                import_with_public_key: false,
            },
            serial,
        }
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = IdentityCache::new();
        assert_eq!(cache.get(&cred(1)), None);
    }

    #[test]
    fn replace_per_backend_preserves_other_backend_entries() {
        let cache = IdentityCache::new();
        let piv_k1 = cred(1);
        let piv_k2 = cred(2);
        let pgp_k1 = cred(3);

        cache.replace_piv([(piv_k1.clone(), piv_meta(Slot::Authentication, Some(10)))]);
        cache.replace_openpgp([(pgp_k1.clone(), pgp_meta(KeyCrt::Auth, Some(20)))]);

        assert_eq!(
            cache.get(&piv_k1),
            Some(CachedIdentity::Piv(piv_meta(
                Slot::Authentication,
                Some(10)
            )))
        );
        assert_eq!(
            cache.get(&pgp_k1),
            Some(CachedIdentity::OpenPgp(pgp_meta(KeyCrt::Auth, Some(20))))
        );

        // Replacing PIV entries evicts old PIV entries without touching OpenPGP.
        cache.replace_piv([(piv_k2.clone(), piv_meta(Slot::Signature, Some(11)))]);
        assert_eq!(cache.get(&piv_k1), None);
        assert_eq!(
            cache.get(&piv_k2),
            Some(CachedIdentity::Piv(piv_meta(Slot::Signature, Some(11))))
        );
        assert_eq!(
            cache.get(&pgp_k1),
            Some(CachedIdentity::OpenPgp(pgp_meta(KeyCrt::Auth, Some(20))))
        );
    }

    #[test]
    fn evict_and_clear_remove_expected_entries() {
        let cache = IdentityCache::new();
        let k1 = cred(1);
        let k2 = cred(2);

        cache.replace_piv([(k1.clone(), piv_meta(Slot::Authentication, Some(1)))]);
        cache.replace_openpgp([(k2.clone(), pgp_meta(KeyCrt::Sign, Some(2)))]);

        cache.evict(&k1);
        assert_eq!(cache.get(&k1), None);
        assert!(cache.get(&k2).is_some());

        cache.clear();
        assert_eq!(cache.get(&k2), None);
    }

    #[test]
    fn cloned_cache_shares_state_across_threads() {
        let cache_a = IdentityCache::new();
        let cache_b = cache_a.clone();
        let k1 = cred(9);
        let meta = piv_meta(Slot::CardAuthentication, Some(99));

        let k1_thread = k1.clone();
        std::thread::spawn(move || {
            cache_b.replace_piv([(k1_thread, meta)]);
        })
        .join()
        .unwrap();

        assert_eq!(cache_a.get(&k1), Some(CachedIdentity::Piv(meta)));
    }
}
