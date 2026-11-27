use std::sync::{Arc, Mutex, PoisonError};

use keyroost_openpgp::{AlgorithmAttributes, KeyCrt};

use crate::protocol::gpg::keygrip::Keygrip;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GpgCachedKey {
    pub(crate) slot: KeyCrt,
    pub(crate) attrs: AlgorithmAttributes,
    pub(crate) aid: Vec<u8>,
    pub(crate) serial: Option<u128>,
}

#[derive(Clone, Default)]
pub(crate) struct GpgKeyCache {
    entries: Arc<Mutex<Vec<(Keygrip, GpgCachedKey)>>>,
}

impl GpgKeyCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, keygrip: &Keygrip) -> Option<GpgCachedKey> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .find(|(kg, _)| kg == keygrip)
            .map(|(_, cached)| cached.clone())
    }

    #[allow(dead_code)]
    pub(crate) fn all(&self) -> Vec<(Keygrip, GpgCachedKey)> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clone()
    }

    pub(crate) fn replace(&self, items: impl IntoIterator<Item = (Keygrip, GpgCachedKey)>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clear();
        entries.extend(items);
    }

    #[allow(dead_code)]
    pub(crate) fn evict(&self, keygrip: &Keygrip) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|(kg, _)| kg != keygrip);
    }

    pub(crate) fn clear(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{GpgCachedKey, GpgKeyCache};
    use crate::protocol::gpg::keygrip::Keygrip;
    use keyroost_openpgp::{AlgorithmAttributes, Curve, EccKind, KeyCrt};
    use std::str::FromStr;

    fn keygrip(hex_byte: &str) -> Keygrip {
        Keygrip::from_str(&hex_byte.repeat(20)).expect("valid test keygrip")
    }

    fn cached(slot: KeyCrt, serial: Option<u128>) -> GpgCachedKey {
        GpgCachedKey {
            slot,
            attrs: AlgorithmAttributes::Ecc {
                kind: EccKind::EdDsa,
                curve: Curve::Ed25519,
                import_with_public_key: false,
            },
            aid: vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01],
            serial,
        }
    }

    #[test]
    fn empty_cache_returns_none_and_empty_all() {
        let cache = GpgKeyCache::new();
        assert_eq!(cache.get(&keygrip("11")), None);
        assert_eq!(cache.all(), Vec::new());
    }

    #[test]
    fn replace_all_evict_and_clear_behave_as_expected() {
        let cache = GpgKeyCache::new();
        let kg1 = keygrip("11");
        let kg2 = keygrip("22");
        let kg3 = keygrip("33");

        let meta1 = cached(KeyCrt::Sign, Some(10));
        let meta2 = cached(KeyCrt::Decrypt, Some(10));
        let meta3 = cached(KeyCrt::Auth, Some(20));

        cache.replace([(kg1, meta1.clone()), (kg2, meta2.clone())]);
        assert_eq!(cache.get(&kg1), Some(meta1.clone()));
        assert_eq!(cache.get(&kg2), Some(meta2.clone()));
        assert_eq!(cache.all(), vec![(kg1, meta1.clone()), (kg2, meta2.clone())]);

        cache.evict(&kg1);
        assert_eq!(cache.get(&kg1), None);
        assert_eq!(cache.all(), vec![(kg2, meta2)]);

        cache.replace([(kg3, meta3.clone())]);
        assert_eq!(cache.get(&kg2), None);
        assert_eq!(cache.get(&kg3), Some(meta3));

        cache.clear();
        assert_eq!(cache.all(), Vec::new());
        assert_eq!(cache.get(&kg3), None);
    }

    #[test]
    fn cloned_cache_shares_state_across_threads() {
        let cache_a = GpgKeyCache::new();
        let cache_b = cache_a.clone();
        let kg = keygrip("AB");
        let meta = cached(KeyCrt::Sign, Some(42));
        let meta_expected = meta.clone();

        std::thread::spawn(move || {
            cache_b.replace([(kg, meta)]);
        })
        .join()
        .unwrap();

        assert_eq!(cache_a.get(&kg), Some(meta_expected));
    }
}
