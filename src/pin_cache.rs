use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use keyroost_transport::TransportError;
use ssh_agent_lib::secrecy::{ExposeSecret, SecretBox};

use crate::pinentry::{Applet, Pinentry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PinCacheKey {
    applet: Applet,
    serial: Option<u128>,
}

struct PinCacheEntry {
    pin: SecretBox<str>,
    created_at: Instant,
    expires_at: Instant,
}

struct PinCacheInner {
    ttl: Duration,
    max_ttl: Option<Duration>,
    entries: HashMap<PinCacheKey, PinCacheEntry>,
}

impl PinCacheInner {
    fn is_expired(&self, entry: &PinCacheEntry, now: Instant) -> bool {
        if now >= entry.expires_at {
            return true;
        }
        if let Some(max_ttl) = self.max_ttl
            && now >= entry.created_at + max_ttl
        {
            return true;
        }
        false
    }
}

#[derive(Clone)]
pub(crate) struct PinCache {
    inner: Arc<Mutex<PinCacheInner>>,
}

impl PinCache {
    #[allow(dead_code)]
    pub(crate) fn new(ttl: Duration, max_ttl: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PinCacheInner {
                ttl,
                max_ttl: max_ttl.filter(|d| !d.is_zero()),
                entries: HashMap::new(),
            })),
        }
    }

    pub(crate) fn get(&self, applet: Applet, serial: Option<u128>) -> Option<SecretBox<str>> {
        self.get_at(applet, serial, Instant::now())
    }

    pub(crate) fn touch(&self, applet: Applet, serial: Option<u128>) {
        self.touch_at(applet, serial, Instant::now());
    }

    pub(crate) fn insert(&self, applet: Applet, serial: Option<u128>, pin: SecretBox<str>) {
        self.insert_at(applet, serial, pin, Instant::now());
    }

    pub(crate) fn evict(&self, applet: Applet, serial: Option<u128>) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.entries.remove(&PinCacheKey { applet, serial });
    }

    #[allow(dead_code)]
    pub(crate) fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.entries.clear();
    }

    #[cfg(test)]
    pub(crate) fn expires_at(&self, applet: Applet, serial: Option<u128>) -> Option<Instant> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner
            .entries
            .get(&PinCacheKey { applet, serial })
            .map(|entry| entry.expires_at)
    }

    fn get_at(&self, applet: Applet, serial: Option<u128>, now: Instant) -> Option<SecretBox<str>> {
        let key = PinCacheKey { applet, serial };
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = inner
            .entries
            .get(&key)
            .is_some_and(|entry| inner.is_expired(entry, now));
        if expired {
            inner.entries.remove(&key);
            return None;
        }
        inner
            .entries
            .get(&key)
            .map(|entry| SecretBox::from(Box::<str>::from(entry.pin.expose_secret())))
    }

    fn touch_at(&self, applet: Applet, serial: Option<u128>, now: Instant) {
        let key = PinCacheKey { applet, serial };
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let ttl = inner.ttl;
        let max_ttl = inner.max_ttl;

        if let Some(entry) = inner.entries.get_mut(&key) {
            if let Some(max_ttl) = max_ttl {
                let max_expiry = entry.created_at + max_ttl;
                if now >= max_expiry {
                    inner.entries.remove(&key);
                } else {
                    entry.expires_at = (now + ttl).min(max_expiry);
                }
            } else {
                entry.expires_at = now + ttl;
            }
        }
    }

    fn insert_at(&self, applet: Applet, serial: Option<u128>, pin: SecretBox<str>, now: Instant) {
        let key = PinCacheKey { applet, serial };
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let sliding_expiry = now + inner.ttl;
        let expires_at = match inner.max_ttl {
            Some(max_ttl) => sliding_expiry.min(now + max_ttl),
            None => sliding_expiry,
        };
        inner.entries.insert(
            key,
            PinCacheEntry {
                pin,
                created_at: now,
                expires_at,
            },
        );
    }
}

pub(crate) fn verify_pin_with_cache(
    applet: Applet,
    serial: Option<u128>,
    allow_cache: bool,
    pin_cache: Option<&PinCache>,
    pinentry: &impl Pinentry,
    mut verify: impl FnMut(&[u8]) -> Result<(), TransportError>,
    is_wrong_pin: impl Fn(&TransportError) -> bool,
) -> Result<bool, crate::Error> {
    if allow_cache
        && let Some(cache) = pin_cache
        && let Some(cached_pin) = cache.get(applet, serial)
    {
        match verify(cached_pin.expose_secret().as_bytes()) {
            Ok(()) => {
                cache.touch(applet, serial);
                return Ok(true);
            }
            Err(err) if is_wrong_pin(&err) => {
                tracing::debug!(
                    %applet,
                    ?serial,
                    "cached PIN rejected by card, evicting and re-prompting"
                );
                cache.evict(applet, serial);
            }
            Err(err) => {
                cache.evict(applet, serial);
                return Err(err.into());
            }
        }
    }

    let Some(fresh_pin) = pinentry.prompt_pin(applet, serial)? else {
        return Ok(false);
    };
    verify(fresh_pin.expose_secret().as_bytes())?;
    if allow_cache && let Some(cache) = pin_cache {
        cache.insert(applet, serial, fresh_pin);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(pin: &str) -> SecretBox<str> {
        SecretBox::from(Box::<str>::from(pin))
    }

    fn entry_count(cache: &PinCache) -> usize {
        cache
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    #[test]
    fn miss_on_empty_cache() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let now = Instant::now();
        assert!(cache.get_at(Applet::Piv, Some(1), now).is_none());
        assert!(cache.get_at(Applet::OpenPgp, None, now).is_none());
    }

    #[test]
    fn insert_and_get_hit() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let now = Instant::now();
        cache.insert_at(Applet::Piv, Some(42), secret("123456"), now);

        let hit = cache.get_at(Applet::Piv, Some(42), now);
        assert_eq!(hit.as_ref().map(ExposeSecret::expose_secret), Some("123456"));
    }

    #[test]
    fn get_does_not_refresh_sliding_ttl() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

        // Lookup near expiry should succeed but NOT extend TTL.
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(50))
                .is_some()
        );
        // At t0 + 60s, entry must be expired.
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(60))
                .is_none()
        );
        assert_eq!(entry_count(&cache), 0);
    }

    #[test]
    fn sliding_ttl_extends_on_touch() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

        // Touch at t0 + 40s -> expires_at becomes t0 + 100s.
        cache.touch_at(Applet::Piv, Some(1), t0 + Duration::from_secs(40));

        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(99))
                .is_some()
        );
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(100))
                .is_none()
        );
        assert_eq!(entry_count(&cache), 0);
    }

    #[test]
    fn expires_after_sliding_ttl_and_lazily_evicts() {
        let cache = PinCache::new(Duration::from_secs(30), None);
        let t0 = Instant::now();
        cache.insert_at(Applet::OpenPgp, Some(7), secret("abcdef"), t0);
        assert_eq!(entry_count(&cache), 1);

        assert!(
            cache
                .get_at(Applet::OpenPgp, Some(7), t0 + Duration::from_secs(29))
                .is_some()
        );
        assert!(
            cache
                .get_at(Applet::OpenPgp, Some(7), t0 + Duration::from_secs(30))
                .is_none()
        );
        assert_eq!(entry_count(&cache), 0);
    }

    #[test]
    fn max_ttl_caps_touch_and_expires_at_created_plus_max_ttl() {
        let cache = PinCache::new(Duration::from_secs(60), Some(Duration::from_secs(100)));
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

        // Touch at t0 + 50s would slide to t0 + 110s, but must be capped at t0 + 100s.
        cache.touch_at(Applet::Piv, Some(1), t0 + Duration::from_secs(50));

        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(99))
                .is_some()
        );
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(100))
                .is_none()
        );
        assert_eq!(entry_count(&cache), 0);
    }

    #[test]
    fn max_ttl_smaller_than_ttl_caps_initial_expiry() {
        let cache = PinCache::new(Duration::from_secs(60), Some(Duration::from_secs(20)));
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(19))
                .is_some()
        );
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(20))
                .is_none()
        );
    }

    #[test]
    fn touch_past_max_ttl_evicts_entry() {
        let cache = PinCache::new(Duration::from_secs(60), Some(Duration::from_secs(100)));
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

        cache.touch_at(Applet::Piv, Some(1), t0 + Duration::from_secs(100));
        assert_eq!(entry_count(&cache), 0);
        assert!(
            cache
                .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(100))
                .is_none()
        );
    }

    #[test]
    fn unbounded_sliding_when_max_ttl_is_none_or_zero() {
        for max_ttl in [None, Some(Duration::ZERO)] {
            let cache = PinCache::new(Duration::from_secs(60), max_ttl);
            let t0 = Instant::now();
            cache.insert_at(Applet::Piv, Some(1), secret("123456"), t0);

            for step in 1..=10 {
                let t = t0 + Duration::from_secs(50 * step);
                assert!(cache.get_at(Applet::Piv, Some(1), t).is_some());
                cache.touch_at(Applet::Piv, Some(1), t);
            }

            // Still valid 50s after the 10th touch (t0 + 550s).
            assert!(
                cache
                    .get_at(Applet::Piv, Some(1), t0 + Duration::from_secs(550))
                    .is_some()
            );
        }
    }

    #[test]
    fn evict_removes_only_targeted_entry() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("piv1"), t0);
        cache.insert_at(Applet::Piv, Some(2), secret("piv2"), t0);
        cache.insert_at(Applet::OpenPgp, Some(1), secret("pgp1"), t0);

        cache.evict(Applet::Piv, Some(1));

        assert!(cache.get_at(Applet::Piv, Some(1), t0).is_none());
        assert_eq!(
            cache
                .get_at(Applet::Piv, Some(2), t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("piv2")
        );
        assert_eq!(
            cache
                .get_at(Applet::OpenPgp, Some(1), t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("pgp1")
        );
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let t0 = Instant::now();
        cache.insert_at(Applet::Piv, Some(1), secret("piv1"), t0);
        cache.insert_at(Applet::OpenPgp, None, secret("pgp"), t0);

        cache.clear();

        assert_eq!(entry_count(&cache), 0);
        assert!(cache.get_at(Applet::Piv, Some(1), t0).is_none());
        assert!(cache.get_at(Applet::OpenPgp, None, t0).is_none());
    }

    #[test]
    fn isolation_between_applets_and_serials() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let t0 = Instant::now();

        cache.insert_at(Applet::Piv, None, secret("piv-none"), t0);
        cache.insert_at(Applet::Piv, Some(100), secret("piv-100"), t0);
        cache.insert_at(Applet::OpenPgp, None, secret("pgp-none"), t0);
        cache.insert_at(Applet::OpenPgp, Some(100), secret("pgp-100"), t0);

        assert_eq!(
            cache
                .get_at(Applet::Piv, None, t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("piv-none")
        );
        assert_eq!(
            cache
                .get_at(Applet::Piv, Some(100), t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("piv-100")
        );
        assert_eq!(
            cache
                .get_at(Applet::OpenPgp, None, t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("pgp-none")
        );
        assert_eq!(
            cache
                .get_at(Applet::OpenPgp, Some(100), t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("pgp-100")
        );
        assert!(cache.get_at(Applet::Piv, Some(200), t0).is_none());
    }

    #[test]
    fn cloned_cache_shares_state() {
        let cache_a = PinCache::new(Duration::from_secs(60), None);
        let cache_b = cache_a.clone();
        let t0 = Instant::now();

        cache_a.insert_at(Applet::Piv, Some(1), secret("shared"), t0);
        assert_eq!(
            cache_b
                .get_at(Applet::Piv, Some(1), t0)
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("shared")
        );

        cache_b.evict(Applet::Piv, Some(1));
        assert!(cache_a.get_at(Applet::Piv, Some(1), t0).is_none());
    }
}
