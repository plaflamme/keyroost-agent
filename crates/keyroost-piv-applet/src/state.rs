//! The applet's reference-data secrets: the application PIN and the PUK.

use zeroize::Zeroizing;

/// One PIV reference-data secret — the application PIN or the PUK — as the
/// card's `JavaCard` `OwnerPIN` objects model it: the stored 8-byte value, the
/// tries-remaining counter, and the session-verified flag.
///
/// The value and the counter live for the applet's life; `verified` lives
/// only as long as the session — set by a successful check, cleared by the
/// card's reset points (an unverify, an unblock, a fresh instance) — and is
/// what the card's security-status sync consults when the key slots land.
pub(crate) struct Pin {
    /// The stored value: six ASCII digits plus two 0xFF padding bytes (the
    /// eight-character PUK has no padding).
    pub(crate) value: Zeroizing<[u8; 8]>,
    /// The retry limit the factory (or SET PIN RETRIES) configured.
    pub(crate) max_tries: u8,
    /// Tries remaining; 0 means blocked.
    pub(crate) tries: u8,
    /// Session-verified: set by a successful check, cleared by the card's
    /// reset points.
    pub(crate) verified: bool,
}

impl Pin {
    /// Factory-fresh state: the stored value, the counter at its limit, not
    /// verified.
    pub(crate) fn factory(value: [u8; 8], max_tries: u8) -> Self {
        Self {
            value: Zeroizing::new(value),
            max_tries,
            tries: max_tries,
            verified: false,
        }
    }

    /// `JavaCard` `OwnerPIN.check`: compare `presented` to the stored value in
    /// constant time. A correct value sets `verified` and restores the
    /// counter to its limit; a wrong one burns a try and leaves `verified`
    /// untouched. Callers must not call this while blocked.
    pub(crate) fn check(&mut self, presented: &[u8]) -> bool {
        let ok = ct_eq(presented, &self.value[..]);
        if ok {
            self.verified = true;
            self.tries = self.max_tries;
        } else {
            self.tries -= 1;
        }
        ok
    }

    /// `JavaCard` `OwnerPIN.reset` / `resetAndUnblock`: the counter back to
    /// its limit, `verified` cleared.
    pub(crate) fn reset(&mut self) {
        self.tries = self.max_tries;
        self.verified = false;
    }

    /// `JavaCard` `OwnerPIN.update`: replace the stored value; the counter and
    /// `verified` are untouched.
    pub(crate) fn set_value(&mut self, value: [u8; 8]) {
        *self.value = value;
    }
}

/// Byte-wise equality, constant time over the input — the same fold the
/// transport layer uses, so a wrong reference leaks neither which byte
/// differs nor how far the match ran.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
