//! The applet's reference-data secrets: the application PIN and the PUK.

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum VerifiedState {
    /// The pin was never verified
    #[default]
    Never,
    /// The pin was verified once this session
    Session,
    /// The pin was verified by the previous APDU
    Previous,
    /// The pin was verified by this APDU
    Now,
}

impl VerifiedState {
    /// Returns true when the pin was verified at least once in the session.
    fn is_verified(self) -> bool {
        !matches!(self, Self::Never)
    }

    /// A more strict check that only accepts the verified state when it was verified by the previous APDU
    fn is_verified_previous(self) -> bool {
        matches!(self, Self::Previous)
    }
}

/// One PIV reference-data state.
///
/// The value and the counter live for the applet's life; `verified` lives
/// only as long as the session — set by a successful check, cleared by the
/// card's reset points (an unverify, an unblock, a fresh instance) — and is
/// what the card's security-status sync consults when the key slots land.
pub(crate) struct Pin {
    /// The stored value: six ASCII digits plus two 0xFF padding bytes (the
    /// eight-character PUK has no padding).
    value: Zeroizing<[u8; 8]>,
    /// The retry limit the factory (or SET PIN RETRIES) configured.
    max_tries: u8,
    /// Tries remaining; 0 means blocked.
    tries: u8,
    verified_state: VerifiedState,
}

impl Pin {
    pub(crate) fn tries(&self) -> u8 {
        self.tries
    }

    pub(crate) fn max_tries(&self) -> u8 {
        self.max_tries
    }

    pub(crate) fn is_default(&self, default_value: &[u8]) -> bool {
        *self.value == default_value
    }

    pub(crate) fn verified(&self) -> bool {
        self.verified_state.is_verified()
    }

    pub(crate) fn verified_previous(&self) -> bool {
        self.verified_state.is_verified_previous()
    }

    /// Factory-fresh state: the stored value, the counter at its limit, not
    /// verified.
    pub(crate) fn factory(value: [u8; 8], max_tries: u8) -> Self {
        Self {
            value: Zeroizing::new(value),
            max_tries,
            tries: max_tries,
            verified_state: VerifiedState::default(),
        }
    }

    /// Compare `presented` to the stored value in
    /// constant time. A correct value sets `verified` and restores the
    /// counter to its limit; a wrong one burns a try and leaves `verified`
    /// untouched. Callers must not call this while blocked.
    pub(crate) fn check(&mut self, presented: &[u8]) -> bool {
        let ok = ct_eq(presented, &self.value[..]);
        if ok {
            self.verified_state = VerifiedState::Now;
            self.tries = self.max_tries;
        } else {
            self.tries -= 1;
        }
        ok
    }

    pub(crate) fn session_end(&mut self) {
        self.verified_state = VerifiedState::Never;
    }

    /// Downgrade the verified state.
    ///
    /// If the state was verified by the current APDU, then it is downgraded to [`VerifiedState::Previous`].
    /// If the state is [`VerifiedState::Previous`], then it is downgraded to [`VerifiedState::Session`].
    ///
    /// Anything else leves the verified state untouched.
    pub(crate) fn downgrade(&mut self) {
        self.verified_state = match self.verified_state {
            VerifiedState::Never | VerifiedState::Session => return,
            VerifiedState::Previous => VerifiedState::Session,
            VerifiedState::Now => VerifiedState::Previous,
        };
    }

    /// Reset the counter back to its limit, `verified` cleared.
    pub(crate) fn reset(&mut self) {
        self.tries = self.max_tries;
        self.verified_state = VerifiedState::Never;
    }

    /// Replace the stored value; the counter and `verified` are untouched.
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
