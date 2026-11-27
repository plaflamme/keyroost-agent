pub(crate) mod openpgp;
pub(crate) mod piv;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CardOperationOutcome<T> {
    /// Operation completed and produced a value (e.g. raw signature or decrypted bytes).
    Completed(T),
    /// User cancelled the PIN prompt.
    UserCancelled,
    /// Expected card or slot was not found (e.g. serial mismatch or stale APDU);
    /// callers may trigger a fresh key scan.
    NotFound,
}
