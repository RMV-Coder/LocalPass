//! The sync engine's error type and the typed **ingest alarms**
//! (sync-protocol.md §5).
//!
//! # No secret leakage
//!
//! No variant carries decrypted plaintext, key material, or a password. Op
//! payloads are ciphertext until the merge decrypts them under the VaultKey, and
//! a decrypt failure surfaces as [`Alarm::SignatureInvalid`] /
//! [`Error::Vault`]`(DecryptionFailed)` with no plaintext attached.

use lp_vault::ids::DeviceId;

/// A typed ingest alarm (sync-protocol.md §5): a per-op verification failure
/// that quarantines the offending device's op **and everything after it**, and
/// is surfaced to the user (PRD §8 T13 "peers detect regression and alarm").
///
/// A *gap* (an as-yet-unreceived earlier `seq`) is **not** an alarm — it is held
/// pending (see [`crate::verify::DeviceOutcome::Pending`]). Only a definite
/// tamper/replay/regression alarms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alarm {
    /// The Ed25519 signature did not verify under the author device's pinned
    /// public key (fields 1..10; sync-protocol.md §5 step 1). Forgery / tamper.
    SignatureInvalid,
    /// The op's `device_id` is not a trusted peer (`peer_devices`); an unknown
    /// device is rejected outright (sync-protocol.md §5 step 1 / §6).
    UnknownDevice,
    /// The op's `seq` went *backwards* relative to what we have recorded for
    /// this device — a rollback attempt (sync-protocol.md §5 step 2 / T13).
    SeqRegression,
    /// The op's `seq` repeats a `seq` we already hold **with different bytes**
    /// (a genuine replay/fork; an identical re-read is an idempotent no-op, not
    /// this). (sync-protocol.md §5 step 2.)
    SeqReplay,
    /// The op's `prev_hash` does not equal the recomputed hash of the author's
    /// previous op — a rewritten/forked history (sync-protocol.md §5 step 3).
    ChainMismatch,
    /// The op's `lamport` is less than the author's previous op's lamport —
    /// a non-monotone author clock (sync-protocol.md §5 step 4).
    LamportRegression,
}

impl Alarm {
    /// A short, stable, secret-free label for this alarm (for `--json` / logs).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Alarm::SignatureInvalid => "signature_invalid",
            Alarm::UnknownDevice => "unknown_device",
            Alarm::SeqRegression => "seq_regression",
            Alarm::SeqReplay => "seq_replay",
            Alarm::ChainMismatch => "chain_mismatch",
            Alarm::LamportRegression => "lamport_regression",
        }
    }
}

impl core::fmt::Display for Alarm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let human = match self {
            Alarm::SignatureInvalid => "invalid op signature (forgery or tamper)",
            Alarm::UnknownDevice => "op from an untrusted device",
            Alarm::SeqRegression => "sequence regression (rollback)",
            Alarm::SeqReplay => "sequence replay / fork",
            Alarm::ChainMismatch => "hash-chain mismatch (rewritten history)",
            Alarm::LamportRegression => "Lamport clock regression",
        };
        f.write_str(human)
    }
}

/// A quarantine record: a device whose ingest halted at some `seq` with a
/// specific alarm (sync-protocol.md §5). Everything from `seq` onward for that
/// device is withheld until the operator resolves the alarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quarantine {
    /// The offending author device.
    pub device_id: DeviceId,
    /// The `seq` at which ingest halted (this op and all later ones are held).
    pub seq: u64,
    /// Why it halted.
    pub alarm: Alarm,
}

/// Errors from the sync engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A storage / crypto failure bubbled up from `lp-vault` (never carries a
    /// secret; see `lp_vault::Error`).
    #[error("vault error: {0}")]
    Vault(#[from] lp_vault::Error),

    /// A filesystem error while reading/writing sync segments, manifest, or key
    /// blobs.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A malformed on-disk sync artifact (a truncated segment, a bad file name,
    /// an unparseable manifest). Carries a static, secret-free description.
    #[error("malformed sync data: {0}")]
    Malformed(&'static str),

    /// A `(de)serialization` failure of a plaintext control artifact (manifest,
    /// identity string). Never a secret.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A logical/usage error: the vault is not enrolled for sync, a device is
    /// not trusted, an identity string is malformed, etc.
    #[error("invalid operation: {0}")]
    Invalid(&'static str),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

/// Convenience alias for `Result<T, `[`Error`]`>`.
pub type Result<T> = core::result::Result<T, Error>;
