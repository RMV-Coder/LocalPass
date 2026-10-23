//! Direct device-to-device sync over the local network
//! (`docs/specs/lan-transport.md`).
//!
//! Two devices that already pinned each other (`sync-protocol.md` §6) open a
//! Noise XX link and run a six-round exchange over it: vault-key shares,
//! inventories of per-device seq heads, the ops each side lacks, the attachment
//! blobs each side lacks, and a closing `DONE`. Nothing here decides what an op
//! means — received ops go through [`crate::engine::ingest`], the same §5
//! verifier and §4 merge a file `pull` uses.
//!
//! # What this module does and does not own
//!
//! - It owns the **handshake** (identity proofs over the Noise transcript,
//!   checked against `peer_devices` before any application data is read), the
//!   **record layer** (framing, size caps, deadlines) and the **exchange**.
//! - It does **not** own sockets. [`run`] takes any [`Stream`] (a
//!   [`std::net::TcpStream`] in production) and a [`Local`] that lends it the
//!   unlocked [`lp_vault::Session`] for each local step. The daemon's listener
//!   and dialer, the address policy and the listen window live in `lp-daemon`.
//! - It holds **no crypto primitive**: the Noise state machine is
//!   [`lp_crypto::NoiseHandshake`] / [`lp_crypto::NoiseTransport`], and the
//!   identity proof is signed by [`lp_vault::Session::sign_lan_handshake`].
//!
//! # Locking
//!
//! [`Local::with_session`] is called around each local step (signing a proof,
//! an inventory, one ingest batch, one blob read) and never across network I/O,
//! so a daemon can lend its session mutex without a slow peer ever holding it.

mod channel;
pub(crate) mod exchange;
pub(crate) mod message;

use std::io::{Read, Write};
use std::time::Duration;

use lp_vault::Session;
use lp_vault::ids::{DeviceId, VaultId};

use crate::error::{Quarantine, Result};

pub use channel::PROLOGUE;
pub use exchange::{Linked, handshake, run};

/// The protocol version, carried in the Noise prologue
/// (`lan-transport.md` §4.1).
pub const PROTOCOL_VERSION: u8 = 1;

/// The largest handshake message accepted (`lan-transport.md` §4.2). Real
/// messages are 32, 176 and 144 bytes.
pub const MAX_HANDSHAKE_MESSAGE: usize = 1024;

/// Most vault-key shares one `HELLO` may carry.
pub const MAX_SHARES: usize = 64;

/// Most vaults one `INVENTORY` may list.
pub const MAX_VAULTS: usize = 1024;

/// Most per-device heads one vault's inventory entry may list.
pub const MAX_HEADS: usize = 4096;

/// Most blob hashes one `BLOB_WANT` may list in total.
pub const MAX_WANTED_BLOBS: usize = 65_536;

/// How many op bytes a sender packs into one `OPS` message (a target, not a
/// cap: one op larger than this still goes alone).
pub const OPS_BATCH_BYTES: usize = 1024 * 1024;

/// How many op bytes a receiver buffers before running an ingest.
pub const INGEST_BUFFER_BYTES: usize = 32 * 1024 * 1024;

/// The deadlines a session runs under (`lan-transport.md` §5.4).
#[derive(Clone, Debug)]
pub struct Limits {
    /// The whole handshake, from the first byte to authenticated. Enforced as
    /// one deadline across every read, so a byte-trickling peer cannot extend
    /// it.
    pub handshake_timeout: Duration,
    /// After the handshake: the longest wait for the next record, and for
    /// writing one.
    pub record_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            record_timeout: Duration::from_secs(120),
        }
    }
}

/// A connected byte stream the session can put deadlines on.
///
/// [`run`] needs to bound every read and write; plain [`Read`] + [`Write`]
/// cannot express a timeout, so a stream also lets the session set its
/// per-call timeouts. Implemented for [`std::net::TcpStream`].
pub trait Stream: Read + Write {
    /// Set (or clear) the timeout for each read call.
    ///
    /// # Errors
    ///
    /// The underlying socket error.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;

    /// Set (or clear) the timeout for each write call.
    ///
    /// # Errors
    ///
    /// The underlying socket error.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl Stream for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, timeout)
    }
}

/// Lends the session its unlocked [`Session`], one local step at a time.
///
/// The daemon implements this over its state mutex (locking for the duration
/// of `f`, failing if the vault locked in the meantime); the CLI implements it
/// over a directly-unlocked session. `f` never performs network I/O.
pub trait Local {
    /// Run `f` against the unlocked session.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns, or an implementation-specific error when no
    /// unlocked session is available (e.g. the vault locked mid-session).
    fn with_session<R>(&self, f: impl FnOnce(&Session) -> Result<R>) -> Result<R>;
}

impl Local for Session {
    fn with_session<R>(&self, f: impl FnOnce(&Session) -> Result<R>) -> Result<R> {
        f(self)
    }
}

/// Which end of the connection this device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The side that connected (`--connect`). Writes first in every round.
    Initiator,
    /// The side that accepted (`--listen`).
    Responder,
}

/// What the caller asks of one session.
#[derive(Clone, Debug, Default)]
pub struct SessionOptions {
    /// Only complete the handshake with this pinned device. Required when
    /// `share` is non-empty (`lan-transport.md` §6.6).
    pub expected_peer: Option<DeviceId>,
    /// Vaults whose key to seal to the peer and send in `HELLO`.
    pub share: Vec<VaultId>,
    /// Deadlines.
    pub limits: Limits,
}

/// What one session did, from this device's side (`lan-transport.md` §6.7).
#[derive(Clone, Debug)]
pub struct SessionReport {
    /// The authenticated peer.
    pub peer: DeviceId,
    /// The peer's label in this device's `peer_devices`, if any.
    pub peer_label: Option<String>,
    /// One entry per vault both devices hold, ascending by vault id.
    pub vaults: Vec<VaultSyncReport>,
    /// Vaults whose key this device sent to the peer.
    pub shares_sent: Vec<VaultId>,
    /// Vaults the peer shared to this device that were newly adopted.
    pub shares_adopted: Vec<VaultId>,
    /// Shares the peer sent that were refused, with the reason (an alarm).
    pub shares_rejected: Vec<(VaultId, String)>,
}

impl SessionReport {
    /// Whether anything in the session is worth alarming on: a quarantine, a
    /// tampered blob, or a refused share.
    #[must_use]
    pub fn has_alarms(&self) -> bool {
        !self.shares_rejected.is_empty()
            || self
                .vaults
                .iter()
                .any(|v| !v.quarantines.is_empty() || !v.blobs_tampered.is_empty())
    }
}

/// Per vault: what was sent and what the §5 verifier did with what arrived.
#[derive(Clone, Debug)]
pub struct VaultSyncReport {
    /// The vault.
    pub vault_id: VaultId,
    /// Ops this device sent.
    pub ops_sent: usize,
    /// Ops received, verified and applied.
    pub applied: usize,
    /// Ops received that this device already held.
    pub skipped: usize,
    /// Ops received but held pending (an earlier op is missing).
    pub pending: usize,
    /// Devices the verifier quarantined (alarms).
    pub quarantines: Vec<Quarantine>,
    /// Attachment blobs this device sent.
    pub blobs_sent: usize,
    /// Attachment blobs received, re-hashed and stored.
    pub blobs_fetched: usize,
    /// Attachment blobs this device still lacks after the session.
    pub blobs_pending: usize,
    /// Hashes of received blobs whose content did not match (alarm).
    pub blobs_tampered: Vec<String>,
}

impl VaultSyncReport {
    fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            ops_sent: 0,
            applied: 0,
            skipped: 0,
            pending: 0,
            quarantines: Vec::new(),
            blobs_sent: 0,
            blobs_fetched: 0,
            blobs_pending: 0,
            blobs_tampered: Vec::new(),
        }
    }
}
