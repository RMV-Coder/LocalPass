//! Offline sync by animated QR codes (`docs/specs/qr-transport.md`).
//!
//! One device shows a stream of QR codes, the other films it. The stream is
//! one-way, so it carries a RaptorQ fountain code: any large-enough subset of
//! frames, in any order, rebuilds the data. What it carries is a **bundle** —
//! signed vault-key shares and the ops the receiver lacks, in the nearby link's
//! encodings — and an optional still **"what I have"** code lets the receiver
//! tell the sender which ops it already holds.
//!
//! # What this module does and does not own
//!
//! - [`bundle`] builds a bundle from the unlocked session and ingests a
//!   received one: shares through `lp-vault`'s signed-share import, ops through
//!   [`crate::engine::ingest`] — the §5 verifier and §4 merge every transport
//!   uses. Nothing here decides whether an op or a share is genuine.
//! - [`have`] encodes and parses the "what I have" code.
//! - [`frame`] is the frame codec and the fountain code over plain bytes. It
//!   knows nothing about cameras, QR rendering or vaults, so the GUI drives it
//!   from the webview's decoded codes and tests drive it with dropped,
//!   shuffled and duplicated frames.
//!
//! The channel is untrusted: every field a camera can see is checked before
//! it is used ([`frame`]'s module docs list the checks), and the header, the
//! frames and the "what I have" code are advisory.

pub mod bundle;
pub mod frame;
pub mod have;

pub use bundle::{Bundle, ExportOptions, ExportSummary, ImportReport, VaultImport};
pub use frame::{FrameDecoder, FrameEncoder, FrameHeader, FrameOutcome, Progress};
pub use have::{HaveCode, Heads};

/// The protocol version carried by every frame, bundle and code.
pub const PROTOCOL_VERSION: u8 = 1;

/// The largest bundle a transfer may carry (`qr-transport.md` §8).
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// The smallest symbol size a frame may declare.
pub const MIN_SYMBOL_SIZE: u16 = 256;

/// The largest symbol size a frame may declare: QR version 40-L carries 2953
/// bytes in byte mode, minus [`FRAME_OVERHEAD`].
pub const MAX_SYMBOL_SIZE: u16 = 2928;

/// Bytes a frame adds around its symbol: a 21-byte header and a 4-byte CRC.
pub const FRAME_OVERHEAD: usize = 25;

/// The most source symbols a transfer may have. `MAX_BUNDLE_BYTES /
/// MIN_SYMBOL_SIZE` is exactly this, and RaptorQ's own limit (56 403) is above
/// it.
pub const MAX_SOURCE_SYMBOLS: u32 = 32_768;

/// Distinct symbols held beyond `K` before a transfer is abandoned. RaptorQ
/// decodes from `K + 2` with probability about 99.9999%, so reaching this
/// means the symbols are not from one consistent bundle.
pub const MAX_EXTRA_SYMBOLS: u32 = 64;

/// The largest "what I have" code: QR version 40-L's byte-mode capacity.
pub const MAX_HAVE_BYTES: usize = 2953;

/// The symbol size of the GUI's default "large" stream: a byte-mode QR code
/// of version 25, level L (1273 bytes) minus [`FRAME_OVERHEAD`]
/// (`qr-transport.md` §7.2). Receivers accept any size within the caps.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1248;

/// Send `bundle` as frames: a [`FrameEncoder`] whose transfer id is the
/// bundle's own (`qr-transport.md` §6.2).
///
/// # Errors
///
/// [`crate::Error::Qr`] if `bundle` is not a well-formed bundle or the symbol
/// size is out of range.
pub fn encoder_for(bundle: &[u8], symbol_size: u16) -> crate::Result<FrameEncoder> {
    let parsed = bundle::parse(bundle)?;
    FrameEncoder::new(parsed.transfer_id, bundle, symbol_size)
}
