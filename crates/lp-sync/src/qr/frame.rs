//! Frames and the RaptorQ fountain code (`qr-transport.md` §5, §6, §8).
//!
//! A frame is one QR code's payload:
//!
//! ```text
//! "LQ" (2) || version (1) || transfer_id (8) || bundle_len u32 LE (4)
//!   || symbol_size u16 LE (2) || esi u32 LE (4) || symbol (T) || crc32 LE (4)
//! ```
//!
//! [`FrameEncoder`] turns a byte string into an endless supply of frames (the
//! `K` source symbols, then repair symbols). [`FrameDecoder`] collects frames
//! in any order, with any loss and any duplicates, and yields the byte string
//! once it holds enough of them.
//!
//! # Hostile input
//!
//! Everything a camera sees is attacker-controlled, and the `raptorq` crate
//! asserts (panics) on a wrong source block number, a symbol of the wrong
//! length, and transmission parameters outside RFC 6330's range. So every field
//! is checked here first: the frame length, magic, version and CRC before
//! anything is kept; the declared sizes against [`MAX_BUNDLE_BYTES`],
//! [`MIN_SYMBOL_SIZE`]..=[`MAX_SYMBOL_SIZE`] and [`MAX_SOURCE_SYMBOLS`] before a
//! decoder is built; the ESI against RaptorQ's 24-bit range before a symbol
//! reaches it. The decoder holds at most `K` + [`MAX_EXTRA_SYMBOLS`] distinct
//! symbols, so its memory is bounded by the declared bundle length.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder,
};

use super::{
    FRAME_OVERHEAD, MAX_BUNDLE_BYTES, MAX_EXTRA_SYMBOLS, MAX_SOURCE_SYMBOLS, MAX_SYMBOL_SIZE,
    MIN_SYMBOL_SIZE, PROTOCOL_VERSION,
};
use crate::error::{Error, Result};
use crate::identity::crc32;

/// The frame magic.
const FRAME_MAGIC: &[u8; 2] = b"LQ";
/// Bytes before the symbol.
const FRAME_HEADER_LEN: usize = 21;
/// RaptorQ encoding symbol ids are 24-bit (RFC 6330 §3.2).
const MAX_ESI: u32 = (1 << 24) - 1;

/// How long the receiver waits for a new symbol before giving up
/// (`qr-transport.md` §8).
pub const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest a whole transfer may take, from its first accepted frame.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Frames of another transfer tolerated without any progress before the
/// receiver stops.
pub const MAX_FOREIGN_FRAMES: u32 = 10_000;

/// The fixed fields every frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Which bundle this frame belongs to: the first 8 bytes of the bundle's
    /// hash field (`qr-transport.md` §6.2).
    pub transfer_id: [u8; 8],
    /// The length of the whole byte string being sent.
    pub bundle_len: u32,
    /// The RaptorQ symbol size `T`.
    pub symbol_size: u16,
    /// The encoding symbol id.
    pub esi: u32,
}

/// Number of source symbols `K` for a string of `len` bytes cut into
/// `symbol_size`-byte symbols, after the caps (`qr-transport.md` §8).
fn source_symbols(len: u32, symbol_size: u16) -> Result<u32> {
    if len == 0 || len as usize > MAX_BUNDLE_BYTES {
        return Err(Error::Qr("the declared transfer size is out of range"));
    }
    if !(MIN_SYMBOL_SIZE..=MAX_SYMBOL_SIZE).contains(&symbol_size) {
        return Err(Error::Qr("the declared symbol size is out of range"));
    }
    let k = len.div_ceil(u32::from(symbol_size));
    if k > MAX_SOURCE_SYMBOLS {
        return Err(Error::Qr("the transfer has too many pieces"));
    }
    Ok(k)
}

/// The RaptorQ transmission parameters for `(len, T)`: one source block, one
/// sub-block, alignment 1. Built only from values [`source_symbols`] accepted,
/// so the `raptorq` constructor's assertions cannot fire.
fn transmission(len: u32, symbol_size: u16) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::new(u64::from(len), symbol_size, 1, 1, 1)
}

/// Encode one frame.
fn encode_frame(header: &FrameHeader, symbol: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_OVERHEAD + symbol.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&header.transfer_id);
    out.extend_from_slice(&header.bundle_len.to_le_bytes());
    out.extend_from_slice(&header.symbol_size.to_le_bytes());
    out.extend_from_slice(&header.esi.to_le_bytes());
    out.extend_from_slice(symbol);
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// Decode and check one frame: its length, magic, version, CRC, declared
/// sizes and ESI. Returns the header and the symbol bytes.
///
/// # Errors
///
/// [`Error::Qr`] naming the first check that failed.
pub fn decode_frame(bytes: &[u8]) -> Result<(FrameHeader, &[u8])> {
    if bytes.len() < FRAME_OVERHEAD + usize::from(MIN_SYMBOL_SIZE)
        || bytes.len() > FRAME_OVERHEAD + usize::from(MAX_SYMBOL_SIZE)
    {
        return Err(Error::Qr("not a LocalPass transfer frame (wrong size)"));
    }
    if &bytes[..2] != FRAME_MAGIC {
        return Err(Error::Qr("not a LocalPass transfer frame"));
    }
    if bytes[2] != PROTOCOL_VERSION {
        return Err(Error::Qr(
            "the frame was made by a different LocalPass version",
        ));
    }
    let (body, crc) = bytes.split_at(bytes.len() - 4);
    if crc32(body).to_le_bytes() != crc {
        return Err(Error::Qr("the frame failed its checksum"));
    }
    let header = FrameHeader {
        transfer_id: body[3..11].try_into().expect("8 bytes"),
        bundle_len: u32::from_le_bytes(body[11..15].try_into().expect("4 bytes")),
        symbol_size: u16::from_le_bytes(body[15..17].try_into().expect("2 bytes")),
        esi: u32::from_le_bytes(body[17..21].try_into().expect("4 bytes")),
    };
    if body.len() - FRAME_HEADER_LEN != usize::from(header.symbol_size) {
        return Err(Error::Qr("the frame's symbol has the wrong length"));
    }
    source_symbols(header.bundle_len, header.symbol_size)?;
    if header.esi > MAX_ESI {
        return Err(Error::Qr("the frame's symbol id is out of range"));
    }
    Ok((header, &body[FRAME_HEADER_LEN..]))
}

/// Turns a byte string into frames: ESI `0..K` are the source symbols (the
/// data itself), ESI `K..` repair symbols, as many as the player wants.
pub struct FrameEncoder {
    transfer_id: [u8; 8],
    len: u32,
    symbol_size: u16,
    k: u32,
    encoder: SourceBlockEncoder,
}

impl FrameEncoder {
    /// An encoder for `data`, identified by `transfer_id`, cut into
    /// `symbol_size`-byte symbols.
    ///
    /// # Errors
    ///
    /// [`Error::Qr`] if `data` is empty or larger than [`MAX_BUNDLE_BYTES`], or
    /// `symbol_size` is outside [`MIN_SYMBOL_SIZE`]..=[`MAX_SYMBOL_SIZE`].
    pub fn new(transfer_id: [u8; 8], data: &[u8], symbol_size: u16) -> Result<Self> {
        let len = u32::try_from(data.len())
            .map_err(|_| Error::Qr("the transfer is too large to send by QR"))?;
        let k = source_symbols(len, symbol_size)?;
        let mut padded = data.to_vec();
        padded.resize(k as usize * usize::from(symbol_size), 0);
        let encoder = SourceBlockEncoder::new(0, &transmission(len, symbol_size), &padded);
        Ok(Self {
            transfer_id,
            len,
            symbol_size,
            k,
            encoder,
        })
    }

    /// The number of source symbols `K`: a receiver needs about this many
    /// distinct frames.
    #[must_use]
    pub fn source_symbols(&self) -> u32 {
        self.k
    }

    /// The transfer id every frame carries.
    #[must_use]
    pub fn transfer_id(&self) -> [u8; 8] {
        self.transfer_id
    }

    /// The highest ESI a frame can carry.
    #[must_use]
    pub fn max_esi(&self) -> u32 {
        MAX_ESI
    }

    /// The frames for ESI `start .. start + count` (clamped to the 24-bit ESI
    /// range).
    #[must_use]
    pub fn frames(&self, start: u32, count: u32) -> Vec<Vec<u8>> {
        let end = start.saturating_add(count).min(MAX_ESI + 1);
        if start >= end {
            return Vec::new();
        }
        let mut packets: Vec<EncodingPacket> = Vec::with_capacity((end - start) as usize);
        if start < self.k {
            let source = self.encoder.source_packets();
            packets.extend(
                source
                    .into_iter()
                    .skip(start as usize)
                    .take((end.min(self.k) - start) as usize),
            );
        }
        let repair_from = start.max(self.k);
        if repair_from < end {
            packets.extend(
                self.encoder
                    .repair_packets(repair_from - self.k, end - repair_from),
            );
        }
        packets
            .into_iter()
            .map(|p| {
                let (id, symbol) = p.split();
                encode_frame(
                    &FrameHeader {
                        transfer_id: self.transfer_id,
                        bundle_len: self.len,
                        symbol_size: self.symbol_size,
                        esi: id.encoding_symbol_id(),
                    },
                    &symbol,
                )
            })
            .collect()
    }
}

/// What happened to one frame handed to [`FrameDecoder::push`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameOutcome {
    /// A new symbol, kept.
    Accepted,
    /// A symbol already held (or one beyond the cap), dropped.
    Duplicate,
    /// A valid frame of a different transfer, dropped.
    OtherTransfer,
    /// Not a valid frame (size, magic, version, checksum or a declared size
    /// out of range), dropped.
    Invalid,
    /// The transfer already finished, failed or timed out.
    Ignored,
}

/// Where a transfer stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// The transfer the decoder locked onto, once a valid frame arrived.
    pub transfer_id: Option<[u8; 8]>,
    /// Its declared length.
    pub bundle_len: u32,
    /// Distinct symbols held.
    pub received: u32,
    /// Source symbols `K`: about this many are needed.
    pub needed: u32,
    /// Frames accepted, duplicate, of another transfer, or invalid so far.
    pub accepted: u32,
    /// Duplicate frames dropped.
    pub duplicates: u32,
    /// Frames of another transfer dropped.
    pub other_transfer: u32,
    /// Invalid frames dropped.
    pub invalid: u32,
    /// The data is complete and ready ([`FrameDecoder::take`]).
    pub complete: bool,
    /// The transfer stopped without completing, and why.
    pub failed: Option<&'static str>,
}

struct Locked {
    header: FrameHeader,
    k: u32,
    decoder: SourceBlockDecoder,
    held: BTreeSet<u32>,
    queued: Vec<EncodingPacket>,
    started: Instant,
    last_progress: Instant,
}

/// Collects frames and rebuilds the byte string (`qr-transport.md` §5.3).
#[derive(Default)]
pub struct FrameDecoder {
    locked: Option<Locked>,
    result: Option<Vec<u8>>,
    progress: Progress,
    foreign_since_progress: u32,
}

impl FrameDecoder {
    /// A decoder that has not seen a frame yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check and queue one frame. The first valid frame fixes the transfer;
    /// call [`decode`](Self::decode) after a batch to try to finish.
    pub fn push(&mut self, frame: &[u8], now: Instant) -> FrameOutcome {
        if self.progress.complete || self.progress.failed.is_some() {
            return FrameOutcome::Ignored;
        }
        let Ok((header, symbol)) = decode_frame(frame) else {
            self.progress.invalid += 1;
            return FrameOutcome::Invalid;
        };
        let locked = match &mut self.locked {
            Some(l) => l,
            None => {
                let k = source_symbols(header.bundle_len, header.symbol_size)
                    .expect("decode_frame checked the declared sizes");
                let oti = transmission(header.bundle_len, header.symbol_size);
                let block_len = u64::from(k) * u64::from(header.symbol_size);
                self.progress.transfer_id = Some(header.transfer_id);
                self.progress.bundle_len = header.bundle_len;
                self.progress.needed = k;
                self.locked.insert(Locked {
                    header,
                    k,
                    decoder: SourceBlockDecoder::new(0, &oti, block_len),
                    held: BTreeSet::new(),
                    queued: Vec::new(),
                    started: now,
                    last_progress: now,
                })
            }
        };
        let same = header.transfer_id == locked.header.transfer_id
            && header.bundle_len == locked.header.bundle_len
            && header.symbol_size == locked.header.symbol_size;
        if !same {
            self.progress.other_transfer += 1;
            self.foreign_since_progress += 1;
            if self.foreign_since_progress >= MAX_FOREIGN_FRAMES {
                self.progress.failed = Some("another transfer's codes kept appearing");
            }
            return FrameOutcome::OtherTransfer;
        }
        if locked.held.len() as u32 >= locked.k + MAX_EXTRA_SYMBOLS
            || !locked.held.insert(header.esi)
        {
            self.progress.duplicates += 1;
            return FrameOutcome::Duplicate;
        }
        locked.queued.push(EncodingPacket::new(
            PayloadId::new(0, header.esi),
            symbol.to_vec(),
        ));
        locked.last_progress = now;
        self.foreign_since_progress = 0;
        self.progress.accepted += 1;
        self.progress.received = locked.held.len() as u32;
        FrameOutcome::Accepted
    }

    /// Feed the queued symbols to the RaptorQ decoder (one decode attempt per
    /// call, once `K` symbols are held), and check the timeouts.
    pub fn decode(&mut self, now: Instant) -> &Progress {
        if self.progress.complete || self.progress.failed.is_some() {
            return &self.progress;
        }
        let Some(locked) = &mut self.locked else {
            return &self.progress;
        };
        if !locked.queued.is_empty() {
            let batch = std::mem::take(&mut locked.queued);
            if let Some(mut data) = locked.decoder.decode(batch) {
                data.truncate(locked.header.bundle_len as usize);
                self.result = Some(data);
                self.progress.complete = true;
                return &self.progress;
            }
        }
        if locked.held.len() as u32 >= locked.k + MAX_EXTRA_SYMBOLS {
            self.progress.failed = Some("the received codes do not fit together");
        } else if now.duration_since(locked.last_progress) > STALL_TIMEOUT {
            self.progress.failed = Some("no new codes arrived for a minute");
        } else if now.duration_since(locked.started) > TRANSFER_TIMEOUT {
            self.progress.failed = Some("the transfer took too long");
        }
        &self.progress
    }

    /// Where the transfer stands.
    #[must_use]
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// The rebuilt byte string and its transfer id, once complete. Still to be
    /// checked against the bundle's hash ([`super::bundle::parse`]).
    pub fn take(&mut self) -> Option<([u8; 8], Vec<u8>)> {
        let data = self.result.take()?;
        let id = self.locked.as_ref()?.header.transfer_id;
        Some((id, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        let mut x: u32 = 0x9e37_79b9;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    fn decode_all(frames: &[Vec<u8>]) -> FrameDecoder {
        let now = Instant::now();
        let mut d = FrameDecoder::new();
        for f in frames {
            d.push(f, now);
        }
        d.decode(now);
        d
    }

    #[test]
    fn source_frames_alone_rebuild_the_data() {
        let input = data(10_000);
        let enc = FrameEncoder::new([7; 8], &input, 800).unwrap();
        assert_eq!(enc.source_symbols(), 13);
        let mut d = decode_all(&enc.frames(0, 13));
        assert!(d.progress().complete);
        assert_eq!(d.take(), Some(([7; 8], input)));
    }

    #[test]
    fn repair_frames_alone_rebuild_the_data() {
        let input = data(5_000);
        let enc = FrameEncoder::new([1; 8], &input, 512).unwrap();
        let k = enc.source_symbols();
        let mut d = decode_all(&enc.frames(k + 100, k + 4));
        assert!(d.progress().complete);
        assert_eq!(d.take().unwrap().1, input);
    }

    #[test]
    fn frames_round_trip_through_the_codec() {
        let enc = FrameEncoder::new([2; 8], &data(3_000), 300).unwrap();
        for f in enc.frames(5, 3) {
            let (h, sym) = decode_frame(&f).unwrap();
            assert_eq!(h.transfer_id, [2; 8]);
            assert_eq!(h.bundle_len, 3_000);
            assert_eq!(sym.len(), 300);
            assert_eq!(f.len(), FRAME_OVERHEAD + 300);
        }
    }

    #[test]
    fn a_flipped_bit_anywhere_fails_the_checksum() {
        let enc = FrameEncoder::new([3; 8], &data(2_000), 400).unwrap();
        let frame = enc.frames(0, 1).remove(0);
        for i in 0..frame.len() {
            let mut bad = frame.clone();
            bad[i] ^= 0x10;
            assert!(decode_frame(&bad).is_err(), "byte {i}");
        }
    }

    fn forged(header: FrameHeader, symbol_len: usize) -> Vec<u8> {
        encode_frame(&header, &vec![0u8; symbol_len])
    }

    #[test]
    fn out_of_range_declared_sizes_are_refused_before_a_decoder_exists() {
        let ok = FrameHeader {
            transfer_id: [0; 8],
            bundle_len: 1000,
            symbol_size: 300,
            esi: 0,
        };
        assert!(decode_frame(&forged(ok, 300)).is_ok());
        // Oversize bundle.
        let big = FrameHeader {
            bundle_len: MAX_BUNDLE_BYTES as u32 + 1,
            ..ok
        };
        assert!(decode_frame(&forged(big, 300)).is_err());
        // Zero-length bundle.
        let zero = FrameHeader {
            bundle_len: 0,
            ..ok
        };
        assert!(decode_frame(&forged(zero, 300)).is_err());
        // Symbol size below the minimum (a valid-length frame for it).
        let small = FrameHeader {
            symbol_size: MIN_SYMBOL_SIZE - 1,
            ..ok
        };
        assert!(decode_frame(&forged(small, usize::from(MIN_SYMBOL_SIZE) - 1)).is_err());
        // Declared symbol size disagrees with the bytes present.
        let lying = FrameHeader {
            symbol_size: 400,
            ..ok
        };
        assert!(decode_frame(&forged(lying, 300)).is_err());
        // ESI beyond 24 bits.
        let esi = FrameHeader {
            esi: MAX_ESI + 1,
            ..ok
        };
        assert!(decode_frame(&forged(esi, 300)).is_err());
        // Wrong magic / version.
        let mut m = forged(ok, 300);
        m[0] = b'X';
        assert!(decode_frame(&m).is_err());
    }

    #[test]
    fn a_frame_of_another_transfer_is_dropped_and_counted() {
        let now = Instant::now();
        let a = FrameEncoder::new([0xAA; 8], &data(3_000), 300).unwrap();
        let b = FrameEncoder::new([0xBB; 8], &data(3_000), 300).unwrap();
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(&a.frames(0, 1)[0], now), FrameOutcome::Accepted);
        assert_eq!(d.push(&b.frames(1, 1)[0], now), FrameOutcome::OtherTransfer);
        assert_eq!(d.push(&a.frames(0, 1)[0], now), FrameOutcome::Duplicate);
        assert_eq!(d.push(b"garbage", now), FrameOutcome::Invalid);
        let p = d.progress();
        assert_eq!(
            (p.received, p.other_transfer, p.duplicates, p.invalid),
            (1, 1, 1, 1)
        );
        assert_eq!(p.transfer_id, Some([0xAA; 8]));
    }

    #[test]
    fn the_symbol_cap_bounds_what_is_held() {
        let now = Instant::now();
        let input = data(3_000);
        let enc = FrameEncoder::new([5; 8], &input, 300).unwrap();
        let k = enc.source_symbols();
        let mut d = FrameDecoder::new();
        // Junk symbols under the right transfer id: never decode to the input.
        for esi in 0..(k + MAX_EXTRA_SYMBOLS + 10) {
            let h = FrameHeader {
                transfer_id: [5; 8],
                bundle_len: 3_000,
                symbol_size: 300,
                esi: esi + k,
            };
            d.push(&encode_frame(&h, &[esi as u8; 300]), now);
        }
        assert_eq!(d.progress().received, k + MAX_EXTRA_SYMBOLS);
        d.decode(now);
        // Junk either fails to decode (cap reached) or decodes to garbage that
        // the bundle hash then refuses; it is never the input.
        if let Some((_, out)) = d.take() {
            assert_ne!(out, input);
        } else {
            assert!(d.progress().failed.is_some());
        }
    }

    #[test]
    fn a_stalled_transfer_times_out() {
        let t0 = Instant::now();
        let enc = FrameEncoder::new([6; 8], &data(3_000), 300).unwrap();
        let mut d = FrameDecoder::new();
        d.push(&enc.frames(0, 1)[0], t0);
        assert!(d.decode(t0).failed.is_none());
        assert!(
            d.decode(t0 + STALL_TIMEOUT + Duration::from_secs(1))
                .failed
                .is_some()
        );
        assert_eq!(d.push(&enc.frames(1, 1)[0], t0), FrameOutcome::Ignored);
    }

    #[test]
    fn encoder_refuses_out_of_range_input() {
        assert!(FrameEncoder::new([0; 8], &[], 300).is_err());
        assert!(FrameEncoder::new([0; 8], &data(10), MAX_SYMBOL_SIZE + 1).is_err());
        assert!(FrameEncoder::new([0; 8], &vec![0; MAX_BUNDLE_BYTES + 1], 2000).is_err());
    }
}
