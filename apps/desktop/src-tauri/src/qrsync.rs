// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! Sync by QR code — the GUI backend (`docs/specs/qr-transport.md` §10.4).
//!
//! The webview **renders and samples**; this module **decides**:
//!
//! - Sending: the daemon builds the bundle into a file (`QrExport`, by path),
//!   this module reads it, deletes the file, runs the RaptorQ encoder
//!   ([`lp_sync::qr::FrameEncoder`]) and renders each frame to a QR module
//!   matrix with the `qrcode` crate. The webview only draws the matrices.
//! - Receiving: the webview runs the camera and jsQR and passes each decoded
//!   code's raw bytes here. [`lp_sync::qr::FrameDecoder`] checks every frame
//!   (size, magic, version, CRC, declared sizes) before keeping it, and once the
//!   bundle is rebuilt this module writes it to a file and hands the **path** to
//!   the daemon (`QrImport`), which checks the hash and runs the §5 verifier.
//!
//! The commands that encode, decode or call the daemon are `async`, so Tauri
//! runs them off the main thread and a large bundle never freezes the window.
//!
//! Nothing that crosses this module is secret: frames and bundles are
//! ciphertext plus the metadata a sync folder holds, and the "what I have" code
//! is ids and counters.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use lp_daemon::protocol::{Request, Response, WireQrExport, WireQrImport};
use lp_sync::qr::{self, FrameDecoder, FrameEncoder, HaveCode, Progress};
use qrcode::{EcLevel, QrCode, Version};
use serde::Serialize;

use crate::daemon;

/// The stream's error-correction level (`qr-transport.md` §7.2): L. A misread
/// frame fails its CRC and the fountain code makes up for lost ones, so the
/// capacity is worth more than the correction; M did not catch more frames in
/// the measurements (§12).
const STREAM_EC: EcLevel = EcLevel::L;
/// Frames shown per second by default (§7.2): 15 caught fewer frames than 10.
const STREAM_FPS: u32 = 10;

/// How large the stream's QR codes are (`qr-transport.md` §7.2, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeSize {
    /// Version 25: the fastest when a phone camera films a laptop screen.
    Large,
    /// Version 15: what a laptop's fixed-focus webcam can read off a phone.
    Small,
}

impl CodeSize {
    /// The sender's platform decides the default: a laptop is usually filmed
    /// by a phone, a phone by a laptop webcam. The user can switch.
    fn default_for_platform() -> Self {
        if cfg!(mobile) {
            Self::Small
        } else {
            Self::Large
        }
    }

    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("large") => Self::Large,
            Some("small") => Self::Small,
            _ => Self::default_for_platform(),
        }
    }

    fn version(self) -> i16 {
        match self {
            Self::Large => 25,
            Self::Small => 15,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Large => "large",
            Self::Small => "small",
        }
    }
}
/// The most frames one `qr_send_frames` / `qr_receive_frames` call handles.
const MAX_BATCH: usize = 64;
/// The largest raw code the webview may hand over (QR version 40's capacity).
const MAX_SCANNED_BYTES: usize = 2953;

/// What a player is sending.
struct Sender {
    encoder: FrameEncoder,
    version: i16,
}

static SEND: Mutex<Option<Sender>> = Mutex::new(None);
static RECV: Mutex<Option<FrameDecoder>> = Mutex::new(None);
/// A rebuilt bundle whose import has not succeeded yet (the vault locked, say):
/// kept so the user can retry without filming the stream again.
static PENDING: Mutex<Option<([u8; 8], Vec<u8>)>> = Mutex::new(None);

/// One QR code for the webview to draw: `width × width` modules, row-major,
/// packed 4 per hex digit (MSB first), dark = 1.
#[derive(Clone, Debug, Serialize)]
pub struct QrMatrixView {
    /// The frame's encoding symbol id (0 for a still code).
    pub esi: u32,
    /// Modules per side (without the quiet zone).
    pub width: u32,
    /// The packed modules.
    pub bits: String,
}

/// The receiver's "what I have" code, ready to show.
#[derive(Clone, Debug, Serialize)]
pub struct QrHaveView {
    /// The `LPHAVE1-…` text (for copying).
    pub text: String,
    /// How many vaults it lists.
    pub vaults: usize,
    /// The still QR code.
    pub qr: QrMatrixView,
}

/// A scanned or pasted "what I have" code, checked.
#[derive(Clone, Debug, Serialize)]
pub struct QrHaveInfo {
    /// The canonical `LPHAVE1-…` text to pass to [`qr_send_start`].
    pub text: String,
    /// The device it claims to come from (hyphenated). Unauthenticated: the
    /// UI may use it to pre-select a trusted device, never to decide anything.
    pub device_id: String,
    /// How many vaults it lists.
    pub vaults: usize,
}

/// A stream ready to play.
#[derive(Clone, Serialize)]
pub struct QrSendView {
    /// What the bundle carries.
    pub summary: WireQrExport,
    /// Source symbols: the receiver needs about this many distinct frames.
    pub frames_needed: u32,
    /// Bytes of bundle per frame.
    pub symbol_size: u16,
    /// The QR version every frame uses.
    pub qr_version: i16,
    /// `"large"` or `"small"`.
    pub code_size: &'static str,
    /// The default frame rate.
    pub fps: u32,
}

/// Where a receive stands.
#[derive(Clone, Debug, Serialize)]
pub struct QrProgressView {
    /// Whether a frame has fixed the transfer yet.
    pub locked: bool,
    /// The transfer's declared size in bytes.
    pub bundle_len: u32,
    /// Distinct frames held.
    pub received: u32,
    /// About this many are needed.
    pub needed: u32,
    /// Frames dropped as invalid (not a LocalPass frame, or misread).
    pub invalid: u32,
    /// Frames of another transfer dropped.
    pub other_transfer: u32,
    /// The bundle is rebuilt; call [`qr_receive_finish`].
    pub complete: bool,
    /// The transfer stopped, and why.
    pub failed: Option<String>,
}

impl From<&Progress> for QrProgressView {
    fn from(p: &Progress) -> Self {
        Self {
            locked: p.transfer_id.is_some(),
            bundle_len: p.bundle_len,
            received: p.received,
            needed: p.needed,
            invalid: p.invalid,
            other_transfer: p.other_transfer,
            complete: p.complete,
            failed: p.failed.map(str::to_owned),
        }
    }
}

/// The symbol size that fills a byte-mode QR code of `version` at `ec`.
fn symbol_size_for(version: i16, ec: EcLevel) -> u16 {
    let mut len = usize::from(qr::MIN_SYMBOL_SIZE);
    while encode_bytes(&vec![0xA5; len + 1 + qr::FRAME_OVERHEAD], version, ec).is_some() {
        len += 1;
    }
    u16::try_from(len).expect("below the QR capacity")
}

/// One byte-mode segment at a fixed version and level — the only form the
/// stream uses (`qr-transport.md` §7.1).
fn encode_bytes(data: &[u8], version: i16, ec: EcLevel) -> Option<QrCode> {
    let mut bits = qrcode::bits::Bits::new(Version::Normal(version));
    bits.push_byte_data(data).ok()?;
    bits.push_terminator(ec).ok()?;
    QrCode::with_bits(bits, ec).ok()
}

fn matrix(code: &QrCode, esi: u32) -> QrMatrixView {
    let width = code.width();
    let colors = code.to_colors();
    let mut bits = String::with_capacity(colors.len().div_ceil(4));
    for chunk in colors.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            if *c == qrcode::Color::Dark {
                n |= 8 >> i;
            }
        }
        bits.push(char::from_digit(n, 16).expect("nibble"));
    }
    QrMatrixView {
        esi,
        width: u32::try_from(width).expect("≤ 177"),
        bits,
    }
}

/// A still code: byte mode, level M at the smallest version that fits, L if M
/// does not fit at all (`qr-transport.md` §4.2).
fn still_code(data: &[u8]) -> Result<QrMatrixView, String> {
    for ec in [EcLevel::M, EcLevel::L] {
        for v in 1..=40 {
            if let Some(code) = encode_bytes(data, v, ec) {
                return Ok(matrix(&code, 0));
            }
        }
    }
    Err("the code is too large for one QR code".into())
}

fn hex_id(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh, unique bundle path in the profile's private `tmp` directory (the
/// Android app-private dir on mobile, where there is no shared temp dir).
fn temp_bundle_path() -> Result<PathBuf, String> {
    let dir = daemon::resolve_profile()?.join("tmp");
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not create a temp folder: {e}"))?;
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| "no OS randomness available".to_string())?;
    Ok(dir.join(format!("qr-{}.lpqr", hex_id(&r))))
}

fn check(resp: &Response) -> Result<(), String> {
    match resp {
        Response::Error { message, .. } => Err(message.clone()),
        Response::Locked => Err("the vault is locked".into()),
        Response::WrongProfile { expected } => Err(format!(
            "the running daemon serves a different profile ({expected})"
        )),
        _ => Ok(()),
    }
}

/// This device's "what I have" code for `vaults` (empty = all), as text and
/// as a still QR.
#[tauri::command]
pub async fn qr_have_code(vaults: Vec<String>) -> Result<QrHaveView, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::QrHaveCode { profile, vaults }).map_err(|e| e.to_string())?;
    check(&resp)?;
    let Response::QrHaveCode { code, vaults } = resp else {
        return Err(format!("unexpected daemon response: {}", resp.kind()));
    };
    let parsed = HaveCode::from_text(&code).map_err(|e| e.to_string())?;
    let bytes = parsed.to_bytes().map_err(|e| e.to_string())?;
    Ok(QrHaveView {
        qr: still_code(&bytes)?,
        text: code,
        vaults,
    })
}

/// Check a scanned (`bytes`) or pasted (`text`) "what I have" code.
#[tauri::command]
pub fn qr_have_parse(bytes: Option<Vec<u8>>, text: Option<String>) -> Result<QrHaveInfo, String> {
    let code = match (bytes, text) {
        (Some(b), _) => {
            if b.len() > MAX_SCANNED_BYTES {
                return Err("that is not a LocalPass \"what I have\" code".into());
            }
            HaveCode::from_bytes(&b)
        }
        (None, Some(t)) => HaveCode::from_text(&t),
        (None, None) => return Err("no code given".into()),
    }
    .map_err(|e| e.to_string())?;
    Ok(QrHaveInfo {
        text: code.to_text().map_err(|e| e.to_string())?,
        device_id: code.device_id.to_hyphenated(),
        vaults: code.heads.len(),
    })
}

/// Build a bundle (through the daemon) and get ready to play it.
#[tauri::command]
pub async fn qr_send_start(
    vaults: Vec<String>,
    have: Option<String>,
    peer: Option<String>,
    share: Vec<String>,
    attachments: bool,
    code_size: Option<String>,
) -> Result<QrSendView, String> {
    let size = CodeSize::parse(code_size.as_deref());
    let profile = daemon::profile_string()?;
    let path = temp_bundle_path()?;
    let out_path = path.to_string_lossy().into_owned();
    let resp = daemon::call(&Request::QrExport {
        profile,
        out_path,
        vaults,
        have,
        peer,
        share,
        attachments,
        force: false,
    })
    .map_err(|e| e.to_string());
    let read = std::fs::read(&path);
    let _ = std::fs::remove_file(&path);
    let resp = resp?;
    check(&resp)?;
    let Response::QrExported { summary } = resp else {
        return Err(format!("unexpected daemon response: {}", resp.kind()));
    };
    let bundle = read.map_err(|e| format!("could not read the bundle: {e}"))?;
    let version = size.version();
    let symbol_size = symbol_size_for(version, STREAM_EC);
    let encoder = qr::encoder_for(&bundle, symbol_size).map_err(|e| e.to_string())?;
    let frames_needed = encoder.source_symbols();
    *SEND.lock().map_err(|_| "busy")? = Some(Sender { encoder, version });
    Ok(QrSendView {
        summary,
        frames_needed,
        symbol_size,
        qr_version: version,
        code_size: size.name(),
        fps: STREAM_FPS,
    })
}

/// The code size this platform sends by default (`"large"` or `"small"`).
#[tauri::command]
#[must_use]
pub fn qr_default_code_size() -> &'static str {
    CodeSize::default_for_platform().name()
}

/// The next `count` frames to show, from encoding symbol `start`.
#[tauri::command]
pub async fn qr_send_frames(start: u32, count: u32) -> Result<Vec<QrMatrixView>, String> {
    let guard = SEND.lock().map_err(|_| "busy")?;
    let sender = guard.as_ref().ok_or("nothing is being sent")?;
    let count = count.min(MAX_BATCH as u32);
    sender
        .encoder
        .frames(start, count)
        .iter()
        .enumerate()
        .map(|(i, f)| {
            encode_bytes(f, sender.version, STREAM_EC)
                .map(|code| matrix(&code, start + i as u32))
                .ok_or_else(|| "a frame did not fit its QR code".to_string())
        })
        .collect()
}

/// Stop sending and drop the bundle.
#[tauri::command]
pub fn qr_send_stop() {
    if let Ok(mut g) = SEND.lock() {
        *g = None;
    }
}

/// Start (or restart) receiving.
#[tauri::command]
pub fn qr_receive_start() {
    if let Ok(mut g) = RECV.lock() {
        *g = Some(FrameDecoder::new());
    }
    if let Ok(mut g) = PENDING.lock() {
        *g = None;
    }
}

/// Hand over a batch of decoded codes (raw bytes, as jsQR read them).
#[tauri::command]
pub async fn qr_receive_frames(frames: Vec<Vec<u8>>) -> Result<QrProgressView, String> {
    let mut guard = RECV.lock().map_err(|_| "busy")?;
    let dec = guard.as_mut().ok_or("not receiving")?;
    let now = Instant::now();
    for f in frames.iter().take(MAX_BATCH) {
        if f.len() <= MAX_SCANNED_BYTES {
            dec.push(f, now);
        }
    }
    Ok(dec.decode(now).into())
}

/// Where the current receive stands (for the timeouts, between frames).
#[tauri::command]
pub fn qr_receive_progress() -> Result<QrProgressView, String> {
    let mut guard = RECV.lock().map_err(|_| "busy")?;
    let dec = guard.as_mut().ok_or("not receiving")?;
    Ok(dec.decode(Instant::now()).into())
}

/// The bundle is complete: hand it to the daemon (by path), which checks its
/// hash and ingests it through the §5 verifier.
#[tauri::command]
pub async fn qr_receive_finish() -> Result<WireQrImport, String> {
    let mut pending = PENDING.lock().map_err(|_| "busy")?;
    if pending.is_none() {
        let mut guard = RECV.lock().map_err(|_| "busy")?;
        let dec = guard.as_mut().ok_or("not receiving")?;
        *pending = Some(dec.take().ok_or("the transfer is not complete yet")?);
        *guard = None;
    }
    let (transfer_id, bundle) = pending.as_ref().expect("set above");
    let profile = daemon::profile_string()?;
    let path = temp_bundle_path()?;
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("could not write the bundle: {e}"))?;
        f.write_all(bundle)
            .map_err(|e| format!("could not write the bundle: {e}"))?;
    }
    let resp = daemon::call(&Request::QrImport {
        profile,
        path: path.to_string_lossy().into_owned(),
        transfer_id: Some(hex_id(transfer_id)),
    })
    .map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&path);
    let resp = resp?;
    check(&resp)?;
    match resp {
        Response::QrImported { report } => {
            *pending = None;
            Ok(report)
        }
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Stop receiving and drop what was collected.
#[tauri::command]
pub fn qr_receive_cancel() {
    if let Ok(mut g) = RECV.lock() {
        *g = None;
    }
    if let Ok(mut g) = PENDING.lock() {
        *g = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_symbol_fills_its_qr_code_exactly() {
        for size in [CodeSize::Large, CodeSize::Small] {
            let v = size.version();
            let t = symbol_size_for(v, STREAM_EC);
            let frame = vec![0xA5u8; usize::from(t) + qr::FRAME_OVERHEAD];
            assert!(encode_bytes(&frame, v, STREAM_EC).is_some());
            let mut over = frame.clone();
            over.push(0);
            assert!(encode_bytes(&over, v, STREAM_EC).is_none());
            assert!((qr::MIN_SYMBOL_SIZE..=qr::MAX_SYMBOL_SIZE).contains(&t));
        }
        // The byte-mode capacities of 25-L and 15-L, minus the frame overhead.
        assert_eq!(symbol_size_for(25, EcLevel::L), 1273 - 25);
        assert_eq!(symbol_size_for(15, EcLevel::L), 520 - 25);
    }

    #[test]
    fn code_sizes_parse_and_default_by_platform() {
        assert_eq!(CodeSize::parse(Some("large")), CodeSize::Large);
        assert_eq!(CodeSize::parse(Some("small")), CodeSize::Small);
        assert_eq!(
            CodeSize::parse(Some("huge")),
            CodeSize::default_for_platform()
        );
        assert_eq!(CodeSize::parse(None), CodeSize::default_for_platform());
    }

    #[test]
    fn matrices_pack_four_modules_per_hex_digit() {
        let code = encode_bytes(b"LQ-test", 1, EcLevel::M).unwrap();
        let m = matrix(&code, 7);
        assert_eq!(m.width, 21);
        assert_eq!(m.bits.len(), (21 * 21usize).div_ceil(4));
        assert_eq!(m.esi, 7);
        // The top-left finder pattern starts with seven dark modules.
        assert!(m.bits.starts_with("fe"));
    }

    #[test]
    fn a_still_code_picks_the_smallest_version() {
        assert_eq!(still_code(&[0u8; 10]).unwrap().width, 21);
        assert!(still_code(&vec![0u8; 3000]).is_err());
    }

    #[test]
    fn frames_of_a_real_encoder_render_and_decode_back() {
        let v = CodeSize::Small.version();
        let t = symbol_size_for(v, STREAM_EC);
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let enc = FrameEncoder::new([9; 8], &data, t).unwrap();
        let mut dec = FrameDecoder::new();
        let now = Instant::now();
        for f in enc.frames(0, enc.source_symbols()) {
            assert!(encode_bytes(&f, v, STREAM_EC).is_some());
            dec.push(&f, now);
        }
        assert!(dec.decode(now).complete);
        assert_eq!(dec.take().unwrap().1, data);
    }
}
