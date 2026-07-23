//! KeePass **KDBX 4** import.
//!
//! # Foreign-format crypto exception
//!
//! Like the `age` archive path (see this crate's `Cargo.toml` / `lib.rs`), this
//! module uses RustCrypto primitives **directly** to READ a foreign database's
//! envelope. That crypto never protects LocalPass's own data — LocalPass's
//! envelope crypto stays in `lp-crypto`. The primitive versions are pinned to
//! the lines `lp-crypto` already resolves (cipher 0.4 for `aes`/`cbc`/
//! `chacha20`; `argon2` 0.5; the digest-0.10 line for `sha2`/`hmac`), so no
//! parallel crypto stack is introduced — the reason the earlier build stubbed
//! this out (the `keepass` crate pulled ~85 crates and a duplicate stack) does
//! not apply to a focused reader on the existing primitives.
//!
//! # Scope (v1)
//!
//! - **Outer cipher:** AES-256-CBC (the KeePass/KeePassXC default). ChaCha20 and
//!   Twofish outer ciphers return [`PorterError::Unsupported`] with an
//!   actionable "re-save with AES-256" message rather than shipping an
//!   unverified decrypt path.
//! - **KDF:** Argon2d / Argon2id (any params). AES-KDF (KDBX 3.x) is refused.
//! - **Inner protected-field stream:** ChaCha20 (KDBX 4). Salsa20 (KDBX 3.x) is
//!   refused.
//!
//! # Mapping
//!
//! Each KeePass entry becomes a LocalPass [`Login`](lp_vault::TypeData::Login):
//! `Title`→title, `UserName`→`username`, `Password`→hidden `password`,
//! `URL`→`url`, `Notes`→the item note, and `otp` (KeePassXC) → hidden `totp`
//! (preserved as the full `otpauth://` URI, matching the other importers). Any
//! other string becomes a custom field — hidden if KeePass marked it protected,
//! text otherwise. Sub-group names become tags. History (previous-version)
//! entries are not imported, but their protected values still advance the inner
//! keystream so later values decrypt correctly.

use std::io::Read;
use std::path::Path;

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, Key, Nonce};
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use lp_vault::ItemPayload;
use lp_vault::payload::TypeData;

use crate::error::{PorterError, Result};
use crate::import::{add_hidden, add_text, add_url};
use crate::model::ImportOutcome;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const SIG1: u32 = 0x9AA2_D903;
const SIG2: u32 = 0xB54B_FB67;

/// AES-256-CBC cipher UUID (`31C1F2E6-BF71-4350-BE58-05216AFC5AFF`).
const CIPHER_AES256: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
/// ChaCha20 outer-cipher UUID (`D6038A2B-8B6F-4CB5-A524-339A31DBB59A`).
const CIPHER_CHACHA20: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];
/// Argon2d KDF UUID (`EF636DDF-8C29-444B-91F7-A9A403E30A0C`).
const KDF_ARGON2D: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
/// Argon2id KDF UUID (`9E298B19-56DB-4773-B23D-FC3EC6F0A1E6`).
const KDF_ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

fn mal(detail: impl Into<String>) -> PorterError {
    PorterError::malformed("kdbx", detail)
}
fn uns(msg: impl Into<String>) -> PorterError {
    PorterError::Unsupported(msg.into())
}

/// Parse a KDBX 4 database at `path`, unlocking with `password`.
///
/// # Errors
///
/// - [`PorterError::Io`] if the file cannot be read.
/// - [`PorterError::Malformed`] on a structurally invalid KDBX file.
/// - [`PorterError::Unsupported`] for a non-KDBX-4 version, or a cipher/KDF/inner
///   stream this build does not implement (with an actionable message).
/// - [`PorterError::KdbxDecrypt`] if the password is wrong or the file is
///   corrupt (the two are indistinguishable — no oracle).
pub fn parse_file(path: &Path, password: &str) -> Result<ImportOutcome> {
    let bytes = std::fs::read(path)?;
    parse_bytes(&bytes, password)
}

/// A little-endian byte cursor that never panics on a short read.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| mal("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| mal("unexpected end of file"))?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Parsed KDF (`kdf_parameters`) variant-dictionary — Argon2 only.
struct Kdf {
    uuid: [u8; 16],
    salt: Vec<u8>,
    iterations: u64,
    memory: u64,
    parallelism: u32,
    version: u32,
}

impl Kdf {
    /// Run the KDF over the 32-byte composite key → 32-byte transformed key.
    fn derive(&self, composite: &[u8]) -> Result<[u8; 32]> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let algo = if self.uuid == KDF_ARGON2ID {
            Algorithm::Argon2id
        } else if self.uuid == KDF_ARGON2D {
            Algorithm::Argon2d
        } else {
            return Err(uns(
                "this KDBX uses an unsupported key-derivation function (only Argon2 is supported); \
                 re-save it with Argon2 in KeePass (Database Settings) and import again",
            ));
        };
        let version = match self.version {
            0x13 => Version::V0x13,
            0x10 => Version::V0x10,
            _ => return Err(mal("unsupported Argon2 version")),
        };
        // KDBX stores memory in BYTES; argon2's Params wants KiB.
        let m_kib =
            u32::try_from(self.memory / 1024).map_err(|_| mal("Argon2 memory too large"))?;
        let t = u32::try_from(self.iterations).map_err(|_| mal("Argon2 iterations too large"))?;
        let params = Params::new(m_kib.max(8), t.max(1), self.parallelism.max(1), Some(32))
            .map_err(|_| mal("invalid Argon2 parameters"))?;
        let mut out = [0u8; 32];
        Argon2::new(algo, version, params)
            .hash_password_into(composite, &self.salt, &mut out)
            .map_err(|_| mal("Argon2 derivation failed"))?;
        Ok(out)
    }
}

/// Read the smallest-fitting little-endian unsigned integer from `b`.
fn le_uint(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    let n = b.len().min(8);
    a[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(a)
}

/// Parse the KDF `VariantDictionary` (field id 11).
fn parse_variant_dict(data: &[u8]) -> Result<Kdf> {
    let mut c = Cursor::new(data);
    let _ver = c.u16()?; // format version (0x0100)
    let (mut uuid, mut salt) = (None, None);
    let (mut iterations, mut memory, mut parallelism, mut version) = (None, None, None, None);
    loop {
        let vtype = c.u8()?;
        if vtype == 0 {
            break; // end of dictionary
        }
        let klen = c.u32()? as usize;
        let key = c.take(klen)?;
        let vlen = c.u32()? as usize;
        let val = c.take(vlen)?;
        match key {
            b"$UUID" if val.len() == 16 => {
                let mut u = [0u8; 16];
                u.copy_from_slice(val);
                uuid = Some(u);
            }
            b"S" => salt = Some(val.to_vec()),
            b"I" => iterations = Some(le_uint(val)),
            b"M" => memory = Some(le_uint(val)),
            b"P" => parallelism = Some(le_uint(val) as u32),
            b"V" => version = Some(le_uint(val) as u32),
            _ => {}
        }
    }
    Ok(Kdf {
        uuid: uuid.ok_or_else(|| mal("KDF params missing $UUID"))?,
        salt: salt.ok_or_else(|| mal("KDF params missing salt"))?,
        iterations: iterations.ok_or_else(|| mal("KDF params missing iterations"))?,
        memory: memory.ok_or_else(|| mal("KDF params missing memory"))?,
        parallelism: parallelism.ok_or_else(|| mal("KDF params missing parallelism"))?,
        version: version.ok_or_else(|| mal("KDF params missing version"))?,
    })
}

/// The inner random stream that unprotects `<Value Protected="True">` bodies.
/// KDBX 4 always uses ChaCha20; the keystream is consumed in document order.
struct ProtectStream {
    cipher: ChaCha20,
}

impl ProtectStream {
    fn new(id: u32, key: &[u8]) -> Result<Self> {
        match id {
            3 => {
                // ChaCha20: key = SHA-512(key)[0..32], nonce = SHA-512(key)[32..44].
                let h = Sha512::digest(key);
                let cipher =
                    ChaCha20::new(Key::from_slice(&h[0..32]), Nonce::from_slice(&h[32..44]));
                Ok(Self { cipher })
            }
            2 => Err(uns(
                "this KDBX uses the Salsa20 inner stream (KDBX 3.x); re-save it with a recent \
                 KeePass (KDBX 4) and import again",
            )),
            _ => Err(mal("unknown inner random stream id")),
        }
    }

    /// Decode base64 and XOR the keystream, advancing it. Always call this for a
    /// protected value in document order — even in History — to keep the stream
    /// aligned.
    fn unprotect(&mut self, b64: &str) -> Result<String> {
        let mut raw = data_encoding::BASE64
            .decode(b64.trim().as_bytes())
            .map_err(|_| mal("invalid base64 in a protected value"))?;
        self.cipher.apply_keystream(&mut raw);
        let s = String::from_utf8(raw.clone()).map_err(|_| mal("protected value is not UTF-8"));
        raw.zeroize();
        s
    }
}

fn parse_bytes(bytes: &[u8], password: &str) -> Result<ImportOutcome> {
    let mut c = Cursor::new(bytes);
    if c.u32()? != SIG1 || c.u32()? != SIG2 {
        return Err(mal("not a KeePass KDBX file (bad signature)"));
    }
    let version = c.u32()?;
    let major = (version >> 16) as u16;
    if major != 4 {
        return Err(uns(format!(
            "KDBX major version {major} is not supported (only KDBX 4); re-save with a recent KeePass"
        )));
    }

    // Outer header: TLV fields terminated by id 0.
    let (mut cipher, mut compression, mut master_seed, mut enc_iv, mut kdf) =
        (None, None, None, None, None);
    loop {
        let id = c.u8()?;
        let len = c.u32()? as usize;
        let data = c.take(len)?;
        match id {
            0 => break,
            2 => cipher = Some(data.to_vec()),
            3 => {
                compression = Some(u32::from_le_bytes(
                    data.try_into().map_err(|_| mal("bad compression flags"))?,
                ));
            }
            4 => master_seed = Some(data.to_vec()),
            7 => enc_iv = Some(data.to_vec()),
            11 => kdf = Some(parse_variant_dict(data)?),
            _ => {} // 12 = public custom data, and unknowns: ignore
        }
    }
    let header = &bytes[..c.pos];
    let cipher = cipher.ok_or_else(|| mal("missing cipher id"))?;
    let compression = compression.ok_or_else(|| mal("missing compression flags"))?;
    let master_seed = master_seed.ok_or_else(|| mal("missing master seed"))?;
    if master_seed.len() != 32 {
        return Err(mal("master seed is not 32 bytes"));
    }
    let enc_iv = enc_iv.ok_or_else(|| mal("missing encryption IV"))?;
    let kdf = kdf.ok_or_else(|| mal("missing KDF parameters"))?;

    // Stored integrity hash + HMAC of the header.
    let stored_sha = c.take(32)?;
    let stored_hmac = c.take(32)?;
    if Sha256::digest(header).as_slice() != stored_sha {
        return Err(mal("header checksum mismatch (corrupt file)"));
    }

    // Key schedule.
    let mut composite = composite_key(password);
    let mut transformed = kdf.derive(&composite)?;
    composite.zeroize();

    // Cipher key = SHA-256(master_seed || transformed).
    let mut mk = Sha256::new();
    mk.update(&master_seed);
    mk.update(transformed);
    let master_key = mk.finalize();

    // HMAC base = SHA-512(master_seed || transformed || 0x01).
    let mut hb = Sha512::new();
    hb.update(&master_seed);
    hb.update(transformed);
    hb.update([0x01u8]);
    let hmac_base = hb.finalize();
    transformed.zeroize();

    // Authenticate the header (block index u64::MAX). A mismatch here is the
    // usual "wrong password" signal — reported without an oracle.
    let header_key = block_hmac_key(u64::MAX, &hmac_base);
    let mut hmac = HmacSha256::new_from_slice(&header_key).expect("HMAC accepts any key length");
    hmac.update(header);
    hmac.verify_slice(stored_hmac)
        .map_err(|_| PorterError::KdbxDecrypt)?;

    // HMAC-block stream → concatenated ciphertext.
    let mut ciphertext = Vec::new();
    let mut idx = 0u64;
    loop {
        let blk_hmac = c.take(32)?;
        let blk_len = c.u32()? as usize;
        let blk_data = c.take(blk_len)?;
        let key = block_hmac_key(idx, &hmac_base);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(&idx.to_le_bytes());
        mac.update(&(blk_len as u32).to_le_bytes());
        mac.update(blk_data);
        mac.verify_slice(blk_hmac)
            .map_err(|_| PorterError::KdbxDecrypt)?;
        if blk_len == 0 {
            break; // terminal empty block
        }
        ciphertext.extend_from_slice(blk_data);
        idx += 1;
    }

    // Decrypt the payload.
    let plain = if cipher == CIPHER_AES256 {
        if enc_iv.len() != 16 {
            return Err(mal("AES IV is not 16 bytes"));
        }
        Aes256CbcDec::new_from_slices(&master_key, &enc_iv)
            .map_err(|_| mal("bad AES key/IV length"))?
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            .map_err(|_| PorterError::KdbxDecrypt)?
    } else if cipher == CIPHER_CHACHA20 {
        return Err(uns(
            "this KDBX uses the ChaCha20 outer cipher; re-save it with AES-256 in KeePass \
             (Database Settings → Security → Encryption Algorithm) and import again",
        ));
    } else {
        return Err(uns(
            "this KDBX uses an unsupported outer cipher; re-save it with AES-256 in KeePass \
             and import again",
        ));
    };

    // Decompress if GZip (flag 1).
    let inner = if compression == 1 {
        let mut out = Vec::new();
        GzDecoder::new(plain.as_slice())
            .read_to_end(&mut out)
            .map_err(|_| mal("gzip decompression failed"))?;
        out
    } else {
        plain
    };

    // Inner header: TLV fields, then the XML body.
    let mut ic = Cursor::new(&inner);
    let (mut stream_id, mut stream_key) = (None, None);
    loop {
        let id = ic.u8()?;
        let len = ic.u32()? as usize;
        let data = ic.take(len)?;
        match id {
            0 => break,
            1 => {
                stream_id = Some(u32::from_le_bytes(
                    data.try_into().map_err(|_| mal("bad inner stream id"))?,
                ));
            }
            2 => stream_key = Some(data.to_vec()),
            _ => {} // 3 = binary (attachment): not imported
        }
    }
    let xml = &inner[ic.pos..];
    let mut protect = ProtectStream::new(
        stream_id.ok_or_else(|| mal("missing inner random stream id"))?,
        &stream_key.ok_or_else(|| mal("missing inner random stream key"))?,
    )?;

    parse_xml(xml, &mut protect)
}

/// KeePass composite key for a password-only database: SHA-256(SHA-256(pw)).
fn composite_key(password: &str) -> [u8; 32] {
    let inner = Sha256::digest(password.as_bytes());
    Sha256::digest(inner).into()
}

/// Per-block HMAC key: SHA-512(LE64(index) || hmac_base).
fn block_hmac_key(index: u64, hmac_base: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(index.to_le_bytes());
    h.update(hmac_base);
    h.finalize().into()
}

/// One accumulated KeePass string: `(key, value, was_protected)`.
type KvTriple = (String, String, bool);

/// Stream-parse the inner XML into logins, decrypting protected values in
/// document order.
fn parse_xml(xml: &[u8], protect: &mut ProtectStream) -> Result<ImportOutcome> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut outcome = ImportOutcome::new();

    // Element-name stack (to know a <Name>'s parent) and open-group names.
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut group_names: Vec<String> = Vec::new();
    let mut entry_depth = 0usize;
    let mut history_depth = 0usize;

    // Current entry's accumulated strings (only for the outer, non-history entry).
    let mut accum: Option<Vec<KvTriple>> = None;
    let mut cur_key: Option<String> = None;

    // Leaf text capture.
    let (mut in_key, mut in_value, mut in_name) = (false, false, false);
    let (mut key_buf, mut value_buf, mut name_buf) = (String::new(), String::new(), String::new());
    let mut value_protected = false;

    // Finish a `<Value>`: decrypt if protected (advances the keystream in doc
    // order, always), then record into the outer entry if we're in one.
    macro_rules! finish_value {
        () => {{
            let v = if value_protected {
                protect.unprotect(&value_buf)?
            } else {
                value_buf.clone()
            };
            if history_depth == 0 && entry_depth == 1 {
                if let (Some(k), Some(a)) = (cur_key.take(), accum.as_mut()) {
                    a.push((k, v, value_protected));
                }
            } else {
                cur_key = None;
            }
            value_buf.clear();
            value_protected = false;
        }};
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(mal(format!("invalid inner XML: {e}"))),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = e.local_name().as_ref().to_vec();
                let parent = stack.last().map(Vec::as_slice);
                match name.as_slice() {
                    b"Group" => group_names.push(String::new()),
                    b"Entry" => {
                        entry_depth += 1;
                        if entry_depth == 1 && history_depth == 0 {
                            accum = Some(Vec::new());
                        }
                    }
                    b"History" => history_depth += 1,
                    b"Key" => {
                        in_key = true;
                        key_buf.clear();
                    }
                    b"Value" => {
                        in_value = true;
                        value_buf.clear();
                        value_protected = attr_is_true(&e, b"Protected")?;
                    }
                    b"Name" if parent == Some(b"Group") && entry_depth == 0 => {
                        in_name = true;
                        name_buf.clear();
                    }
                    _ => {}
                }
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                // Self-closing element: only a `<Value/>` matters (empty value,
                // possibly protected → advance keystream by zero bytes).
                if e.local_name().as_ref() == b"Value" {
                    value_buf.clear();
                    value_protected = attr_is_true(&e, b"Protected")?;
                    finish_value!();
                }
            }
            Ok(Event::Text(t)) => {
                if in_key || in_value || in_name {
                    // xml10_content decodes the charset AND resolves entities
                    // (`&lt;` → `<`, `&#x2615;` → ☕) — the quick-xml 0.41
                    // replacement for the old `unescape()`.
                    let txt = t
                        .xml10_content()
                        .map_err(|e| mal(format!("bad XML text: {e}")))?;
                    if in_key {
                        key_buf.push_str(&txt);
                    } else if in_value {
                        value_buf.push_str(&txt);
                    } else {
                        name_buf.push_str(&txt);
                    }
                }
            }
            Ok(Event::GeneralRef(r)) => {
                // quick-xml 0.41 emits entity references (`&lt;`, `&#x2615;`) as
                // their own events; resolve and append to the active capture
                // buffer. (Protected values are base64 and never contain refs.)
                if (in_key || in_value || in_name)
                    && let Some(ch) = resolve_ref(&r)?
                {
                    let mut tmp = [0u8; 4];
                    let s = ch.encode_utf8(&mut tmp);
                    if in_key {
                        key_buf.push_str(s);
                    } else if in_value {
                        value_buf.push_str(s);
                    } else {
                        name_buf.push_str(s);
                    }
                }
            }
            Ok(Event::CData(t)) => {
                if in_value {
                    value_buf.push_str(&String::from_utf8_lossy(&t.into_inner()));
                }
            }
            Ok(Event::End(e)) => {
                stack.pop();
                match e.local_name().as_ref() {
                    b"Key" => {
                        in_key = false;
                        cur_key = Some(key_buf.clone());
                    }
                    b"Value" => {
                        in_value = false;
                        finish_value!();
                    }
                    b"Name" if in_name => {
                        in_name = false;
                        if let Some(top) = group_names.last_mut() {
                            *top = name_buf.clone();
                        }
                    }
                    b"History" => history_depth = history_depth.saturating_sub(1),
                    b"Entry" => {
                        entry_depth = entry_depth.saturating_sub(1);
                        if entry_depth == 0
                            && let Some(fields) = accum.take()
                        {
                            build_item(&mut outcome, fields, tags_from(&group_names));
                        }
                    }
                    b"Group" => {
                        group_names.pop();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(outcome)
}

/// Sub-group names (everything below the root group) → tags.
fn tags_from(group_names: &[String]) -> Vec<String> {
    group_names
        .iter()
        .skip(1)
        .filter(|s| !s.is_empty())
        .cloned()
        .collect()
}

/// Resolve an XML general/character reference to a char. Numeric refs
/// (`&#x2615;`, `&#49;`) go through quick-xml; the five predefined named
/// entities are handled here. Unknown named entities are dropped (KeePass emits
/// only the predefined set).
fn resolve_ref(r: &quick_xml::events::BytesRef<'_>) -> Result<Option<char>> {
    if let Some(c) = r
        .resolve_char_ref()
        .map_err(|e| mal(format!("bad character reference: {e}")))?
    {
        return Ok(Some(c));
    }
    let name = r.decode().map_err(|e| mal(format!("bad entity: {e}")))?;
    Ok(match name.as_ref() {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "apos" => Some('\''),
        "quot" => Some('"'),
        _ => None,
    })
}

/// Read a boolean attribute (`Protected="True"`).
fn attr_is_true(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Result<bool> {
    for attr in e.attributes() {
        let attr = attr.map_err(|err| mal(format!("bad XML attribute: {err}")))?;
        if attr.key.as_ref() == name {
            return Ok(attr.value.as_ref() == b"True");
        }
    }
    Ok(false)
}

/// Map one KeePass entry's accumulated strings into a LocalPass login.
fn build_item(outcome: &mut ImportOutcome, fields: Vec<KvTriple>, tags: Vec<String>) {
    let (mut title, mut username, mut password, mut url, mut notes, mut otp) =
        (None, None, None, None, None, None);
    let mut customs: Vec<KvTriple> = Vec::new();

    for (key, value, protected) in fields {
        match key.as_str() {
            "Title" => title = Some(value),
            "UserName" => username = Some(value),
            "Password" => password = Some(value),
            "URL" => url = Some(value),
            "Notes" => notes = Some(value),
            // KeePassXC ("otp", full otpauth URI) and the KeePass2 TOTP plugin.
            "otp" | "TOTP Seed" | "TimeOtp-Secret-Base32" => otp = Some(value),
            _ => customs.push((key, value, protected)),
        }
    }

    let title = title
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(untitled)".to_string());
    let mut p = ItemPayload::new(TypeData::Login { urls: Vec::new() }, &title);

    if let Some(u) = username {
        add_text(&mut p, "username", &u);
    }
    if let Some(pw) = password {
        add_hidden(&mut p, "password", &pw);
    }
    if let Some(u) = url {
        add_url(&mut p, "url", &u);
    }
    if let Some(o) = otp {
        add_hidden(&mut p, "totp", &o);
    }
    if let Some(n) = notes {
        p.notes = n;
    }
    for (key, value, protected) in customs {
        if value.is_empty() {
            continue;
        }
        if protected {
            add_hidden(&mut p, &key, &value);
        } else {
            add_text(&mut p, &key, &value);
        }
    }
    p.tags.extend(tags);

    outcome.push(p);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_kdbx_bytes() {
        let err = parse_bytes(b"not a kdbx file at all", "pw").unwrap_err();
        assert!(matches!(err, PorterError::Malformed { .. }));
    }

    #[test]
    fn truncated_header_is_clean_error_no_panic() {
        // Valid signature + version, then abruptly ends.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SIG1.to_le_bytes());
        bytes.extend_from_slice(&SIG2.to_le_bytes());
        bytes.extend_from_slice(&0x0004_0000u32.to_le_bytes());
        let err = parse_bytes(&bytes, "pw").unwrap_err();
        assert!(matches!(err, PorterError::Malformed { .. }));
    }

    #[test]
    fn le_uint_widths() {
        assert_eq!(le_uint(&[0x0e]), 14);
        assert_eq!(le_uint(&14u64.to_le_bytes()), 14);
        assert_eq!(le_uint(&[0x00, 0x00, 0x00, 0x04]), 0x0400_0000);
    }
}
