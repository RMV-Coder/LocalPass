//! Human-readable encoding for the 128-bit [`SecretKey`](crate::SecretKey).
//!
//! # Goals
//!
//! The Secret Key is printed in the Emergency Kit and re-typed by hand during
//! device setup (PRD §4.3 / §4.11). The encoding therefore has to be:
//!
//! - **Versioned** — an `LP1-` prefix so the format can evolve.
//! - **Unambiguous to read/type** — Crockford base32 excludes the confusable
//!   letters `I`, `L`, `O`, `U`, and is case-insensitive on input.
//! - **Grouped** — dashes every 5 characters for legibility, ignored on input.
//! - **Self-checking** — a checksum so a *single* mistyped character is
//!   rejected rather than silently producing the wrong key.
//!
//! # Layout
//!
//! ```text
//! LP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX   (dash-grouped Crockford base32)
//!      └───────────── base32( key(16) || crc32(key)(4) ) ─────────────┘
//! ```
//!
//! We encode **20 bytes**: the 16 key bytes followed by a 4-byte big-endian
//! CRC-32 (IEEE) over the key. 20 bytes = 160 bits = **exactly 32** Crockford
//! base32 symbols (5 bits/symbol), so the encoding is bit-aligned with **no
//! trailing partial symbol** — this avoids the non-canonical-trailing-bit
//! fragility that a non-multiple-of-5 payload would introduce.
//!
//! On decode we normalise the input (see [`normalize`]), Crockford-decode,
//! recompute the CRC over the key bytes, and compare it against the trailing 4
//! bytes in constant time.
//!
//! # Why CRC-32 (and why a checksum at all)
//!
//! The checksum is a *typo* detector, not a security control — the Secret
//! Key's strength comes from its 128 bits of entropy, not the checksum. CRC-32
//! reliably catches single-character substitutions (and all burst errors up to
//! 32 bits), which more than satisfies the "reject any single-character
//! corruption" requirement, while sizing the payload to a clean base32 length.

use data_encoding::{Encoding, Specification};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::keys::SECRET_KEY_LEN;

/// Versioned prefix emitted on every display string (tag + separator dash).
const PREFIX: &str = "LP1-";

/// The version tag alone, without the separator. Recognised on input whether or
/// not the user typed the following dash.
const PREFIX_TAG: &str = "LP1";

/// Characters per readability group between dashes.
const GROUP: usize = 5;

/// Length of the CRC-32 checksum appended to the key, in bytes.
const CRC_LEN: usize = 4;

/// Total encoded payload length in bytes (`key || crc32`), a multiple of 5 so
/// it maps to a whole number of base32 symbols.
const PAYLOAD_LEN: usize = SECRET_KEY_LEN + CRC_LEN;

/// Number of Crockford base32 characters in the payload (`PAYLOAD_LEN * 8 / 5`).
const PAYLOAD_CHARS: usize = PAYLOAD_LEN * 8 / 5;

/// Canonical (uppercase, unpadded) Crockford base32 codec.
///
/// We deliberately do **not** rely on `data-encoding`'s translate feature for
/// confusable folding; that folding is done explicitly in [`normalize`] so the
/// mapping is auditable in plain Rust rather than buried in a spec table.
fn crockford() -> Encoding {
    let mut spec = Specification::new();
    // Crockford alphabet: 0-9 A-Z minus I, L, O, U.
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    // No padding: our payload is a fixed, bit-aligned length.
    spec.padding = None;
    spec.encoding()
        .expect("static canonical Crockford base32 specification is valid")
}

/// Normalise a user-entered display body to canonical Crockford symbols.
///
/// Uppercases, strips the group separators (`-` and spaces), and folds the
/// Crockford confusables to their canonical digit: `O`/`o` → `0`, and `I`/`i`
/// / `L`/`l` → `1`. Any other character is passed through unchanged; if it is
/// not a valid symbol, the subsequent decode step rejects it.
fn normalize(body: &str) -> String {
    body.chars()
        .filter_map(|c| match c.to_ascii_uppercase() {
            '-' | ' ' => None,
            'O' => Some('0'),
            'I' | 'L' => Some('1'),
            other => Some(other),
        })
        .collect()
}

/// CRC-32/IEEE (reflected, init `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`) over
/// `data`. A compact, dependency-free typo detector. Not cryptographic — see
/// the module docs for why that is the right choice here.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Encode 16 key bytes to the grouped, checksummed display string.
pub(crate) fn encode(key: &[u8; SECRET_KEY_LEN]) -> String {
    // payload = key || crc32(key)  (big-endian checksum)
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..SECRET_KEY_LEN].copy_from_slice(key);
    payload[SECRET_KEY_LEN..].copy_from_slice(&crc32(key).to_be_bytes());

    let b32 = crockford().encode(&payload);
    payload.zeroize();
    debug_assert_eq!(b32.len(), PAYLOAD_CHARS);

    // Prefix, then group the 32 symbols into fives with dashes.
    let mut out = String::with_capacity(PREFIX.len() + PAYLOAD_CHARS + PAYLOAD_CHARS / GROUP);
    out.push_str(PREFIX);
    for (i, ch) in b32.chars().enumerate() {
        if i != 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Decode a display string back to 16 key bytes, verifying prefix and checksum.
///
/// # Errors
///
/// [`Error::InvalidSecretKeyEncoding`] for a missing/wrong prefix, an
/// out-of-alphabet character, a wrong decoded length, or a checksum mismatch
/// (any single-character corruption trips the alphabet check or the checksum).
pub(crate) fn decode(s: &str) -> Result<[u8; SECRET_KEY_LEN]> {
    // Uppercase and strip *layout* characters (dashes, spaces) across the whole
    // input first — but do NOT fold confusables yet, because the version tag
    // "LP1" itself contains an `L` that would be mis-folded to `1`.
    let stripped: String = s
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // The tag is recognised with or without its trailing dash (already stripped).
    let body = stripped
        .strip_prefix(PREFIX_TAG)
        .ok_or(Error::InvalidSecretKeyEncoding(
            "missing or wrong LP1 prefix",
        ))?;

    // Now fold Crockford confusables on the payload body only.
    let normalized = normalize(body);
    let mut decoded = crockford()
        .decode(normalized.as_bytes())
        .map_err(|_| Error::InvalidSecretKeyEncoding("invalid base32 / bad character"))?;

    if decoded.len() != PAYLOAD_LEN {
        decoded.zeroize();
        return Err(Error::InvalidSecretKeyEncoding("wrong decoded length"));
    }

    let (key_bytes, crc_bytes) = decoded.split_at(SECRET_KEY_LEN);
    let expected = crc32(key_bytes).to_be_bytes();
    // Constant-time compare of the 4 checksum bytes.
    let ok: bool = expected.ct_eq(&crc_bytes[..CRC_LEN]).into();

    let mut key = [0u8; SECRET_KEY_LEN];
    key.copy_from_slice(key_bytes);
    decoded.zeroize();

    if ok {
        Ok(key)
    } else {
        key.zeroize();
        Err(Error::InvalidSecretKeyEncoding("checksum mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; SECRET_KEY_LEN] {
        [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB,
        ]
    }

    #[test]
    fn encode_shape_is_correct() {
        let s = encode(&sample_key());
        assert!(s.starts_with("LP1-"));
        // 32 payload chars grouped in 5s → 6 dashes between groups after the prefix.
        let body = &s[PREFIX.len()..];
        let symbols: String = body.chars().filter(|c| *c != '-').collect();
        assert_eq!(symbols.len(), PAYLOAD_CHARS);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let key = sample_key();
        let s = encode(&key);
        assert_eq!(decode(&s).unwrap(), key);
    }

    #[test]
    fn case_and_dash_insensitive() {
        let key = sample_key();
        let s = encode(&key);
        assert_eq!(decode(&s.to_lowercase()).unwrap(), key);
        // Fully dash-free entry (including no dash after the LP1 tag) still works.
        assert_eq!(decode(&s.replace('-', "")).unwrap(), key);
        // Confusable substitution in the PAYLOAD (0→O, 1→I) still decodes; the
        // fixed "LP1-" tag is copied verbatim in real use, so only fold the body.
        let (tag, body) = s.split_at(PREFIX.len());
        let confused = format!("{tag}{}", body.replace('0', "O").replace('1', "I"));
        assert_eq!(decode(&confused).unwrap(), key);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let s = encode(&sample_key());
        let bad = s.replacen("LP1-", "LP2-", 1);
        assert!(matches!(
            decode(&bad),
            Err(Error::InvalidSecretKeyEncoding(_))
        ));
    }

    /// The core requirement: any single-character corruption must be rejected.
    /// We flip every payload position to a *different valid symbol* and confirm
    /// the checksum (or alphabet check) catches all of them.
    #[test]
    fn rejects_any_single_character_corruption() {
        let key = sample_key();
        let s = encode(&key);
        let chars: Vec<char> = s.chars().collect();
        let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        let mut checked = 0usize;
        for (i, &orig) in chars.iter().enumerate() {
            // Skip the fixed "LP1-" prefix and the dash separators.
            if i < PREFIX.len() || orig == '-' {
                continue;
            }
            for repl in alphabet.chars() {
                if repl == orig {
                    continue;
                }
                let mut m = chars.clone();
                m[i] = repl;
                let corrupted: String = m.into_iter().collect();
                assert!(
                    decode(&corrupted).is_err(),
                    "single-char corruption at {i} ({orig}->{repl}) was NOT rejected"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "expected to check some corruptions");
    }

    #[test]
    fn rejects_out_of_alphabet_character() {
        // 'U' is excluded from the Crockford alphabet and is not a folded
        // confusable, so a body containing it must fail to decode.
        let s = encode(&sample_key());
        let mut chars: Vec<char> = s.chars().collect();
        // Replace the first payload symbol (just after "LP1-") with 'U'.
        chars[PREFIX.len()] = 'U';
        let corrupted: String = chars.into_iter().collect();
        assert!(decode(&corrupted).is_err());
    }
}
