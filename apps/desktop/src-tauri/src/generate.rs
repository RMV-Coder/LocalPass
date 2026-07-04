// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! Secret generation (random-character passwords and EFF-wordlist passphrases),
//! done **locally in the Tauri backend**.
//!
//! # Why local, not via the daemon
//!
//! The daemon IPC protocol has no `generate` operation (it is a vault-access
//! surface). Rather than additively extend the daemon for a pure, keyless,
//! stateless computation, the GUI mirrors `lp-cli`'s `generate.rs` verbatim —
//! the *same* algorithm, charset, entropy accounting, and OS-CSPRNG source.
//! This is the documented design choice (see `apps/desktop/README.md`).
//!
//! # Randomness
//!
//! All randomness comes from [`getrandom::fill`] — the OS CSPRNG, the same
//! source `lp-crypto` uses. Generation randomness is **not** key-hierarchy
//! material; no key ever originates here. Selection is **rejection-sampled** so
//! every character/word is uniform over its set (no modulo bias).
//!
//! # Entropy
//!
//! Each element is drawn uniformly and independently, so the entropy is
//! `count * log2(set_size)` bits — the attacker's exact search cost against this
//! generator, not a guess-strength model.

use crate::model::GeneratedView;

/// A shell-safe punctuation set (no space, quotes, backticks, or backslashes).
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
/// Upper + lower letters and digits — the always-on base charset.
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Fill `dest` with cryptographically secure random bytes from the OS CSPRNG.
fn os_random(dest: &mut [u8]) -> Result<(), String> {
    getrandom::fill(dest).map_err(|e| format!("OS randomness unavailable: {e}"))
}

/// Draw a uniform value in `0..n` via rejection sampling over `u32`
/// (no modulo bias). `n` must be in `1..=u32::MAX`.
fn uniform_below(n: u32) -> Result<u32, String> {
    debug_assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut buf = [0u8; 4];
        os_random(&mut buf)?;
        let v = u32::from_le_bytes(buf);
        if v < zone {
            return Ok(v % n);
        }
    }
}

/// Generate a random-character password of `length` over alphanumerics plus
/// optional symbols.
///
/// # Errors
///
/// `length == 0`, `length` too large to bound, or the CSPRNG being unavailable.
pub fn password(length: usize, symbols: bool) -> Result<GeneratedView, String> {
    if length == 0 {
        return Err("password length must be at least 1".into());
    }
    if length > 4096 {
        return Err("password length is unreasonably large (max 4096)".into());
    }
    let mut charset: Vec<u8> = ALNUM.to_vec();
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    let set_size = u32::try_from(charset.len()).map_err(|_| "charset too large".to_string())?;

    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let idx = uniform_below(set_size)? as usize;
        out.push(charset[idx] as char);
    }
    let entropy_bits = length as f64 * f64::from(set_size).log2();
    Ok(GeneratedView {
        secret: out,
        entropy_bits,
    })
}

/// Generate an EFF-short-wordlist passphrase of `words` words joined by
/// `separator`.
///
/// # Errors
///
/// `words == 0`, `words` too large, or the CSPRNG being unavailable.
pub fn passphrase(words: usize, separator: &str) -> Result<GeneratedView, String> {
    if words == 0 {
        return Err("passphrase must have at least 1 word".into());
    }
    if words > 64 {
        return Err("passphrase is unreasonably long (max 64 words)".into());
    }
    let set_size = u32::try_from(crate::wordlist::EFF_SHORT_LEN)
        .map_err(|_| "wordlist too large".to_string())?;
    let mut picked = Vec::with_capacity(words);
    for _ in 0..words {
        let idx = uniform_below(set_size)? as usize;
        picked.push(crate::wordlist::EFF_SHORT[idx]);
    }
    let secret = picked.join(separator);
    let entropy_bits = words as f64 * f64::from(set_size).log2();
    Ok(GeneratedView {
        secret,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_requested_length() {
        let g = password(24, true).unwrap();
        assert_eq!(g.secret.chars().count(), 24);
    }

    #[test]
    fn password_no_symbols_is_alphanumeric_with_exact_entropy() {
        let g = password(64, false).unwrap();
        assert!(g.secret.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!((g.entropy_bits - 64.0 * 62f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn passphrase_word_count_and_words_from_list() {
        let g = passphrase(5, "-").unwrap();
        let parts: Vec<&str> = g.secret.split('-').collect();
        assert_eq!(parts.len(), 5);
        for w in parts {
            assert!(
                crate::wordlist::EFF_SHORT.contains(&w),
                "word {w} not in list"
            );
        }
        // 1296-word list → log2(1296) bits per word.
        assert!((g.entropy_bits - 5.0 * 1296f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn distinct_outputs() {
        assert_ne!(
            password(24, true).unwrap().secret,
            password(24, true).unwrap().secret
        );
        assert_ne!(
            passphrase(6, "-").unwrap().secret,
            passphrase(6, "-").unwrap().secret
        );
    }

    #[test]
    fn zero_and_oversize_rejected() {
        assert!(password(0, true).is_err());
        assert!(password(99_999, true).is_err());
        assert!(passphrase(0, "-").is_err());
        assert!(passphrase(999, "-").is_err());
    }
}
