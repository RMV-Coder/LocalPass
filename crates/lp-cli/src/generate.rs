//! Secret generation: random character passwords and EFF-wordlist passphrases,
//! with an entropy estimate in bits.
//!
//! # Randomness
//!
//! All randomness comes from [`getrandom::fill`], the OS CSPRNG — the *same*
//! source `lp-crypto` uses (`getrandom` → `OsRng`, PRD §5.2). `getrandom` is
//! permitted directly here (and only here) because generation randomness is not
//! key-hierarchy material; no key ever originates in this crate. Selection is
//! **rejection-sampled** so every character / word is uniform over its set (no
//! modulo bias).
//!
//! # Entropy accounting
//!
//! Because each element is drawn uniformly and independently, the entropy of
//! the whole secret is `count * log2(set_size)` bits — an exact figure for the
//! generator (it is the attacker's search cost against *this* process, not a
//! guess-strength model like zxcvbn, which is deliberately out of scope here).

use anyhow::{Result, bail};

use crate::wordlist::{EFF_SHORT, EFF_SHORT_LEN};

/// The symbol set used when symbols are enabled. A conservative, shell-safe-ish
/// punctuation set (no space, no quotes/backticks/backslashes that commonly
/// break copy-paste into shells or CSVs).
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
/// Uppercase + lowercase letters and digits — the always-on base charset.
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A generated secret and its exact entropy in bits.
pub struct Generated {
    /// The generated secret (password or passphrase).
    pub secret: String,
    /// Entropy of the generation process, in bits.
    pub entropy_bits: f64,
}

/// Fill `dest` with cryptographically secure random bytes from the OS CSPRNG.
fn os_random(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|e| anyhow::anyhow!("OS randomness unavailable: {e}"))?;
    Ok(())
}

/// Draw a uniform `usize` in `0..n` by rejection sampling over `u32`, avoiding
/// modulo bias. `n` must be in `1..=u32::MAX`.
fn uniform_below(n: u32) -> Result<u32> {
    debug_assert!(n > 0);
    // Largest multiple of n that fits in u32; reject draws at or above it.
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

/// Generate a random character password of `length` over the alphanumeric set
/// plus optional symbols.
///
/// # Errors
///
/// Fails if `length == 0` or the OS CSPRNG is unavailable.
pub fn password(length: usize, symbols: bool) -> Result<Generated> {
    if length == 0 {
        bail!("password length must be at least 1");
    }
    // Build the charset once.
    let mut charset: Vec<u8> = ALNUM.to_vec();
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    let set_size = u32::try_from(charset.len()).expect("charset fits in u32");

    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let idx = uniform_below(set_size)? as usize;
        out.push(charset[idx] as char);
    }
    let entropy_bits = length as f64 * f64::from(set_size).log2();
    Ok(Generated {
        secret: out,
        entropy_bits,
    })
}

/// Generate an EFF-short-wordlist passphrase of `words` words joined by
/// `separator`.
///
/// # Errors
///
/// Fails if `words == 0` or the OS CSPRNG is unavailable.
pub fn passphrase(words: usize, separator: &str) -> Result<Generated> {
    if words == 0 {
        bail!("passphrase must have at least 1 word");
    }
    let set_size = u32::try_from(EFF_SHORT_LEN).expect("wordlist length fits in u32");
    let mut picked = Vec::with_capacity(words);
    for _ in 0..words {
        let idx = uniform_below(set_size)? as usize;
        picked.push(EFF_SHORT[idx]);
    }
    let secret = picked.join(separator);
    let entropy_bits = words as f64 * f64::from(set_size).log2();
    Ok(Generated {
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
    fn password_no_symbols_is_alphanumeric() {
        let g = password(64, false).unwrap();
        assert!(g.secret.chars().all(|c| c.is_ascii_alphanumeric()));
        // 62-symbol set → ~5.954 bits/char.
        assert!((g.entropy_bits - 64.0 * 62f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn password_with_symbols_can_include_a_symbol_over_many_draws() {
        // Over a long password the symbol class is overwhelmingly likely to appear.
        let g = password(200, true).unwrap();
        assert!(g.secret.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn passphrase_word_count_and_words_are_from_the_list() {
        let g = passphrase(5, "-").unwrap();
        let parts: Vec<&str> = g.secret.split('-').collect();
        assert_eq!(parts.len(), 5);
        for w in parts {
            assert!(EFF_SHORT.contains(&w), "word {w} not from EFF list");
        }
    }

    #[test]
    fn distinct_outputs() {
        // Two generations must differ (collision probability negligible).
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
    fn zero_is_rejected() {
        assert!(password(0, true).is_err());
        assert!(passphrase(0, "-").is_err());
    }
}
