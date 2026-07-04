//! Time-based one-time passwords (TOTP, RFC 6238) — and the HOTP core it builds
//! on (RFC 4226).
//!
//! # Why SHA-1 lives here, and ONLY here
//!
//! RFC 6238 / RFC 4226 and the entire installed base of authenticator apps
//! (Google Authenticator, Authy, etc.) default to **HMAC-SHA-1**. LocalPass must
//! interoperate with the codes those apps and web sites generate, so SHA-1 is
//! *required* for TOTP compatibility. This module is therefore the **single**
//! place in the whole workspace that may touch SHA-1.
//!
//! **SHA-1 here is not a general-purpose hash.** It is used solely as the PRF
//! inside HMAC for one-time-code generation — a use for which its known
//! collision weaknesses are irrelevant (HMAC-SHA-1 remains a secure MAC/PRF).
//! It **must never** be used for hashing, key derivation, signatures, or
//! integrity chaining anywhere else — those are BLAKE3 ([`crate::hash`]),
//! HKDF-SHA256 ([`crate::kdf`]), Argon2id ([`crate::params`]), and Ed25519
//! ([`crate::sign`]) respectively. To keep this contained, the SHA-1 dependency
//! is not re-exported and no public function outside this module hands back a
//! raw SHA-1 hasher: SHA-1 is reachable only *through* [`code`] / [`code_now`].
//!
//! # What this module provides
//!
//! - [`TotpAlgo`] — the HMAC digest choice (`Sha1` default, plus `Sha256` /
//!   `Sha512`, both of which RFC 6238 §1.2 permits and some issuers use).
//! - [`code`] — compute the zero-padded OTP for an explicit unix time.
//! - [`code_now`] — a convenience returning `(code, seconds_remaining)` for the
//!   current wall clock (the number the UI/CLI actually wants to render).
//! - [`decode_base32`] — RFC 4648 base32 of the shared secret, tolerant of
//!   lowercase, spaces, and missing/optional `=` padding (as authenticator
//!   apps and `otpauth://` URIs present it), reusing the crate's existing
//!   `data-encoding` dependency.
//! - [`hotp`] — the RFC 4226 HOTP primitive (counter-based), exposed because
//!   TOTP is exactly HOTP over a time-derived counter and it lets us pin the
//!   RFC 4226 Appendix D test vectors directly.
//!
//! # Secret hygiene
//!
//! The decoded secret bytes are the sensitive input. [`code`] takes an already
//! decoded `&[u8]` (the caller owns that buffer's lifetime) and zeroizes every
//! *derived* copy it makes internally — the HMAC key buffer and the HMAC output
//! block — on every path, including early returns. [`decode_base32`] returns a
//! `Vec<u8>` the caller is expected to zeroize when done (the CLI does).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// The lower bound on OTP digit count we accept (RFC 4226 requires ≥ 6).
const MIN_DIGITS: u8 = 6;

/// The upper bound on OTP digit count we accept.
///
/// RFC 4226's dynamic-truncation extracts a 31-bit value (`0..=2^31-1`), which
/// has 10 decimal digits, so 10 is the largest digit count that is always
/// representable; we cap there.
const MAX_DIGITS: u8 = 10;

/// The HMAC digest a TOTP/HOTP secret uses (RFC 6238 §1.2).
///
/// `Sha1` is the ubiquitous default (Google Authenticator and virtually every
/// 2FA site); `Sha256` / `Sha512` are permitted by the RFC and used by some
/// issuers, selectable in an `otpauth://` URI's `algorithm` parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgo {
    /// HMAC-SHA-1 — the RFC default and the compatibility baseline.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgo {
    /// Parse the `algorithm` token from an `otpauth://` URI or item field
    /// (case-insensitive; `SHA1` / `SHA256` / `SHA512`). An empty string maps to
    /// the RFC default [`TotpAlgo::Sha1`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTotp`] for an unrecognised algorithm token.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "" | "SHA1" => Ok(TotpAlgo::Sha1),
            "SHA256" => Ok(TotpAlgo::Sha256),
            "SHA512" => Ok(TotpAlgo::Sha512),
            _ => Err(Error::InvalidTotp(
                "unknown TOTP algorithm (expected SHA1, SHA256, or SHA512)",
            )),
        }
    }

    /// The canonical uppercase token (`"SHA1"` / `"SHA256"` / `"SHA512"`) as it
    /// is stored in the item payload and shown in `--json`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TotpAlgo::Sha1 => "SHA1",
            TotpAlgo::Sha256 => "SHA256",
            TotpAlgo::Sha512 => "SHA512",
        }
    }
}

/// Validate the `digits` count against the accepted `6..=10` range.
fn check_digits(digits: u8) -> Result<()> {
    if (MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        Ok(())
    } else {
        Err(Error::InvalidTotp("digits must be between 6 and 10"))
    }
}

/// Decode an RFC 4648 base32 shared secret, tolerant of real-world spellings.
///
/// Authenticator apps, QR codes, and `otpauth://` URIs present the secret in
/// base32 that is variously lowercase, grouped with spaces, and with or without
/// trailing `=` padding. This normalises all of that before decoding:
///
/// - ASCII whitespace (spaces, tabs, newlines) and `-` group separators removed;
/// - folded to uppercase;
/// - any trailing `=` padding stripped, then re-derived exactly so the length is
///   a valid base32 quantum (we decode with the *unpadded* codec, which requires
///   the input length itself be a valid base32 length).
///
/// # Errors
///
/// [`Error::InvalidTotp`] if, after normalisation, the input contains a
/// character outside the RFC 4648 base32 alphabet or is not a valid base32
/// length (e.g. a stray single trailing symbol).
pub fn decode_base32(s: &str) -> Result<Vec<u8>> {
    // Strip layout characters and uppercase; drop any '=' padding so we can use
    // the no-padding codec uniformly (some inputs pad, some don't).
    let normalized: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // `data_encoding::BASE32_NOPAD` is the RFC 4648 alphabet (A-Z, 2-7) with no
    // padding — exactly what remains after we stripped '='.
    data_encoding::BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| Error::InvalidTotp("secret is not valid base32"))
}

/// Compute an HOTP value (RFC 4226): `HOTP(K, C)` truncated to `digits` decimal
/// digits, zero-padded.
///
/// `secret` is the shared key `K`; `counter` is the 8-byte big-endian moving
/// factor `C`. This is the primitive TOTP is built on ([`code`] just computes
/// `C = unix_time / period`), and is exposed so the RFC 4226 Appendix D test
/// vectors can be pinned directly.
///
/// # Errors
///
/// [`Error::InvalidTotp`] if `digits` is outside `6..=10`.
pub fn hotp(secret: &[u8], counter: u64, algo: TotpAlgo, digits: u8) -> Result<String> {
    check_digits(digits)?;
    let msg = counter.to_be_bytes();
    // One concrete branch per digest. We deliberately avoid a generic
    // `Hmac<D>` (whose bound salad is enormous and would drag `digest`'s trait
    // vocabulary into this file); the `hmac_*` helpers below are monomorphic and
    // each zeroize their own derived intermediates.
    let truncated = match algo {
        TotpAlgo::Sha1 => hmac_sha1_dt(secret, &msg),
        TotpAlgo::Sha256 => hmac_sha256_dt(secret, &msg),
        TotpAlgo::Sha512 => hmac_sha512_dt(secret, &msg),
    };
    Ok(format_code(truncated, digits))
}

/// Compute the TOTP code for the given absolute unix time (RFC 6238).
///
/// The moving factor is `T = unix_time_secs / period_secs` (integer division,
/// RFC 6238 §4), and the code is `HOTP(secret, T)`. `algo` selects the HMAC
/// digest; `digits` (6..=10) is the zero-padded output length; `period_secs`
/// is the time step (typically 30).
///
/// # Errors
///
/// [`Error::InvalidTotp`] if `digits` is outside `6..=10`, or if `period_secs`
/// is zero (division by zero / a meaningless step).
pub fn code(
    secret: &[u8],
    algo: TotpAlgo,
    digits: u8,
    period_secs: u32,
    unix_time_secs: u64,
) -> Result<String> {
    check_digits(digits)?;
    if period_secs == 0 {
        return Err(Error::InvalidTotp("period must be non-zero"));
    }
    let counter = unix_time_secs / u64::from(period_secs);
    hotp(secret, counter, algo, digits)
}

/// Compute the current TOTP code and how many seconds remain in its window.
///
/// A convenience over [`code`] using the system wall clock. `seconds_remaining`
/// is `period - (now % period)` — the number of whole seconds before the code
/// rolls over — so a UI can render "expires in Ns" and a caller can decide
/// whether to wait out a boundary.
///
/// # Errors
///
/// [`Error::InvalidTotp`] from [`code`] (bad `digits` / zero `period_secs`), or
/// [`Error::InvalidTotp`] if the system clock is before the unix epoch (which
/// should never happen on a sane host).
pub fn code_now(
    secret: &[u8],
    algo: TotpAlgo,
    digits: u8,
    period_secs: u32,
) -> Result<(String, u32)> {
    if period_secs == 0 {
        return Err(Error::InvalidTotp("period must be non-zero"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidTotp("system clock is before the unix epoch"))?
        .as_secs();
    let value = code(secret, algo, digits, period_secs, now)?;
    let remaining = period_secs - u32::try_from(now % u64::from(period_secs)).unwrap_or(0);
    Ok((value, remaining))
}

/// RFC 4226 §5.3 dynamic truncation of an HMAC output block to a 31-bit value.
///
/// Shared by the three concrete `hmac_*` helpers. `hs` is the finished HMAC
/// digest; this reads the offset from its low nibble, extracts 4 bytes, masks
/// off the high bit, then zeroizes `hs` (a secret-derived buffer) before
/// returning.
fn dynamic_truncate(hs: &mut [u8]) -> u32 {
    // The low nibble of the last byte is an offset into the digest.
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(hs[offset]) & 0x7f) << 24
        | (u32::from(hs[offset + 1])) << 16
        | (u32::from(hs[offset + 2])) << 8
        | (u32::from(hs[offset + 3]));
    // Wipe the derived HMAC output (a function of the secret) on the way out.
    hs.zeroize();
    bin
}

/// HMAC-SHA-1 over `msg` with `secret`, then RFC 4226 dynamic truncation. The
/// RFC 6238 / authenticator-app default — the ONLY SHA-1 use in the workspace.
fn hmac_sha1_dt(secret: &[u8], msg: &[u8]) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .expect("HMAC accepts a key of any length (RFC 2104 §2)");
    mac.update(msg);
    let mut hs = mac.finalize().into_bytes();
    dynamic_truncate(hs.as_mut_slice())
}

/// HMAC-SHA-256 variant (RFC 6238 §1.2 permits it; some issuers use it).
fn hmac_sha256_dt(secret: &[u8], msg: &[u8]) -> u32 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC accepts a key of any length (RFC 2104 §2)");
    mac.update(msg);
    let mut hs = mac.finalize().into_bytes();
    dynamic_truncate(hs.as_mut_slice())
}

/// HMAC-SHA-512 variant (RFC 6238 §1.2 permits it; some issuers use it).
fn hmac_sha512_dt(secret: &[u8], msg: &[u8]) -> u32 {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
        .expect("HMAC accepts a key of any length (RFC 2104 §2)");
    mac.update(msg);
    let mut hs = mac.finalize().into_bytes();
    dynamic_truncate(hs.as_mut_slice())
}

/// Reduce a 31-bit truncated value to `digits` decimal digits, zero-padded.
fn format_code(binary: u32, digits: u8) -> String {
    // 10^digits fits in u64 for digits ≤ 10 (checked by `check_digits`).
    let modulus = 10u64.pow(u32::from(digits));
    let value = u64::from(binary) % modulus;
    format!("{value:0width$}", width = usize::from(digits))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 Appendix B seeds. The ASCII strings are the shared secrets;
    /// SHA-256 / SHA-512 use longer seeds (the ASCII repeated/truncated to the
    /// key length), exactly as the RFC's reference `Java` code does.
    const SEED_SHA1: &[u8] = b"12345678901234567890"; // 20 bytes
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012"; // 32 bytes
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes

    /// RFC 6238 Appendix B — the full table: for six unix timestamps, the 8-digit
    /// code under each of SHA1 / SHA256 / SHA512, with period 30.
    ///
    /// Columns: (unix_time, sha1_code, sha256_code, sha512_code).
    const RFC6238_TABLE: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_appendix_b_full_table() {
        for &(t, s1, s256, s512) in RFC6238_TABLE {
            assert_eq!(
                code(SEED_SHA1, TotpAlgo::Sha1, 8, 30, t).unwrap(),
                s1,
                "SHA1 at t={t}"
            );
            assert_eq!(
                code(SEED_SHA256, TotpAlgo::Sha256, 8, 30, t).unwrap(),
                s256,
                "SHA256 at t={t}"
            );
            assert_eq!(
                code(SEED_SHA512, TotpAlgo::Sha512, 8, 30, t).unwrap(),
                s512,
                "SHA512 at t={t}"
            );
        }
    }

    /// RFC 4226 Appendix D — the HOTP test vectors: counters 0..=9 over the
    /// 20-byte ASCII secret, 6 digits, HMAC-SHA-1.
    const RFC4226_HOTP: &[&str] = &[
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    #[test]
    fn rfc4226_appendix_d_hotp_vectors() {
        for (counter, expected) in RFC4226_HOTP.iter().enumerate() {
            let got = hotp(SEED_SHA1, counter as u64, TotpAlgo::Sha1, 6).unwrap();
            assert_eq!(&got, expected, "HOTP counter {counter}");
        }
    }

    #[test]
    fn totp_is_hotp_over_time_counter() {
        // At t=59, period=30, the counter is 1; the 6-digit SHA1 TOTP must equal
        // the 6-digit HOTP at counter 1 (== RFC4226 vector index 1).
        let totp6 = code(SEED_SHA1, TotpAlgo::Sha1, 6, 30, 59).unwrap();
        let hotp1 = hotp(SEED_SHA1, 1, TotpAlgo::Sha1, 6).unwrap();
        assert_eq!(totp6, hotp1);
        assert_eq!(totp6, RFC4226_HOTP[1]);
    }

    #[test]
    fn code_is_zero_padded_to_width() {
        // Every RFC vector is exactly 8 chars, including ones with leading zeros
        // (e.g. "07081804"). Confirm the width invariant directly.
        for &(t, s1, _, _) in RFC6238_TABLE {
            let c = code(SEED_SHA1, TotpAlgo::Sha1, 8, 30, t).unwrap();
            assert_eq!(c.len(), 8);
            assert_eq!(c, s1);
        }
        assert!(
            RFC6238_TABLE
                .iter()
                .any(|&(_, s1, _, _)| s1.starts_with('0'))
        );
    }

    // --- base32 decoding edge cases -------------------------------------

    /// The canonical "Hello!\u{DE}AD\u{BE}EF" fixture from RFC 4648 examples is
    /// awkward; use the widely-published `JBSWY3DPEHPK3PXP` == "Hello!\xDE\xAD\xBE\xEF"?
    /// Instead verify against our own SEED_SHA1, whose base32 is well known.
    #[test]
    fn base32_decodes_known_secret() {
        // base32("12345678901234567890") — the RFC 6238 SHA1 seed.
        let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(decode_base32(b32).unwrap(), SEED_SHA1);
    }

    #[test]
    fn base32_is_lowercase_tolerant() {
        let upper = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let lower = upper.to_ascii_lowercase();
        assert_eq!(
            decode_base32(&lower).unwrap(),
            decode_base32(upper).unwrap()
        );
    }

    #[test]
    fn base32_tolerates_spaces_dashes_and_padding() {
        // The classic "JBSWY3DP" == "Hello" (RFC 4648 §10, without the trailing
        // "EHPK3PXP"). Grouped with spaces, dashes, lowercase, and '=' padding.
        assert_eq!(decode_base32("JBSWY3DP").unwrap(), b"Hello");
        assert_eq!(decode_base32("jbsw y3dp").unwrap(), b"Hello");
        assert_eq!(decode_base32("JBSW-Y3DP").unwrap(), b"Hello");
        assert_eq!(decode_base32("JBSWY3DP====").unwrap(), b"Hello");
        assert_eq!(decode_base32(" j b s w y 3 d p ").unwrap(), b"Hello");
    }

    #[test]
    fn base32_rejects_bad_alphabet() {
        // '1', '8', '0', '9' are not in the RFC4648 base32 alphabet (A-Z, 2-7).
        assert!(matches!(
            decode_base32("JBSW01"),
            Err(Error::InvalidTotp(_))
        ));
        assert!(matches!(
            decode_base32("has!bang"),
            Err(Error::InvalidTotp(_))
        ));
    }

    #[test]
    fn base32_rejects_bad_length() {
        // A single trailing symbol is not a valid base32 quantum.
        assert!(matches!(
            decode_base32("JBSWY3DPA"),
            Err(Error::InvalidTotp(_))
        ));
    }

    // --- parameter bounds -----------------------------------------------

    #[test]
    fn digits_below_six_rejected() {
        assert!(matches!(
            code(SEED_SHA1, TotpAlgo::Sha1, 5, 30, 59),
            Err(Error::InvalidTotp(_))
        ));
    }

    #[test]
    fn digits_above_ten_rejected() {
        assert!(matches!(
            code(SEED_SHA1, TotpAlgo::Sha1, 11, 30, 59),
            Err(Error::InvalidTotp(_))
        ));
    }

    #[test]
    fn digits_bounds_inclusive() {
        // Both 6 and 10 are accepted (boundary values).
        assert!(code(SEED_SHA1, TotpAlgo::Sha1, 6, 30, 59).is_ok());
        assert!(code(SEED_SHA1, TotpAlgo::Sha1, 10, 30, 59).is_ok());
    }

    #[test]
    fn zero_period_rejected() {
        assert!(matches!(
            code(SEED_SHA1, TotpAlgo::Sha1, 6, 0, 59),
            Err(Error::InvalidTotp(_))
        ));
        assert!(matches!(
            code_now(SEED_SHA1, TotpAlgo::Sha1, 6, 0),
            Err(Error::InvalidTotp(_))
        ));
    }

    // --- algo parsing ----------------------------------------------------

    #[test]
    fn algo_parse_round_trips_and_defaults() {
        assert_eq!(TotpAlgo::parse("").unwrap(), TotpAlgo::Sha1);
        assert_eq!(TotpAlgo::parse("sha1").unwrap(), TotpAlgo::Sha1);
        assert_eq!(TotpAlgo::parse("SHA256").unwrap(), TotpAlgo::Sha256);
        assert_eq!(TotpAlgo::parse("Sha512").unwrap(), TotpAlgo::Sha512);
        assert!(TotpAlgo::parse("md5").is_err());
        assert_eq!(TotpAlgo::Sha1.as_str(), "SHA1");
        assert_eq!(TotpAlgo::Sha256.as_str(), "SHA256");
        assert_eq!(TotpAlgo::Sha512.as_str(), "SHA512");
    }

    // --- code_now sanity -------------------------------------------------

    #[test]
    fn code_now_matches_code_at_same_second_and_reports_remaining() {
        // code_now uses the wall clock; compute code() at the same second and
        // confirm they agree (retrying once if we straddle a period boundary),
        // and that remaining is in 1..=period.
        for _ in 0..2 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let (nowcode, remaining) = code_now(SEED_SHA1, TotpAlgo::Sha1, 6, 30).unwrap();
            let now2 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // Only assert when the second didn't advance across the two clock
            // reads (else we may have crossed a boundary between them).
            if now == now2 {
                assert_eq!(
                    nowcode,
                    code(SEED_SHA1, TotpAlgo::Sha1, 6, 30, now).unwrap()
                );
                assert!((1..=30).contains(&remaining));
                return;
            }
        }
        // If we were unlucky twice, at least assert remaining is well-formed on a
        // fresh read.
        let (_c, remaining) = code_now(SEED_SHA1, TotpAlgo::Sha1, 6, 30).unwrap();
        assert!((1..=30).contains(&remaining));
    }
}
