//! Parsing `otpauth://` URIs — the string a 2FA QR code encodes (PRD §4.1:
//! "codes computed locally; QR import" — the QR image itself is out of scope,
//! but the `otpauth://` URI it carries is parsed here).
//!
//! # The format (Key Uri Format, de-facto standard)
//!
//! ```text
//! otpauth://totp/Issuer:account@example.com?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
//! ```
//!
//! - **type** — the authority: `totp` (accepted) or `hotp` (rejected — LocalPass
//!   stores time-based secrets only; counter-based HOTP is not an item type).
//! - **label** — the path (after the leading `/`), percent-encoded, of the form
//!   `Issuer:account` or just `account`. The issuer here is a *fallback* for the
//!   `issuer` query parameter.
//! - **secret** — required; base32 (validated by [`lp_crypto::decode_base32`]).
//! - **issuer / algorithm / digits / period** — optional query parameters with
//!   RFC 6238 defaults (`SHA1`, `6`, `30`).
//!
//! Percent-decoding reuses the crate's existing [`crate::dotenv::percent_decode`]
//! (no new dependency). We validate the secret decodes and the algorithm/digits
//! are in range up front, so a malformed URI fails cleanly at import rather than
//! producing an item that can never generate a code.

use anyhow::Result;
use lp_crypto::TotpAlgo;
use lp_vault::payload::TypeData;

use crate::dotenv::percent_decode;
use crate::error::CliError;

/// A parsed `otpauth://totp/...` URI, ready to become a [`TypeData::Totp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthTotp {
    /// The base32 secret exactly as written in the URI (already validated to
    /// decode; stored verbatim so re-export round-trips).
    pub secret_b32: String,
    /// The canonical algorithm token (`SHA1` / `SHA256` / `SHA512`).
    pub algo: String,
    /// Digit count (RFC 6238 default 6).
    pub digits: u32,
    /// Period in seconds (RFC 6238 default 30).
    pub period: u32,
    /// The issuer label (from `issuer=` or the label prefix; may be empty).
    pub issuer: String,
    /// The account label (the part of the label after `Issuer:`; may be empty).
    pub account: String,
}

impl OtpauthTotp {
    /// Convert into the vault's [`TypeData::Totp`] payload variant.
    #[must_use]
    pub fn into_type_data(self) -> TypeData {
        TypeData::Totp {
            secret_b32: self.secret_b32,
            algo: self.algo,
            digits: self.digits,
            period: self.period,
            issuer: self.issuer,
            account: self.account,
        }
    }
}

/// Parse an `otpauth://totp/...` URI.
///
/// # Errors
///
/// [`CliError::Usage`] if the scheme is not `otpauth://`, the type is `hotp`
/// (rejected with a clear message) or unknown, the `secret` parameter is absent
/// or not valid base32, or `algorithm` / `digits` / `period` are out of range.
pub fn parse(uri: &str) -> Result<OtpauthTotp> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| CliError::usage(format!("{uri:?} is not an otpauth:// URI")))?;

    // Split "type/label?query" — the authority is up to the first '/'.
    let (kind, after_kind) = match rest.split_once('/') {
        Some((k, r)) => (k, r),
        None => (rest, ""),
    };

    match kind.to_ascii_lowercase().as_str() {
        "totp" => {}
        "hotp" => {
            return Err(CliError::usage(
                "otpauth://hotp URIs (counter-based HOTP) are not supported; \
                 LocalPass stores time-based TOTP secrets only",
            )
            .into());
        }
        other => {
            return Err(
                CliError::usage(format!("unknown otpauth type {other:?} (expected totp)")).into(),
            );
        }
    }

    // Split the label from the query string.
    let (label_raw, query) = match after_kind.split_once('?') {
        Some((l, q)) => (l, q),
        None => (after_kind, ""),
    };

    // Parse query parameters into (key, decoded-value) pairs.
    let mut secret: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm = String::new();
    let mut digits: u32 = 6;
    let mut period: u32 = 30;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        // otpauth uses form-encoding: '+' is a space in query values.
        let v_decoded = percent_decode(&v.replace('+', " ")).map_err(CliError::usage_from)?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v_decoded),
            "issuer" => issuer_param = Some(v_decoded),
            "algorithm" => algorithm = v_decoded,
            "digits" => {
                digits = v_decoded.trim().parse().map_err(|_| {
                    CliError::usage(format!("otpauth digits {v_decoded:?} is not a number"))
                })?;
            }
            "period" => {
                period = v_decoded.trim().parse().map_err(|_| {
                    CliError::usage(format!("otpauth period {v_decoded:?} is not a number"))
                })?;
            }
            // Unknown parameters (e.g. counter for hotp, image) are ignored.
            _ => {}
        }
    }

    // The label is `Issuer:account` or `account`, percent-encoded.
    let label = percent_decode(label_raw).map_err(CliError::usage_from)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((iss, acc)) => (iss.trim().to_string(), acc.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    // The `issuer=` query parameter wins over the label prefix (spec guidance);
    // fall back to the label issuer when the parameter is absent.
    let issuer = issuer_param.unwrap_or(label_issuer);

    // Validate the secret is present and decodes as base32 (fail early).
    let secret_b32 = secret
        .ok_or_else(|| CliError::usage(format!("otpauth URI {uri:?} has no `secret` parameter")))?;
    if secret_b32.is_empty() {
        return Err(CliError::usage("otpauth `secret` is empty").into());
    }
    lp_crypto::decode_base32(&secret_b32)
        .map_err(|_| CliError::usage("otpauth `secret` is not valid base32"))?;

    // Validate the algorithm and digit range up front.
    let algo = TotpAlgo::parse(&algorithm)
        .map_err(|_| {
            CliError::usage(format!(
                "otpauth algorithm {algorithm:?} is not one of SHA1/SHA256/SHA512"
            ))
        })?
        .as_str()
        .to_string();
    if !(6..=10).contains(&digits) {
        return Err(CliError::usage("otpauth digits must be between 6 and 10").into());
    }
    if period == 0 {
        return Err(CliError::usage("otpauth period must be non-zero").into());
    }

    Ok(OtpauthTotp {
        secret_b32,
        algo,
        digits,
        period,
        issuer,
        account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_uri() {
        let uri = "otpauth://totp/ACME%20Co:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60";
        let p = parse(uri).unwrap();
        assert_eq!(p.secret_b32, "JBSWY3DPEHPK3PXP");
        assert_eq!(p.algo, "SHA256");
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert_eq!(p.issuer, "ACME Co");
        assert_eq!(p.account, "alice@acme.com");
    }

    #[test]
    fn applies_rfc_defaults() {
        // Only a secret and label; algorithm/digits/period default.
        let uri = "otpauth://totp/me@example.com?secret=JBSWY3DPEHPK3PXP";
        let p = parse(uri).unwrap();
        assert_eq!(p.algo, "SHA1");
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
        assert_eq!(p.issuer, "");
        assert_eq!(p.account, "me@example.com");
    }

    #[test]
    fn issuer_param_wins_over_label_prefix() {
        let uri = "otpauth://totp/OldName:acct?secret=JBSWY3DPEHPK3PXP&issuer=NewName";
        let p = parse(uri).unwrap();
        assert_eq!(p.issuer, "NewName");
        assert_eq!(p.account, "acct");
    }

    #[test]
    fn label_issuer_used_when_no_param() {
        let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP";
        let p = parse(uri).unwrap();
        assert_eq!(p.issuer, "GitHub");
        assert_eq!(p.account, "octocat");
    }

    #[test]
    fn rejects_hotp_clearly() {
        let uri = "otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=0";
        let err = parse(uri).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hotp") || msg.contains("HOTP"), "msg: {msg}");
        assert!(msg.to_lowercase().contains("not supported"), "msg: {msg}");
    }

    #[test]
    fn rejects_non_otpauth_scheme() {
        assert!(parse("https://example.com/totp").is_err());
    }

    #[test]
    fn rejects_missing_secret() {
        let err = parse("otpauth://totp/acct?issuer=X").unwrap_err();
        assert!(format!("{err:#}").contains("secret"));
    }

    #[test]
    fn rejects_bad_base32_secret() {
        // '1' and '0' are not in the base32 alphabet.
        let err = parse("otpauth://totp/acct?secret=10101010").unwrap_err();
        assert!(format!("{err:#}").contains("base32"));
    }

    #[test]
    fn rejects_bad_algorithm() {
        let err = parse("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").unwrap_err();
        assert!(format!("{err:#}").contains("SHA1"));
    }

    #[test]
    fn rejects_out_of_range_digits() {
        let err = parse("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP&digits=12").unwrap_err();
        assert!(format!("{err:#}").contains("digits"));
    }

    #[test]
    fn plus_in_query_is_space() {
        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=ACME+Corp";
        let p = parse(uri).unwrap();
        assert_eq!(p.issuer, "ACME Corp");
    }
}
