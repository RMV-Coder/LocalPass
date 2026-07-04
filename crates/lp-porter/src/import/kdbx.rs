//! KeePass KDBX 4 import — **stubbed** in this build.
//!
//! # Why stubbed (the best-effort decision, PRD §4.6 / work-unit scope)
//!
//! The task allowed implementing KDBX *only if* the `keepass` crate integrated
//! cleanly and did not bloat the dependency tree unreasonably. It does not, for
//! this project:
//!
//! - `keepass 0.13` pulls in **~85 transitive crates**, including a **second,
//!   parallel crypto stack** — `aes`, `chacha20`, `salsa20`, `twofish`,
//!   `sha2 0.11`, `hmac`, `rust-argon2`, `cbc`/`block-modes`, `quick-xml`,
//!   `chrono`. LocalPass deliberately confines cryptographic primitives to
//!   `lp-crypto` (the crypto-boundary rule); importing an independent primitive
//!   stack into a leaf crate cuts against that and enlarges the audit surface a
//!   secrets manager least wants enlarged.
//! - Those crates track the bleeding edge of RustCrypto (`cipher 0.5`,
//!   `crypto-common 0.2`, `sha2 0.11`) and would collide with `lp-crypto`'s
//!   pinned older RustCrypto versions, tripping cargo-deny's
//!   `multiple-versions` lint across the workspace.
//!
//! All licenses in the `keepass` tree happen to be within the allowlist, so the
//! block is **dependency weight and crypto-surface duplication**, not licensing.
//!
//! The foreign-format crypto exception in this crate's docs *permits* depending
//! on `keepass` for KDBX; it does not *require* it. We take the documented
//! escape: stub the command with a clear message so the wave is not blocked, and
//! leave a single, well-isolated integration point ([`parse_file`]) for a later
//! work unit to fill in behind a Cargo feature.

use crate::error::{PorterError, Result};
use crate::model::ImportOutcome;

/// Parse a KDBX 4 database at `path`, unlocking with `password`.
///
/// **Not implemented in this build.** Always returns
/// [`PorterError::Unsupported`] with a clear, actionable message. The signature
/// is the one a real implementation would take (path + password), so wiring it
/// up later is a drop-in.
///
/// # Errors
///
/// Always [`PorterError::Unsupported`].
pub fn parse_file(_path: &std::path::Path, _password: &str) -> Result<ImportOutcome> {
    Err(PorterError::Unsupported(
        "KDBX import is not yet supported in this build; \
         export from KeePass to CSV and use `localpass import csv` instead"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_unsupported_cleanly() {
        let err = parse_file(std::path::Path::new("x.kdbx"), "pw").unwrap_err();
        assert!(matches!(err, PorterError::Unsupported(_)));
        assert!(err.to_string().contains("not yet supported"));
    }
}
