//! The one error type for `lp-porter`.
//!
//! # Secret hygiene (hard rule)
//!
//! No variant here ever carries a secret value. Parse failures name only
//! structural context — a line number, a field *name*, a container path, a
//! format label. A malformed input yields a clean [`PorterError`], **never** a
//! panic (untrusted-file parsing must not crash the process, PRD §5.1 / the
//! fuzzing gate in §5.6).

use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, PorterError>;

/// An import or export failure. Messages are safe to print: they never include
/// a secret value.
#[derive(Debug, Error)]
pub enum PorterError {
    /// An I/O failure reading or writing bytes (file open, read, write).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The input was not the format the importer expected (bad magic, missing
    /// required container entry, wrong top-level JSON shape). The string names
    /// only *what* was wrong structurally, never a value.
    #[error("malformed {format} input: {detail}")]
    Malformed {
        /// The format label (e.g. `"1pux"`, `"bitwarden"`, `"lastpass csv"`).
        format: &'static str,
        /// A value-free description of the structural problem.
        detail: String,
    },

    /// A ZIP container error (the `.1pux` wrapper).
    #[error("zip container error: {0}")]
    Zip(String),

    /// A CSV parsing error (LastPass / generic CSV). The `csv` crate's error is
    /// value-free at the row/field-shape level, but we still stringify it via a
    /// bounded description rather than embedding a field.
    #[error("csv error: {0}")]
    Csv(String),

    /// JSON (de)serialization failed. serde_json's message can include a snippet
    /// of the offending JSON, so we deliberately drop it and keep only a
    /// value-free label plus the line/column when available.
    #[error("json error: {0}")]
    Json(String),

    /// An age encryption/decryption failure (wrong passphrase, corrupt archive,
    /// unsupported age recipient). Collapsed to a single message so a wrong
    /// passphrase is not distinguishable from corruption (no oracle).
    #[error("archive decryption failed (wrong passphrase or corrupt archive)")]
    ArchiveDecrypt,

    /// An age encryption failure while writing the archive.
    #[error("archive encryption failed")]
    ArchiveEncrypt,

    /// The requested importer is not yet implemented in this build (KDBX stub).
    #[error("{0}")]
    Unsupported(String),

    /// A generic, value-free failure with a human message.
    #[error("{0}")]
    Other(String),
}

impl PorterError {
    /// Build a [`PorterError::Malformed`] with a value-free detail string.
    pub fn malformed(format: &'static str, detail: impl Into<String>) -> Self {
        PorterError::Malformed {
            format,
            detail: detail.into(),
        }
    }

    /// Build a [`PorterError::Other`].
    pub fn other(msg: impl Into<String>) -> Self {
        PorterError::Other(msg.into())
    }
}

impl From<serde_json::Error> for PorterError {
    fn from(e: serde_json::Error) -> Self {
        // Keep only line/column and the classification, never the payload text
        // (serde_json's Display can echo the offending token).
        PorterError::Json(format!(
            "invalid JSON at line {} column {}",
            e.line(),
            e.column()
        ))
    }
}

impl From<csv::Error> for PorterError {
    fn from(e: csv::Error) -> Self {
        // csv::Error's Display describes the shape problem (UnequalLengths, etc.)
        // and a byte position, not field contents — but to be safe we map to a
        // fixed set of value-free descriptions.
        use csv::ErrorKind;
        let detail = match e.kind() {
            ErrorKind::UnequalLengths {
                pos,
                expected_len,
                len,
            } => {
                let line = pos.as_ref().map_or(0, csv::Position::line);
                format!("ragged row at line {line}: expected {expected_len} fields, found {len}")
            }
            ErrorKind::Io(io) => format!("io: {io}"),
            ErrorKind::Utf8 { .. } => "input is not valid UTF-8".to_string(),
            _ => "malformed CSV".to_string(),
        };
        PorterError::Csv(detail)
    }
}
