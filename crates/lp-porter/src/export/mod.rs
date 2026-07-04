//! Exporters: turn [`ItemPayload`](lp_vault::ItemPayload)s into bytes.
//!
//! - [`archive`] — the age-encrypted, tar-wrapped, documented-JSON archive: the
//!   recoverable exit hatch (PRD §6.9). Decryptable by the standalone `age` CLI.
//!   Also re-importable ([`archive::decrypt_archive`]).
//! - [`plaintext`] — full-secret JSON and CSV. **Unguarded at this layer** — the
//!   caller is responsible for obtaining explicit user consent (the CLI gates it
//!   behind `--i-understand-plaintext-export`).
//! - [`dotenv`] — one env-set item → `KEY=value` lines.

pub mod archive;
pub mod dotenv;
pub mod plaintext;
