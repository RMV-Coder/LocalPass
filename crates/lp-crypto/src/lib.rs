#![forbid(unsafe_code)]
//! LocalPass cryptographic core.
//!
//! This crate is the *only* place in the workspace that may depend on
//! cryptographic primitive crates; everything else consumes the
//! misuse-resistant API exposed here.
//!
//! Implementation pending — see `PRD.md` §4.3/§5.2/§6.2 and `docs/specs/`.
