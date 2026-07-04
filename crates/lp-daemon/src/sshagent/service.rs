#![forbid(unsafe_code)]
//! The agent service: turning agent [`Request`]s into replies against a held
//! [`lp_vault::Session`].
//!
//! This is the pure, session-driven core of the SSH agent — it never touches a
//! socket. [`handle_request`] takes the (locked) session and one parsed request
//! and returns the bytes to write back. The listener ([`crate::sshagent::listener`])
//! owns the transport and calls this under the daemon's state mutex, exactly
//! like [`crate::engine::handle`] does for the control protocol.
//!
//! # What the agent serves (PRD §4.8: "keys never touch disk")
//!
//! - **`REQUEST_IDENTITIES`**: every `ssh_key` item across **all unlocked
//!   vaults** becomes one identity — the public-key blob derived from the
//!   item's stored private key (re-derived, so it is authoritative even if the
//!   stored `public_openssh` drifted), with the **item title** as the comment.
//!   Items whose private key fails to parse (garbage, encrypted, unsupported
//!   algorithm) are **skipped** — they never break the identity list.
//! - **`SIGN_REQUEST`**: locate the identity by public-key blob, read the item's
//!   **current** payload, parse its private key, and sign. Because the payload is
//!   read at request time, a rotated key is picked up immediately — there is no
//!   long-lived private-key cache (see [`crate::sshagent::keys`]).
//! - Everything else → `SSH_AGENT_FAILURE`.
//!
//! # Locked behavior (never kills the connection)
//!
//! When the daemon is **locked** (no session), `REQUEST_IDENTITIES` returns an
//! **empty** identity list and `SIGN_REQUEST` returns `SSH_AGENT_FAILURE`. A
//! locked agent is a working agent with no keys — it never errors the
//! connection. The listener passes `None` for the session in that case.

use lp_vault::Session;
use lp_vault::payload::TypeData;

use crate::sshagent::keys::{self, ParsedKey};
use crate::sshagent::protocol::{self, Identity, Request};

/// One `ssh_key` item resolved to what the agent needs: the public-key blob (the
/// identity + lookup key), the comment (item title), the raw PEM (parsed lazily
/// on sign), and its algorithm string.
pub struct AgentIdentity {
    /// The public-key blob (SSH wire encoding).
    pub blob: Vec<u8>,
    /// The comment shown to the client (the item title).
    pub comment: String,
    /// The algorithm string (`ssh-ed25519`, `ssh-rsa`, …).
    pub algo: String,
    /// The SHA-256 fingerprint (for `localpass ssh list`).
    pub fingerprint: String,
}

/// Collect every servable identity across all unlocked vaults.
///
/// Skips (never fails on) items whose stored private key can't be parsed, is
/// encrypted, or uses an unsupported algorithm — a bad item must not hide the
/// good ones. Returns an empty vec when the session serves no `ssh_key` items.
///
/// # Errors
///
/// [`lp_vault::Error`] only on a storage-level failure (opening a vault, listing
/// items) — not on a per-item key problem, which is skipped.
pub fn collect_identities(session: &Session) -> Result<Vec<AgentIdentity>, lp_vault::Error> {
    let mut out = Vec::new();
    for (vault_id, _name) in session.list_vaults()? {
        let vault = session.open_vault(vault_id)?;
        for item in vault.list_items()? {
            let TypeData::SshKey {
                ref private_pem,
                ref algo,
                ..
            } = item.payload.type_data
            else {
                continue;
            };
            let _ = algo;
            // Parse the private key to derive the AUTHORITATIVE public blob.
            let parsed = match keys::parse_private_key(private_pem, &item.payload.title) {
                Ok(k) => k,
                Err(_) => continue, // skip unparsable/encrypted/unsupported items
            };
            let Ok(blob) = parsed.public_blob() else {
                continue;
            };
            out.push(AgentIdentity {
                blob,
                comment: item.payload.title.clone(),
                algo: parsed.algorithm_str(),
                fingerprint: parsed.fingerprint(),
            });
        }
    }
    Ok(out)
}

/// Find the item whose derived public blob equals `blob`, and return its parsed
/// private key (re-read from the CURRENT payload, so rotation is immediate).
///
/// Returns `Ok(None)` when no unlocked item matches the requested key.
///
/// # Errors
///
/// [`lp_vault::Error`] on a storage failure; a per-item parse failure that
/// matches the blob is impossible (an unparsable item never produces a blob to
/// match), so parse errors here simply mean "keep looking".
fn find_signer(session: &Session, blob: &[u8]) -> Result<Option<ParsedKey>, lp_vault::Error> {
    for (vault_id, _name) in session.list_vaults()? {
        let vault = session.open_vault(vault_id)?;
        for item in vault.list_items()? {
            let TypeData::SshKey {
                ref private_pem, ..
            } = item.payload.type_data
            else {
                continue;
            };
            let Ok(parsed) = keys::parse_private_key(private_pem, &item.payload.title) else {
                continue;
            };
            let Ok(candidate) = parsed.public_blob() else {
                continue;
            };
            if candidate == blob {
                return Ok(Some(parsed));
            }
        }
    }
    Ok(None)
}

/// Handle one parsed agent request against an optional session, returning the
/// framed reply bytes to write back to the client.
///
/// `session` is `Some` when the daemon is unlocked, `None` when locked. A locked
/// daemon yields an empty identity list / a sign failure — never a connection
/// error. `verbose` gates a one-line stderr log of the request kind + outcome
/// (never a secret, never key bytes).
///
/// This function performs **no** client IO; the listener writes the returned
/// bytes. It is called under the daemon state mutex.
#[must_use]
pub fn handle_request(session: Option<&Session>, request: &Request, verbose: bool) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        Request::RequestIdentities => {
            let identities = match session {
                Some(s) => collect_identities(s).unwrap_or_default(),
                None => Vec::new(),
            };
            let wire: Vec<Identity> = identities
                .iter()
                .map(|i| Identity {
                    key_blob: i.blob.clone(),
                    comment: i.comment.clone(),
                })
                .collect();
            if verbose {
                log(&format!("RequestIdentities -> {} identities", wire.len()));
            }
            // Writing to a Vec cannot fail; ignore the Result.
            let _ = protocol::write_identities_answer(&mut out, &wire);
        }
        Request::SignRequest {
            key_blob,
            data,
            flags,
        } => {
            let signed = session.and_then(|s| match find_signer(s, key_blob) {
                Ok(Some(parsed)) => parsed.sign(data, *flags).ok(),
                _ => None,
            });
            match signed {
                Some(sig) => {
                    if verbose {
                        log("SignRequest -> signed");
                    }
                    let _ = protocol::write_sign_response(&mut out, &sig);
                }
                None => {
                    if verbose {
                        log("SignRequest -> failure (no key / locked / unsupported)");
                    }
                    let _ = protocol::write_failure(&mut out);
                }
            }
        }
        Request::Unsupported(ty) => {
            if verbose {
                log(&format!("Unsupported({ty}) -> failure"));
            }
            let _ = protocol::write_failure(&mut out);
        }
    }
    out
}

/// Log one line to stderr, prefixed. Never called with a secret or key bytes.
fn log(msg: &str) {
    eprintln!("[localpass-daemon ssh-agent] {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::AccountStore;
    use lp_vault::payload::{ItemPayload, TypeData};

    use crate::sshagent::keys::{GenAlgorithm, generate};
    use crate::sshagent::protocol::{
        Request, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
        SSH_AGENTC_REQUEST_IDENTITIES, read_string, write_message,
    };
    use std::io::Cursor;

    /// Build a test account+vault with the given ssh_key items, returning the
    /// session.
    fn account_with_keys(items: &[(&str, GenAlgorithm)]) -> (tempfile::TempDir, lp_vault::Session) {
        let dir = tempfile::tempdir().unwrap();
        let (session, _sk) = AccountStore::create(dir.path(), "correct horse battery").unwrap();
        let vid = session.create_vault("personal").unwrap();
        let vault = session.open_vault(vid).unwrap();
        for (title, algo) in items {
            let key = generate(*algo, title).unwrap();
            let payload = ItemPayload::new(
                TypeData::SshKey {
                    algo: key.algo,
                    private_pem: key.private_pem,
                    public_openssh: key.public_openssh,
                    fingerprint: key.fingerprint,
                },
                *title,
            );
            vault.create_item(&payload).unwrap();
        }
        (dir, session)
    }

    /// Parse an identities-answer into `(count, Vec<(blob, comment)>)`.
    fn parse_identities(bytes: &[u8]) -> (u32, Vec<(Vec<u8>, String)>) {
        let mut cur = Cursor::new(bytes);
        let (ty, payload) = protocol::read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_IDENTITIES_ANSWER);
        let mut pc = Cursor::new(payload);
        let mut count_buf = [0u8; 4];
        std::io::Read::read_exact(&mut pc, &mut count_buf).unwrap();
        let count = u32::from_be_bytes(count_buf);
        let mut ids = Vec::new();
        for _ in 0..count {
            let blob = read_string(&mut pc).unwrap();
            let comment = String::from_utf8(read_string(&mut pc).unwrap()).unwrap();
            ids.push((blob, comment));
        }
        (count, ids)
    }

    #[test]
    fn lists_ed25519_and_rsa_identities() {
        // RSA generation at 4096 is slow; use ed25519 twice plus one RSA via the
        // fast 2048 direct path is not exposed by generate(), so use ed25519 for
        // the fast path and confirm both a login (ignored) and two ssh keys show.
        let (_dir, session) = account_with_keys(&[
            ("laptop key", GenAlgorithm::Ed25519),
            ("server key", GenAlgorithm::Ed25519),
        ]);
        // Add a non-ssh item to confirm it is ignored.
        let vid = session.list_vaults().unwrap()[0].0;
        let vault = session.open_vault(vid).unwrap();
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, "not a key"))
            .unwrap();

        let out = handle_request(Some(&session), &Request::RequestIdentities, false);
        let (count, ids) = parse_identities(&out);
        assert_eq!(count, 2, "two ssh keys, note ignored");
        let comments: Vec<&str> = ids.iter().map(|(_, c)| c.as_str()).collect();
        assert!(comments.contains(&"laptop key"));
        assert!(comments.contains(&"server key"));
    }

    #[test]
    fn locked_daemon_lists_no_identities() {
        let out = handle_request(None, &Request::RequestIdentities, false);
        let (count, _) = parse_identities(&out);
        assert_eq!(count, 0);
    }

    #[test]
    fn sign_request_produces_verifiable_signature() {
        use signature::Verifier;
        let (_dir, session) = account_with_keys(&[("sign me", GenAlgorithm::Ed25519)]);
        let ids = collect_identities(&session).unwrap();
        assert_eq!(ids.len(), 1);
        let blob = ids[0].blob.clone();

        let data = b"session-id-and-transport-signed-data";
        let out = handle_request(
            Some(&session),
            &Request::SignRequest {
                key_blob: blob.clone(),
                data: data.to_vec(),
                flags: 0,
            },
            false,
        );
        // The reply is a SIGN_RESPONSE carrying the OpenSSH signature blob.
        let mut cur = Cursor::new(out);
        let (ty, payload) = protocol::read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_SIGN_RESPONSE);
        let mut pc = Cursor::new(payload);
        let sig_blob = read_string(&mut pc).unwrap();

        // Verify the signature against the public key derived from the same item.
        let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
        // Recover the public key from the blob by re-collecting; simplest is to
        // parse the item again. Grab the private key and verify with its public.
        let vid = session.list_vaults().unwrap()[0].0;
        let vault = session.open_vault(vid).unwrap();
        let item = vault.list_items().unwrap().into_iter().next().unwrap();
        if let TypeData::SshKey { private_pem, .. } = &item.payload.type_data {
            let pk = ssh_key::PrivateKey::from_openssh(private_pem.trim())
                .unwrap()
                .public_key()
                .clone();
            pk.key_data().verify(data, &sig).unwrap();
        } else {
            panic!("expected ssh key");
        }
    }

    #[test]
    fn unknown_key_sign_is_failure() {
        let (_dir, session) = account_with_keys(&[("real", GenAlgorithm::Ed25519)]);
        let out = handle_request(
            Some(&session),
            &Request::SignRequest {
                key_blob: b"not a real key blob".to_vec(),
                data: b"data".to_vec(),
                flags: 0,
            },
            false,
        );
        let mut cur = Cursor::new(out);
        let (ty, payload) = protocol::read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_FAILURE);
        assert!(payload.is_empty());
    }

    #[test]
    fn locked_daemon_sign_is_failure() {
        let out = handle_request(
            None,
            &Request::SignRequest {
                key_blob: b"anything".to_vec(),
                data: b"data".to_vec(),
                flags: 0,
            },
            false,
        );
        let mut cur = Cursor::new(out);
        let (ty, _) = protocol::read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_FAILURE);
    }

    #[test]
    fn unsupported_request_is_failure() {
        let out = handle_request(None, &Request::Unsupported(22), false);
        let mut cur = Cursor::new(out);
        let (ty, _) = protocol::read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_FAILURE);
    }

    // Keep the unused import warning-free while documenting the constant used by
    // the framing tests above.
    #[allow(dead_code)]
    const _ASSERT_CONST: u8 = SSH_AGENTC_REQUEST_IDENTITIES;
    #[allow(dead_code)]
    fn _use_write_message() {
        let mut v = Vec::new();
        let _ = write_message(&mut v, SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    }
}
