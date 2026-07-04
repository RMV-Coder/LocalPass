#![forbid(unsafe_code)]
//! SSH key parsing, public-blob derivation, and signing — the **foreign-format
//! crypto boundary** for the agent.
//!
//! # Why this is a foreign-format exception (LESSONS.md)
//!
//! `lp-crypto` is the sole home of LocalPass's **own** vault crypto (envelope
//! AEAD, key wrapping, sealing, the device Ed25519 identity). The SSH keys a
//! user stores in a vault are **foreign artifacts** — arbitrary OpenSSH-format
//! Ed25519/RSA keypairs the user generated elsewhere (or with `localpass ssh
//! generate`). Parsing and signing with them is exactly like `lp-porter` using
//! the `age` crate for foreign archive crypto: it stays out of `lp-crypto`, and
//! it reuses the same RustCrypto/dalek stack `lp-crypto` already pins (so there
//! is no duplicated crypto surface — verified via `cargo tree`).
//!
//! All `ssh-key` / `rsa` usage in the daemon is confined to this module.
//!
//! # Zeroization
//!
//! [`ssh_key::PrivateKey`] and its `KeypairData` hold their secret scalars in
//! `zeroize`-on-drop containers (Ed25519 via `ed25519-dalek`'s `SigningKey`
//! zeroization; RSA via `num-bigint-dig`/`rsa`'s zeroizing secrets). We parse a
//! key from the decrypted item payload **on demand** for each sign request and
//! let it drop at the end of the call — there is no long-lived private-key
//! cache. So a rotated key is picked up immediately (the next sign reads the
//! current item payload), and the private scalar exists in memory only for the
//! duration of one signing operation. The intermediate `RsaPrivateKey` we build
//! for RSA signing (see [`ParsedKey::sign`]) likewise zeroizes on drop.
//!
//! # Encrypted PEMs
//!
//! An encrypted OpenSSH private key (passphrase-protected) is **not supported**:
//! the vault `ssh_key` type has no passphrase field, and prompting is impossible
//! inside a non-interactive agent sign path. [`parse_private_key`] detects this
//! ([`ssh_key::PrivateKey::is_encrypted`]) and returns a clear [`KeyError`]
//! naming the situation; the caller maps it to an agent failure.
//!
//! # RSA note (ssh-key 0.6.7 bug worked around here)
//!
//! ssh-key 0.6.7's `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` passes the
//! prime `p` **twice** instead of `p` and `q`, so its built-in RSA signing (and
//! any conversion through it) fails with a crypto error on a real key. We
//! therefore build the `rsa::RsaPrivateKey` ourselves from the keypair's
//! components (`n, e, d, p, q`), which are public fields, and precompute the CRT
//! values — sidestepping the bug. Ed25519 signing uses ssh-key's own path.

use ssh_encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, Signature};

use crate::sshagent::protocol::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

/// An error from the key layer. Messages are secret-free (they never contain key
/// material) and name the item title where useful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The stored PEM could not be parsed as an OpenSSH private key.
    Parse(String),
    /// The stored private key is passphrase-encrypted (unsupported — see module
    /// docs). The message names the item.
    Encrypted(String),
    /// The key algorithm is not one the agent can sign with (only Ed25519 and
    /// RSA are supported; ECDSA/DSA are not).
    UnsupportedAlgorithm(String),
    /// A signing operation failed internally.
    Sign(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Parse(m) => write!(f, "could not parse SSH private key: {m}"),
            KeyError::Encrypted(m) => write!(
                f,
                "SSH key {m:?} is passphrase-encrypted, which the agent cannot use \
                 (store an unencrypted OpenSSH key, or generate one with `localpass ssh generate`)"
            ),
            KeyError::UnsupportedAlgorithm(a) => {
                write!(
                    f,
                    "unsupported SSH key algorithm {a:?} (only ed25519 and rsa)"
                )
            }
            KeyError::Sign(m) => write!(f, "SSH signing failed: {m}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A parsed, in-memory SSH private key ready to derive a public blob or sign.
/// Wraps [`ssh_key::PrivateKey`], whose secret material zeroizes on drop.
pub struct ParsedKey {
    inner: PrivateKey,
}

impl ParsedKey {
    /// The public-key blob (the SSH wire encoding of the public key), used both
    /// as the identity blob in `SSH_AGENT_IDENTITIES_ANSWER` and as the lookup
    /// key for a sign request.
    ///
    /// # Errors
    ///
    /// [`KeyError::Sign`] only if the (in-memory) public key fails to encode,
    /// which does not happen for well-formed keys.
    pub fn public_blob(&self) -> Result<Vec<u8>, KeyError> {
        let mut blob = Vec::new();
        self.inner
            .public_key()
            .key_data()
            .encode(&mut blob)
            .map_err(|e| KeyError::Sign(e.to_string()))?;
        Ok(blob)
    }

    /// The SHA-256 fingerprint string (e.g. `SHA256:…`), matching `ssh-keygen -lf`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.inner
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// The OpenSSH public-key line (e.g. `ssh-ed25519 AAAA… comment`), suitable
    /// for `authorized_keys`. The `comment` is appended by ssh-key from the
    /// key's own comment; callers that want the item title as the comment set it
    /// on the payload separately.
    ///
    /// # Errors
    ///
    /// [`KeyError::Sign`] if the public key fails to render (does not happen for
    /// well-formed keys).
    pub fn public_openssh(&self) -> Result<String, KeyError> {
        self.inner
            .public_key()
            .to_openssh()
            .map_err(|e| KeyError::Sign(e.to_string()))
    }

    /// The algorithm string (`"ssh-ed25519"`, `"ssh-rsa"`, …).
    #[must_use]
    pub fn algorithm_str(&self) -> String {
        self.inner.algorithm().to_string()
    }

    /// Sign `data` for an SSH agent sign request, honoring the RSA SHA-2 flags.
    ///
    /// Returns the **OpenSSH signature blob** (`string algorithm || string
    /// signature-data`), which is exactly the `signature` field of an
    /// `SSH_AGENT_SIGN_RESPONSE`.
    ///
    /// - **Ed25519**: signs via ssh-key's own path (`flags` are ignored — they
    ///   only apply to RSA).
    /// - **RSA**: honors [`SSH_AGENT_RSA_SHA2_512`] / [`SSH_AGENT_RSA_SHA2_256`]
    ///   from `flags`; when neither is set we default to **SHA-512**
    ///   (`rsa-sha2-512`) — never legacy SHA-1 `ssh-rsa`.
    /// - Any other algorithm → [`KeyError::UnsupportedAlgorithm`].
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] for a non-Ed25519/RSA key;
    /// [`KeyError::Sign`] on an internal signing failure.
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, KeyError> {
        let signature = match self.inner.key_data() {
            KeypairData::Ed25519(_) => {
                use signature::Signer;
                self.inner
                    .try_sign(data)
                    .map_err(|e| KeyError::Sign(e.to_string()))?
            }
            KeypairData::Rsa(kp) => rsa_sign(kp, data, flags)?,
            other => {
                return Err(KeyError::UnsupportedAlgorithm(
                    other.algorithm().map(|a| a.to_string()).unwrap_or_default(),
                ));
            }
        };
        encode_signature(&signature)
    }
}

/// Parse an OpenSSH-format private key from a vault item's `private_pem`.
///
/// `title` is used only to name the item in error messages (never a secret).
///
/// # Errors
///
/// - [`KeyError::Parse`] if the PEM is not a valid OpenSSH private key.
/// - [`KeyError::Encrypted`] if the key is passphrase-protected (unsupported).
pub fn parse_private_key(private_pem: &str, title: &str) -> Result<ParsedKey, KeyError> {
    let key = PrivateKey::from_openssh(private_pem.trim())
        .map_err(|e| KeyError::Parse(format!("{title:?}: {e}")))?;
    if key.is_encrypted() {
        return Err(KeyError::Encrypted(title.to_string()));
    }
    Ok(ParsedKey { inner: key })
}

/// The algorithm choices accepted by [`generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenAlgorithm {
    /// Ed25519 (recommended default; small, fast, modern).
    Ed25519,
    /// RSA-4096 (PRD §4.1 generation target).
    Rsa4096,
}

/// A freshly generated keypair, ready to store as an `ssh_key` item.
pub struct GeneratedKey {
    /// The private key in OpenSSH PEM format (the `private_pem` field).
    pub private_pem: String,
    /// The public key in OpenSSH form (the `public_openssh` field).
    pub public_openssh: String,
    /// The SHA-256 fingerprint (the `fingerprint` field).
    pub fingerprint: String,
    /// The algorithm string (the `algo` field, e.g. `"ssh-ed25519"`).
    pub algo: String,
}

/// Generate a new SSH keypair **in memory** (never touching disk), with an
/// optional comment (LocalPass sets it to the item title). Uses the OS CSPRNG.
///
/// # Errors
///
/// [`KeyError::Sign`] on an (unexpected) keygen or render failure.
pub fn generate(algorithm: GenAlgorithm, comment: &str) -> Result<GeneratedKey, KeyError> {
    let mut key = match algorithm {
        GenAlgorithm::Ed25519 => PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| KeyError::Sign(e.to_string()))?,
        GenAlgorithm::Rsa4096 => {
            let kp = ssh_key::private::RsaKeypair::random(&mut OsRng, 4096)
                .map_err(|e| KeyError::Sign(e.to_string()))?;
            PrivateKey::from(kp)
        }
    };
    key.set_comment(comment);
    let private_pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| KeyError::Sign(e.to_string()))?
        .to_string();
    let public_openssh = key
        .public_key()
        .to_openssh()
        .map_err(|e| KeyError::Sign(e.to_string()))?;
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let algo = key.algorithm().to_string();
    Ok(GeneratedKey {
        private_pem,
        public_openssh,
        fingerprint,
        algo,
    })
}

/// Sign `data` with an RSA keypair, honoring the SHA-2 flags.
///
/// Builds a correct `rsa::RsaPrivateKey` from the keypair components (working
/// around the ssh-key 0.6.7 `p`-twice bug — see module docs), precomputes CRT
/// values, and signs with PKCS#1 v1.5 over the requested hash.
fn rsa_sign(
    kp: &ssh_key::private::RsaKeypair,
    data: &[u8],
    flags: u32,
) -> Result<Signature, KeyError> {
    use rsa::pkcs1v15::{Signature as RsaSig, SigningKey};
    use signature::{SignatureEncoding, Signer};
    use ssh_key::sha2::{Sha256, Sha512};

    // Build the RSA private key from components with the CORRECT p and q.
    let n = rsa::BigUint::try_from(&kp.public.n).map_err(|e| KeyError::Sign(e.to_string()))?;
    let e = rsa::BigUint::try_from(&kp.public.e).map_err(|e| KeyError::Sign(e.to_string()))?;
    let d = rsa::BigUint::try_from(&kp.private.d).map_err(|e| KeyError::Sign(e.to_string()))?;
    let p = rsa::BigUint::try_from(&kp.private.p).map_err(|e| KeyError::Sign(e.to_string()))?;
    let q = rsa::BigUint::try_from(&kp.private.q).map_err(|e| KeyError::Sign(e.to_string()))?;
    let mut rk = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| KeyError::Sign(e.to_string()))?;
    rk.precompute().map_err(|e| KeyError::Sign(e.to_string()))?;

    // Choose the hash: SHA-512 flag, SHA-256 flag, or default SHA-512.
    // (SHA-512 takes precedence if both are somehow set; we never sign SHA-1.)
    let use_sha256 = flags & SSH_AGENT_RSA_SHA2_256 != 0 && flags & SSH_AGENT_RSA_SHA2_512 == 0;
    if use_sha256 {
        let raw: RsaSig = SigningKey::<Sha256>::new(rk)
            .try_sign(data)
            .map_err(|e| KeyError::Sign(e.to_string()))?;
        Signature::new(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            raw.to_bytes().to_vec(),
        )
        .map_err(|e| KeyError::Sign(e.to_string()))
    } else {
        // The SHA-512 flag and the no-flag default both land here — we sign
        // rsa-sha2-512, never legacy SHA-1 `ssh-rsa`.
        let raw: RsaSig = SigningKey::<Sha512>::new(rk)
            .try_sign(data)
            .map_err(|e| KeyError::Sign(e.to_string()))?;
        Signature::new(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            raw.to_bytes().to_vec(),
        )
        .map_err(|e| KeyError::Sign(e.to_string()))
    }
}

/// Encode a signature to the OpenSSH signature blob (`string algo || string
/// data`) — the SSH agent sign-response payload.
fn encode_signature(signature: &Signature) -> Result<Vec<u8>, KeyError> {
    let mut blob = Vec::new();
    signature
        .encode(&mut blob)
        .map_err(|e| KeyError::Sign(e.to_string()))?;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate → serialize PEM → parse back → public blob is stable.
    #[test]
    fn ed25519_generate_parse_roundtrip() {
        let key = generate(GenAlgorithm::Ed25519, "test-comment").unwrap();
        assert!(key.private_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.algo, "ssh-ed25519");

        let parsed = parse_private_key(&key.private_pem, "test").unwrap();
        assert_eq!(parsed.algorithm_str(), "ssh-ed25519");
        // The generated fingerprint matches the parsed one.
        assert_eq!(parsed.fingerprint(), key.fingerprint);
        // Public blob is non-empty and stable.
        let blob = parsed.public_blob().unwrap();
        assert!(!blob.is_empty());
    }

    /// An Ed25519 signature verifies against the public key.
    #[test]
    fn ed25519_sign_verifies() {
        use signature::Verifier;
        let key = generate(GenAlgorithm::Ed25519, "c").unwrap();
        let parsed = parse_private_key(&key.private_pem, "t").unwrap();
        let data = b"the data under the SSH transport signature";
        let blob = parsed.sign(data, 0).unwrap();

        // Decode the OpenSSH signature blob and verify with the public key.
        let sig = Signature::try_from(blob.as_slice()).unwrap();
        let pk = PrivateKey::from_openssh(key.private_pem.trim())
            .unwrap()
            .public_key()
            .clone();
        pk.key_data().verify(data, &sig).unwrap();
    }

    /// RSA signatures verify for both SHA-256 and SHA-512 flags (uses a 2048-bit
    /// key so the test is fast — generation is the same code path as 4096).
    #[test]
    fn rsa_sign_verifies_both_hashes() {
        use signature::Verifier;
        // Build a 2048-bit RSA key directly (generate() only offers 4096, which
        // is slow; the sign path is identical).
        let kp = ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap();
        let key = PrivateKey::from(kp);
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        let parsed = parse_private_key(&pem, "rsa").unwrap();
        assert_eq!(parsed.algorithm_str(), "ssh-rsa");
        let data = b"rsa challenge data";

        for flag in [SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512, 0] {
            let blob = parsed.sign(data, flag).unwrap();
            let sig = Signature::try_from(blob.as_slice()).unwrap();
            key.public_key().key_data().verify(data, &sig).unwrap();
            // A 0 flag defaults to SHA-512.
            let expect = if flag == SSH_AGENT_RSA_SHA2_256 {
                HashAlg::Sha256
            } else {
                HashAlg::Sha512
            };
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(expect) });
        }
    }

    /// A garbage PEM is a clean Parse error, not a panic.
    #[test]
    fn garbage_pem_is_parse_error() {
        match parse_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n", "bad") {
            Err(KeyError::Parse(_)) => {}
            Err(other) => panic!("expected Parse, got {other:?}"),
            Ok(_) => panic!("garbage PEM unexpectedly parsed"),
        }
    }

    /// An encrypted OpenSSH key is detected and rejected with a clear error.
    #[test]
    fn encrypted_key_is_rejected() {
        // Generate a key, then encrypt it with a passphrase via ssh-key.
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let encrypted = key.encrypt(&mut OsRng, "hunter2").unwrap();
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();
        match parse_private_key(&pem, "locked-key") {
            Err(KeyError::Encrypted(name)) => assert_eq!(name, "locked-key"),
            Err(other) => panic!("expected Encrypted, got {other:?}"),
            Ok(_) => panic!("encrypted key unexpectedly parsed as usable"),
        }
    }
}
