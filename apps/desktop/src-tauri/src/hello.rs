// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! # Windows Hello unlock
//!
//! Opt-in convenience: unlock with a PIN, fingerprint or face instead of
//! typing the master password. The design follows KeePassXC's: a Windows Hello
//! **key credential** (an RSA key in the user's TPM-backed Passport container,
//! usable only after a Hello gesture) signs a fixed random challenge, and the
//! signature — which only that key can produce, and only with the user present
//! — is the input keying material for the key that seals the master password.
//!
//! ```text
//! enroll:  password ──(checked by the service)──┐
//!          challenge = random 32 B               │
//!          sig = Hello.sign(challenge)  ◄── prompt
//!          k   = HKDF-SHA256(ikm = sig, salt = challenge, info = INFO ‖ profile)
//!          blob = XChaCha20-Poly1305(k, nonce, password, aad = profile)
//! unlock:  sig = Hello.sign(challenge)  ◄── prompt  →  k  →  password  →  Unlock
//! ```
//!
//! RSASSA-PKCS1-v1_5 signatures are deterministic, so the same challenge
//! yields the same signature and therefore the same key every time.
//!
//! ## What this does and does not change
//!
//! - The master password is still what unlocks the vault: the daemon protocol
//!   and the AGPL core are untouched. This module only stores a sealed copy of
//!   the password and replays it into the ordinary `Unlock` request.
//! - The sealed blob lives in the app's **local** (non-roaming) data dir, per
//!   profile. It is useless on another machine (the key never leaves the TPM)
//!   and is never synced.
//! - The password never reaches the webview: unsealing and the unlock both
//!   happen here, and every plaintext copy is a [`Zeroizing`] buffer.
//! - A process running as the user could ask Hello to sign the challenge, but
//!   Windows shows the user a prompt for every signature; that is the same
//!   trust boundary as KeePassXC and the Hello-based unlock of other managers.
//! - If the master password changes, the sealed copy stops working: the first
//!   failed Hello unlock deletes the enrolment and says so.
//!
//! The sealing math is platform-independent (and unit-tested on every OS);
//! only [`platform`] talks to Windows.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// HKDF `info` prefix; the profile path is appended so a blob for one profile
/// can never unseal under another.
const INFO: &[u8] = b"localpass-desktop hello-unlock v1|";
/// The on-disk format version of [`Sealed`].
const VERSION: u32 = 1;
const CHALLENGE_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Errors, each with a secret-free message the UI can show as-is.
#[derive(Debug, PartialEq, Eq)]
pub enum HelloError {
    /// Windows Hello is not available (not Windows, or no PIN set up).
    Unsupported,
    /// The user dismissed the Hello prompt.
    Cancelled,
    /// Nothing is enrolled for this profile.
    NotEnrolled,
    /// The blob or key no longer matches (corrupt, re-imaged TPM, …).
    Stale,
    /// Anything else, with a message.
    Other(String),
}

impl HelloError {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unsupported => "Windows Hello is not set up on this device.".into(),
            Self::Cancelled => "cancelled".into(),
            Self::NotEnrolled => "Windows Hello unlock is not turned on.".into(),
            Self::Stale => {
                "Windows Hello can no longer unlock LocalPass on this device, so it was turned off. \
                 Unlock with your master password and turn it on again in Settings."
                    .into()
            }
            Self::Other(m) => m.clone(),
        }
    }
}

/// The sealed master password, as stored on disk (hex fields; nothing secret
/// in the clear).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sealed {
    pub v: u32,
    /// The Windows Hello key credential's name.
    pub key_name: String,
    pub challenge: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A short, stable id for a profile path (file and key names; not secret).
#[must_use]
pub fn profile_id(profile: &str) -> String {
    hex(&Sha256::digest(profile.as_bytes())[..8])
}

/// Where the sealed password for `profile` lives under `dir`.
#[must_use]
pub fn blob_path(dir: &Path, profile: &str) -> PathBuf {
    dir.join("hello")
        .join(format!("{}.json", profile_id(profile)))
}

/// The Windows Hello key credential name for `profile`.
#[must_use]
pub fn key_name(profile: &str) -> String {
    format!("LocalPass unlock {}", profile_id(profile))
}

fn cipher(signature: &[u8], challenge: &[u8], profile: &str) -> XChaCha20Poly1305 {
    let mut info = INFO.to_vec();
    info.extend_from_slice(profile.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(challenge), signature);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    XChaCha20Poly1305::new(key.as_ref().into())
}

/// Seal `password` under the key derived from a Hello `signature` over
/// `challenge`. `nonce` must be fresh random bytes.
pub fn seal(
    signature: &[u8],
    challenge: &[u8],
    nonce: &[u8; NONCE_LEN],
    profile: &str,
    key_name: &str,
    password: &[u8],
) -> Result<Sealed, HelloError> {
    let ciphertext = cipher(signature, challenge, profile)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: password,
                aad: profile.as_bytes(),
            },
        )
        .map_err(|_| HelloError::Other("could not seal the password".into()))?;
    Ok(Sealed {
        v: VERSION,
        key_name: key_name.into(),
        challenge: hex(challenge),
        nonce: hex(nonce),
        ciphertext: hex(&ciphertext),
    })
}

/// The challenge stored in a blob (what Hello must sign to unseal it).
pub fn challenge_of(sealed: &Sealed) -> Result<Vec<u8>, HelloError> {
    if sealed.v != VERSION {
        return Err(HelloError::Stale);
    }
    unhex(&sealed.challenge)
        .filter(|c| c.len() == CHALLENGE_LEN)
        .ok_or(HelloError::Stale)
}

/// Unseal with a Hello `signature`. Any mismatch (wrong key, edited blob,
/// another profile) is [`HelloError::Stale`].
pub fn open(
    sealed: &Sealed,
    signature: &[u8],
    profile: &str,
) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    let challenge = challenge_of(sealed)?;
    let nonce = unhex(&sealed.nonce)
        .filter(|n| n.len() == NONCE_LEN)
        .ok_or(HelloError::Stale)?;
    let ciphertext = unhex(&sealed.ciphertext).ok_or(HelloError::Stale)?;
    cipher(signature, &challenge, profile)
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: profile.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| HelloError::Stale)
}

pub fn read_blob(path: &Path) -> Result<Sealed, HelloError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(HelloError::NotEnrolled),
        Err(e) => {
            return Err(HelloError::Other(format!(
                "could not read the Windows Hello data: {e}"
            )));
        }
    };
    serde_json::from_str(&text).map_err(|_| HelloError::Stale)
}

/// Write the blob atomically (temp file + rename) so a crash never leaves a
/// half-written enrolment behind.
pub fn write_blob(path: &Path, sealed: &Sealed) -> Result<(), HelloError> {
    let io = |e: std::io::Error| {
        HelloError::Other(format!("could not save the Windows Hello data: {e}"))
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(sealed).map_err(|e| HelloError::Other(e.to_string()))?;
    std::fs::write(&tmp, json).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

pub fn random<const N: usize>() -> Result<[u8; N], HelloError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| HelloError::Other(format!("no randomness: {e}")))?;
    Ok(b)
}

/// Enrol: create (or replace) the Hello key, sign a fresh challenge, seal.
/// The caller has already verified `password` with the service.
pub fn enroll(dir: &Path, profile: &str, password: &[u8]) -> Result<(), HelloError> {
    let name = key_name(profile);
    platform::create_key(&name)?;
    let challenge = random::<CHALLENGE_LEN>()?;
    let signature = Zeroizing::new(platform::sign(&name, &challenge)?);
    let nonce = random::<NONCE_LEN>()?;
    let sealed = seal(&signature, &challenge, &nonce, profile, &name, password)?;
    write_blob(&blob_path(dir, profile), &sealed)
}

/// Unseal the master password (one Hello prompt).
pub fn unseal(dir: &Path, profile: &str) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    let sealed = read_blob(&blob_path(dir, profile))?;
    let challenge = challenge_of(&sealed)?;
    let signature = Zeroizing::new(platform::sign(&sealed.key_name, &challenge)?);
    open(&sealed, &signature, profile)
}

/// Turn Hello unlock off: delete the blob and the key. Idempotent.
pub fn disable(dir: &Path, profile: &str) -> Result<(), HelloError> {
    let path = blob_path(dir, profile);
    let name = read_blob(&path)
        .map(|s| s.key_name)
        .unwrap_or_else(|_| key_name(profile));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(HelloError::Other(format!(
                "could not remove the Windows Hello data: {e}"
            )));
        }
    }
    platform::delete_key(&name);
    Ok(())
}

/// Whether Hello is usable here, and whether this profile is enrolled.
#[must_use]
pub fn status(dir: &Path, profile: &str) -> (bool, bool) {
    let supported = platform::is_supported();
    let enrolled = supported && blob_path(dir, profile).is_file();
    (supported, enrolled)
}

#[cfg(windows)]
mod platform {
    //! The Windows binding: `Windows.Security.Credentials.KeyCredentialManager`.

    use super::HelloError;
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::core::{Array, HSTRING};

    fn status_err(status: KeyCredentialStatus) -> HelloError {
        match status {
            KeyCredentialStatus::UserCanceled => HelloError::Cancelled,
            KeyCredentialStatus::NotFound => HelloError::Stale,
            KeyCredentialStatus::UserPrefersPassword => HelloError::Cancelled,
            KeyCredentialStatus::SecurityDeviceLocked => HelloError::Other(
                "Windows Hello is locked after too many attempts. Try again later.".into(),
            ),
            other => HelloError::Other(format!("Windows Hello failed ({})", other.0)),
        }
    }

    fn win(e: windows::core::Error) -> HelloError {
        HelloError::Other(format!("Windows Hello failed: {}", e.message()))
    }

    /// The Hello prompt opens behind a desktop app's window (it has no owner
    /// window). Bring it to the front, as KeePassXC does, for a few seconds.
    fn raise_prompt() {
        std::thread::spawn(|| {
            use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
            use windows::core::w;
            for _ in 0..40 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // SAFETY: plain Win32 calls with static, NUL-terminated strings.
                if let Ok(hwnd) = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), None) } {
                    let _ = unsafe { SetForegroundWindow(hwnd) };
                    return;
                }
            }
        });
    }

    pub fn is_supported() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.get())
            .unwrap_or(false)
    }

    pub fn create_key(name: &str) -> Result<(), HelloError> {
        if !is_supported() {
            return Err(HelloError::Unsupported);
        }
        raise_prompt();
        let result = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(name),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.get())
        .map_err(win)?;
        match result.Status().map_err(win)? {
            KeyCredentialStatus::Success => Ok(()),
            other => Err(status_err(other)),
        }
    }

    pub fn sign(name: &str, challenge: &[u8]) -> Result<Vec<u8>, HelloError> {
        if !is_supported() {
            return Err(HelloError::Unsupported);
        }
        let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
            .and_then(|op| op.get())
            .map_err(win)?;
        match opened.Status().map_err(win)? {
            KeyCredentialStatus::Success => {}
            other => return Err(status_err(other)),
        }
        let credential = opened.Credential().map_err(win)?;
        let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(win)?;
        raise_prompt();
        let signed = credential
            .RequestSignAsync(&data)
            .and_then(|op| op.get())
            .map_err(win)?;
        match signed.Status().map_err(win)? {
            KeyCredentialStatus::Success => {}
            other => return Err(status_err(other)),
        }
        let buffer = signed.Result().map_err(win)?;
        let mut out = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buffer, &mut out).map_err(win)?;
        Ok(out.to_vec())
    }

    pub fn delete_key(name: &str) {
        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.get());
    }
}

#[cfg(not(windows))]
mod platform {
    //! No Windows Hello off Windows. (macOS Touch ID / Android BiometricPrompt
    //! would slot in here behind the same four functions.)

    use super::HelloError;

    pub fn is_supported() -> bool {
        false
    }
    pub fn create_key(_name: &str) -> Result<(), HelloError> {
        Err(HelloError::Unsupported)
    }
    pub fn sign(_name: &str, _challenge: &[u8]) -> Result<Vec<u8>, HelloError> {
        Err(HelloError::Unsupported)
    }
    pub fn delete_key(_name: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &[u8] = &[7u8; 256];
    const CH: [u8; CHALLENGE_LEN] = [3u8; CHALLENGE_LEN];
    const NONCE: [u8; NONCE_LEN] = [9u8; NONCE_LEN];

    fn sealed(profile: &str, pw: &[u8]) -> Sealed {
        seal(SIG, &CH, &NONCE, profile, &key_name(profile), pw).unwrap()
    }

    #[test]
    fn round_trips_with_the_same_signature() {
        let s = sealed("C:\\p", b"correct horse");
        assert_eq!(open(&s, SIG, "C:\\p").unwrap().as_slice(), b"correct horse");
    }

    #[test]
    fn the_blob_holds_no_plaintext() {
        let s = sealed("/p", b"hunter2-hunter2");
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(!json.contains(&hex(b"hunter2")));
    }

    #[test]
    fn a_different_signature_cannot_open_it() {
        let s = sealed("/p", b"pw");
        let mut other = SIG.to_vec();
        other[0] ^= 1;
        assert_eq!(open(&s, &other, "/p").unwrap_err(), HelloError::Stale);
    }

    #[test]
    fn a_blob_for_one_profile_cannot_open_under_another() {
        let s = sealed("/home/a/localpass", b"pw");
        assert_eq!(
            open(&s, SIG, "/home/b/localpass").unwrap_err(),
            HelloError::Stale
        );
    }

    #[test]
    fn edited_or_malformed_blobs_are_stale() {
        let mut s = sealed("/p", b"pw");
        let last = s.ciphertext.pop().unwrap();
        s.ciphertext.push(if last == '0' { '1' } else { '0' });
        assert_eq!(open(&s, SIG, "/p").unwrap_err(), HelloError::Stale);

        let mut s = sealed("/p", b"pw");
        s.nonce = "zz".into();
        assert_eq!(open(&s, SIG, "/p").unwrap_err(), HelloError::Stale);

        let mut s = sealed("/p", b"pw");
        s.v = 99;
        assert_eq!(challenge_of(&s).unwrap_err(), HelloError::Stale);

        let mut s = sealed("/p", b"pw");
        s.challenge = "abcd".into();
        assert_eq!(challenge_of(&s).unwrap_err(), HelloError::Stale);
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn names_are_stable_and_profile_specific() {
        assert_eq!(profile_id("/p"), profile_id("/p"));
        assert_ne!(profile_id("/p"), profile_id("/q"));
        assert_eq!(profile_id("/p").len(), 16);
        assert!(key_name("/p").starts_with("LocalPass unlock "));
        let dir = Path::new("/data");
        assert_eq!(
            blob_path(dir, "/p"),
            dir.join("hello").join(format!("{}.json", profile_id("/p")))
        );
    }

    #[test]
    fn blob_file_round_trip_and_missing_means_not_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let path = blob_path(dir.path(), "/p");
        assert_eq!(read_blob(&path).unwrap_err(), HelloError::NotEnrolled);
        let s = sealed("/p", b"pw");
        write_blob(&path, &s).unwrap();
        assert_eq!(read_blob(&path).unwrap(), s);
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(read_blob(&path).unwrap_err(), HelloError::Stale);
    }

    #[test]
    fn disable_removes_the_blob_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = blob_path(dir.path(), "/p");
        write_blob(&path, &sealed("/p", b"pw")).unwrap();
        disable(dir.path(), "/p").unwrap();
        assert!(!path.exists());
        disable(dir.path(), "/p").unwrap();
    }

    #[test]
    fn messages_are_secret_free_and_specific() {
        assert_eq!(HelloError::Cancelled.message(), "cancelled");
        assert!(HelloError::Stale.message().contains("turned off"));
        assert!(HelloError::Unsupported.message().contains("not set up"));
    }
}
