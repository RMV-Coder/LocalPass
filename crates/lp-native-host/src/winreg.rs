// This module is the ONLY place `unsafe` is permitted in the crate (see the
// crate-level `#![deny(unsafe_code)]` note in `lib.rs`). It makes a handful of
// Win32 registry calls to point Chrome/Firefox at our native-messaging manifest.
// Every unsafe block documents its safety contract inline.
#![allow(unsafe_code)]
//! A tiny `HKEY_CURRENT_USER` registry helper for browser native-messaging
//! registration (Windows only).
//!
//! Browsers locate a native-messaging host on Windows via a registry value:
//! `HKCU\Software\<vendor>\NativeMessagingHosts\com.localpass.host` whose
//! **default** value (`""`) is the absolute path to the host's manifest JSON.
//! This module writes and deletes exactly that, using `windows-sys` — the same
//! crate family `lp-daemon` already uses for its Win32 needs, so no new
//! third-party surface enters the tree.
//!
//! Only three operations are needed — create-key-and-set-default,
//! delete-key-tree — so this is deliberately minimal rather than a general
//! registry abstraction. Nothing here handles a secret; a manifest path is
//! non-sensitive.

use std::io;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
};

/// Encode `s` as a NUL-terminated UTF-16 buffer for the wide Win32 APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Create (or open) `HKCU\<subkey>` and set its **default** value to `value`
/// (a `REG_SZ` string). Intermediate keys are created as needed.
///
/// # Errors
///
/// An [`io::Error`] built from the Win32 error code on any failure.
pub fn set_hkcu_default(subkey: &str, value: &str) -> io::Result<()> {
    let subkey_w = wide(subkey);
    let mut hkey: HKEY = std::ptr::null_mut();

    // SAFETY: `subkey_w` is a valid NUL-terminated wide string that outlives the
    // call; `hkey` is a valid out-pointer. All other pointers are null/`0` where
    // the API accepts them (no class, default options, no security attributes).
    // On success `hkey` is an owned handle we close below.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }

    let value_w = wide(value);
    // Byte length of the wide buffer INCLUDING the terminating NUL (REG_SZ wants
    // the full byte count).
    let byte_len = value_w.len() * std::mem::size_of::<u16>();

    // SAFETY: `hkey` is a valid, open key from the successful create above.
    // `value_w` is a valid wide buffer of `byte_len` bytes (its own length), and
    // we pass its byte length as required for `REG_SZ`. The value name is null =
    // the key's default value.
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            std::ptr::null(),
            0,
            REG_SZ,
            value_w.as_ptr() as *const u8,
            byte_len as u32,
        )
    };

    // SAFETY: `hkey` is a valid handle we own; closing it exactly once here.
    unsafe { RegCloseKey(hkey) };

    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Delete `HKCU\<subkey>` and everything under it. A missing key is **not** an
/// error (idempotent unregister).
///
/// # Errors
///
/// An [`io::Error`] built from the Win32 error code on a failure other than
/// "key not found".
pub fn delete_hkcu_key(subkey: &str) -> io::Result<()> {
    let subkey_w = wide(subkey);
    // SAFETY: `subkey_w` is a valid NUL-terminated wide string outliving the
    // call; `RegDeleteTreeW` on a predefined key handle + relative subkey deletes
    // the subtree. We treat FILE_NOT_FOUND as success (idempotent).
    let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr()) };
    if rc == ERROR_SUCCESS {
        return Ok(());
    }
    // ERROR_FILE_NOT_FOUND (2) — nothing to delete; that is fine.
    if rc == 2 {
        return Ok(());
    }
    Err(io::Error::from_raw_os_error(rc as i32))
}
