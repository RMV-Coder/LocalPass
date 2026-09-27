// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! Clipboard hygiene for **secret** copies (PRD §8 T9).
//!
//! A value the user copies is already in the webview (it arrived through an
//! explicit reveal / TOTP / generate gesture), so copying it does not widen the
//! secret boundary. What the webview's Clipboard API cannot do is *contain* the
//! copy once it is on the system clipboard:
//!
//! - **History and cloud sync.** Windows 10+ keeps every clipboard entry in
//!   Win+V history and can sync it to other devices; KDE and macOS clipboard
//!   managers do the same. We set the platform exclusion formats so the entry
//!   is never recorded (Windows: history, cloud, and monitoring exclusion;
//!   Linux and macOS: the password-manager / transient hint).
//! - **Lingering.** The entry is cleared [`CLEAR_AFTER`] later, and when the
//!   vault locks, **but only if the clipboard still holds our value**: if the
//!   user copied something else in the meantime, we leave it alone.
//!
//! Non-secret copies (a device's public identity, CLI snippets) keep using the
//! webview path. Mobile targets have no arboard backend; the command reports
//! that and the webview falls back.

use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

/// How long a secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// What the logic needs from a clipboard. The system implementation is
/// [`SystemClipboard`]; tests use a fake.
pub trait Backend {
    /// Write `text`, excluded from clipboard history / cloud sync where the
    /// platform supports it.
    fn set_secret(&mut self, text: &str) -> Result<(), String>;
    /// The clipboard's current text, if it holds text.
    fn text(&mut self) -> Option<String>;
    /// Empty the clipboard.
    fn clear(&mut self) -> Result<(), String>;
}

/// The last secret we put on the clipboard, and which copy it was.
struct Copied {
    value: Zeroizing<String>,
    generation: u64,
}

/// Tracks our most recent secret copy so a later clear only removes *ours*.
#[derive(Default)]
pub struct Tracker {
    last: Option<Copied>,
    generation: u64,
}

impl Tracker {
    /// Copy `text` as a secret. Returns the generation to pass to
    /// [`Tracker::clear_if_current`] when the timer fires.
    pub fn copy(&mut self, backend: &mut impl Backend, text: &str) -> Result<u64, String> {
        backend.set_secret(text)?;
        self.generation += 1;
        self.last = Some(Copied {
            value: Zeroizing::new(text.to_string()),
            generation: self.generation,
        });
        Ok(self.generation)
    }

    /// Timer path: clear only if `generation` is still the latest copy AND the
    /// clipboard still holds that value. Returns whether it cleared.
    pub fn clear_if_current(&mut self, backend: &mut impl Backend, generation: u64) -> bool {
        match &self.last {
            Some(c) if c.generation == generation => self.clear_if_ours(backend),
            _ => false,
        }
    }

    /// Lock path: clear if the clipboard still holds our latest secret. Always
    /// forgets the tracked value. Returns whether it cleared.
    pub fn clear_if_ours(&mut self, backend: &mut impl Backend) -> bool {
        let Some(copied) = self.last.take() else {
            return false;
        };
        let ours = backend
            .text()
            .map(Zeroizing::new)
            .is_some_and(|current| *current == *copied.value);
        ours && backend.clear().is_ok()
    }
}

/// The process-wide tracker behind the Tauri commands.
static TRACKER: Mutex<Tracker> = Mutex::new(Tracker {
    last: None,
    generation: 0,
});

/// Copy a secret to the system clipboard (excluded from history) and schedule
/// its removal after [`CLEAR_AFTER`].
pub fn copy_secret(text: &str) -> Result<(), String> {
    let mut backend = SystemClipboard::open()?;
    let generation = {
        let mut tracker = TRACKER
            .lock()
            .map_err(|_| "clipboard state poisoned".to_string())?;
        tracker.copy(&mut backend, text)?
    };
    std::thread::spawn(move || {
        std::thread::sleep(CLEAR_AFTER);
        if let (Ok(mut backend), Ok(mut tracker)) = (SystemClipboard::open(), TRACKER.lock()) {
            tracker.clear_if_current(&mut backend, generation);
        }
    });
    Ok(())
}

/// Clear the clipboard if it still holds our last secret (called on lock).
pub fn clear_on_lock() {
    if let (Ok(mut backend), Ok(mut tracker)) = (SystemClipboard::open(), TRACKER.lock()) {
        tracker.clear_if_ours(&mut backend);
    }
}

/// The OS clipboard via arboard.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub struct SystemClipboard(arboard::Clipboard);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl SystemClipboard {
    fn open() -> Result<Self, String> {
        arboard::Clipboard::new()
            .map(Self)
            .map_err(|e| format!("clipboard unavailable: {e}"))
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Backend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        let set = self.0.set();
        #[cfg(target_os = "windows")]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history()
                .exclude_from_cloud()
                .exclude_from_monitoring()
        };
        #[cfg(target_os = "linux")]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        set.text(text).map_err(|e| format!("could not copy: {e}"))
    }

    fn text(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }

    fn clear(&mut self) -> Result<(), String> {
        self.0
            .clear()
            .map_err(|e| format!("could not clear the clipboard: {e}"))
    }
}

/// Mobile: no native backend; the command errors and the webview falls back.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub struct SystemClipboard;

#[cfg(any(target_os = "android", target_os = "ios"))]
impl SystemClipboard {
    fn open() -> Result<Self, String> {
        Err("native clipboard unavailable on this platform".into())
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl Backend for SystemClipboard {
    fn set_secret(&mut self, _text: &str) -> Result<(), String> {
        Err("native clipboard unavailable on this platform".into())
    }
    fn text(&mut self) -> Option<String> {
        None
    }
    fn clear(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        content: Option<String>,
        secret_writes: usize,
        fail_set: bool,
    }

    impl Backend for Fake {
        fn set_secret(&mut self, text: &str) -> Result<(), String> {
            if self.fail_set {
                return Err("denied".into());
            }
            self.secret_writes += 1;
            self.content = Some(text.to_string());
            Ok(())
        }
        fn text(&mut self) -> Option<String> {
            self.content.clone()
        }
        fn clear(&mut self) -> Result<(), String> {
            self.content = None;
            Ok(())
        }
    }

    #[test]
    fn the_timer_clears_our_copy() {
        let (mut t, mut cb) = (Tracker::default(), Fake::default());
        let g = t.copy(&mut cb, "hunter2-password").unwrap();
        assert_eq!(cb.secret_writes, 1, "written through the secret path");
        assert!(t.clear_if_current(&mut cb, g));
        assert_eq!(cb.content, None);
    }

    #[test]
    fn the_timer_leaves_something_the_user_copied_afterwards() {
        let (mut t, mut cb) = (Tracker::default(), Fake::default());
        let g = t.copy(&mut cb, "hunter2-password").unwrap();
        cb.content = Some("a URL the user copied later".into());
        assert!(!t.clear_if_current(&mut cb, g));
        assert_eq!(cb.content.as_deref(), Some("a URL the user copied later"));
    }

    #[test]
    fn an_older_timer_does_not_clear_a_newer_copy() {
        let (mut t, mut cb) = (Tracker::default(), Fake::default());
        let first = t.copy(&mut cb, "first-secret-value").unwrap();
        let second = t.copy(&mut cb, "second-secret-value").unwrap();
        assert!(
            !t.clear_if_current(&mut cb, first),
            "stale timer must no-op"
        );
        assert_eq!(cb.content.as_deref(), Some("second-secret-value"));
        assert!(t.clear_if_current(&mut cb, second));
    }

    #[test]
    fn lock_clears_our_copy_and_forgets_it() {
        let (mut t, mut cb) = (Tracker::default(), Fake::default());
        let g = t.copy(&mut cb, "hunter2-password").unwrap();
        assert!(t.clear_if_ours(&mut cb));
        assert_eq!(cb.content, None);
        // The timer that fires later finds nothing to do.
        assert!(!t.clear_if_current(&mut cb, g));
    }

    #[test]
    fn lock_leaves_foreign_content_but_still_forgets_ours() {
        let (mut t, mut cb) = (Tracker::default(), Fake::default());
        t.copy(&mut cb, "hunter2-password").unwrap();
        cb.content = Some("user's own text".into());
        assert!(!t.clear_if_ours(&mut cb));
        assert_eq!(cb.content.as_deref(), Some("user's own text"));
        assert!(t.last.is_none(), "the secret is not retained after lock");
    }

    #[test]
    fn nothing_tracked_means_nothing_cleared() {
        let (mut t, mut cb) = (
            Tracker::default(),
            Fake {
                content: Some("x".into()),
                ..Fake::default()
            },
        );
        assert!(!t.clear_if_ours(&mut cb));
        assert!(!t.clear_if_current(&mut cb, 1));
        assert_eq!(cb.content.as_deref(), Some("x"));
    }

    #[test]
    fn a_failed_copy_tracks_nothing() {
        let (mut t, mut cb) = (
            Tracker::default(),
            Fake {
                fail_set: true,
                ..Fake::default()
            },
        );
        assert!(t.copy(&mut cb, "hunter2-password").is_err());
        assert!(t.last.is_none());
    }

    #[test]
    fn the_clear_window_is_thirty_seconds() {
        assert_eq!(CLEAR_AFTER, Duration::from_secs(30));
    }
}
