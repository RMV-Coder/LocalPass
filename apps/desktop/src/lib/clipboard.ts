// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { copySecretNative } from "./api";

// Clipboard copy for a value the user has already explicitly revealed/generated.
//
// The value is already in the webview at the point of copy (it arrived via a
// reveal/totp/generate gesture), so copying it does not widen the secret
// boundary. We prefer the browser Clipboard API available in the WebView2/WKWeb
// context; there is no persistence and no store involved.

/** Copy a SECRET (revealed field, TOTP code, generated password, Emergency Kit
 *  key). Goes through the native command so the copy is kept out of clipboard
 *  history / cloud sync and cleared after 30 s or on lock; falls back to the
 *  webview path where there is no native clipboard (mobile). */
export async function copySecret(text: string): Promise<boolean> {
  try {
    await copySecretNative(text);
    return true;
  } catch {
    return copyToClipboard(text);
  }
}

/** Copy non-secret `text` (identities, CLI snippets) to the system clipboard.
 *  Returns true on success. */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy path
  }
  // Legacy fallback for environments without the async Clipboard API.
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "absolute";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
