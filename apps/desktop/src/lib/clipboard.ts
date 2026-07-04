// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Clipboard copy for a value the user has already explicitly revealed/generated.
//
// The value is already in the webview at the point of copy (it arrived via a
// reveal/totp/generate gesture), so copying it does not widen the secret
// boundary. We prefer the browser Clipboard API available in the WebView2/WKWeb
// context; there is no persistence and no store involved.

/** Copy `text` to the system clipboard. Returns true on success. */
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
