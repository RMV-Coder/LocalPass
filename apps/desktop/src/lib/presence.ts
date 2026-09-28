// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Human presence (mcp-server.md §7). While an AI agent is connected to the
// LocalPass service, a change or consent request comes back with an error
// carrying PRESENCE_MARKER. `withPresence` catches that, asks the registered
// prompt (the password dialog) to confirm, and retries the call once. The
// password goes straight to the backend's `confirm_presence`; the grant it buys
// stays in the Rust backend and never reaches the webview.

/** Must match `daemon::PRESENCE_REQUIRED_MARKER` in src-tauri. */
export const PRESENCE_MARKER = "presence_required:";

/** Show the password dialog for `action`. `submit` checks a password and
 *  rejects with a message on a wrong one, so the dialog can say so and stay
 *  open. Resolves `true` once confirmed, `false` if the user cancelled. */
export type PresencePrompt = (
  action: string,
  submit: (password: string) => Promise<void>,
) => Promise<boolean>;

let prompt: PresencePrompt | null = null;
let pending: Promise<boolean> | null = null;

/** Register (or, with `null`, remove) the dialog that confirms presence. */
export function setPresencePrompt(p: PresencePrompt | null): void {
  prompt = p;
}

/** The request kind a presence error names, or `null` for any other error. */
export function presenceAction(err: unknown): string | null {
  if (typeof err !== "string") return null;
  const m = err.match(/presence_required:([A-Za-z]+)/);
  return m ? m[1] : null;
}

/** A short phrase for the dialog, e.g. "Editing an item". */
export function describeAction(action: string): string {
  const phrases: Record<string, string> = {
    CreateItem: "Creating an item",
    UpdateItem: "Editing an item",
    DeleteItem: "Deleting an item",
    RestoreVersion: "Restoring an item version",
    UntrashItem: "Restoring an item from the trash",
    CreateVault: "Creating a vault",
    DeleteVault: "Deleting a vault",
    AddAttachment: "Adding an attachment",
    DeleteAttachment: "Deleting an attachment",
    SetAgentFillMode: "Turning on agent fill",
    SetPairingMode: "Turning on pairing mode",
    TrustDevice: "Trusting a device",
    ShareVaultToDevice: "Sharing a vault to a device",
    SyncSetup: "Setting up sync",
  };
  return phrases[action] ?? "This change";
}

export const CANCELLED_MESSAGE =
  "Cancelled. An AI agent is connected, so this change needs your master password.";

/** Run `call`; if it needs presence, confirm through the prompt and run it
 *  once more. Concurrent calls share one dialog. Any other error, and a
 *  cancelled dialog, reject as usual. */
export async function withPresence<T>(
  call: () => Promise<T>,
  confirm: (password: string) => Promise<void>,
): Promise<T> {
  try {
    return await call();
  } catch (err) {
    const action = presenceAction(err);
    if (action === null) throw err;
    if (!prompt) throw CANCELLED_MESSAGE;
    if (!pending) {
      pending = prompt(action, confirm).finally(() => {
        pending = null;
      });
    }
    if (!(await pending)) throw CANCELLED_MESSAGE;
    return call();
  }
}
