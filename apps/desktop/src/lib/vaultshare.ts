// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Words for sharing a vault with another device and receiving one. Pure: it
// reads public sync metadata (counts, device ids, folder paths), never a
// secret.
//
// "Nothing was shared to this device" has several different causes, and each
// has a different fix: the folder is not the one the other device uses (or has
// not synced here yet), the user picked one vault's folder instead of the
// shared folder, the share was addressed to another device, or the two devices
// trust each other in one direction only. The daemon's adopt report says which.

import type { SyncAdoptView, SyncStatusView } from "./types";

export type ShareTone = "ok" | "warn" | "info";

export interface Outcome {
  tone: ShareTone;
  title: string;
  detail: string;
  /** "pair": the fix is trusting a device, so offer the pairing panel. */
  action?: "pair";
}

/** What "Receive" found, as a title and the next step. */
export function adoptOutcome(r: SyncAdoptView): Outcome {
  const untrusted = r.untrusted_shares;
  if (r.adopted.length > 0) {
    const names = r.adopted.map((a) => a.name || a.vault_id).join(", ");
    const more = untrusted
      ? ` ${plural(untrusted, "other share")} came from a device this one does not trust yet.`
      : "";
    return {
      tone: "ok",
      title: `Added ${names}.`,
      detail: `${r.adopted.length === 1 ? "Its" : "Their"} items are on this device now.${more}`,
    };
  }
  if (untrusted > 0) {
    return {
      tone: "warn",
      title: `${untrusted === 1 ? "A vault here was" : `${untrusted} vaults here were`} shared with this device by a device it does not trust yet.`,
      detail:
        "If you shared it from one of your devices, trust that device under Add a device, " +
        "comparing the fingerprint with the one it shows under This device. Then press " +
        "Receive again. If you did not share anything, ignore this: anyone who can write " +
        "to this folder could have put it there.",
      action: "pair",
    };
  }
  if (r.looks_like_vault_folder) {
    return {
      tone: "warn",
      title: "This is one vault's folder.",
      detail: "Choose the folder that contains it: the shared folder itself.",
    };
  }
  if (r.vault_folders === 0) {
    return {
      tone: "warn",
      title: "There is no LocalPass data in this folder.",
      detail:
        "Use the same shared folder the other device syncs through, as it appears on this " +
        "device. If you just shared, wait until the folder has finished syncing here.",
    };
  }
  if (r.shares_for_other_devices > 0) {
    return {
      tone: "warn",
      title: "The vaults here were shared with a different device.",
      detail:
        "On the sharing device, share again and choose this device. Its fingerprint is " +
        "shown above.",
    };
  }
  return {
    tone: "info",
    title: "Nothing has been shared with this device in this folder yet.",
    detail:
      "On the other device, use Share a vault with a device and choose this one. If you " +
      "just did, wait for the folder to sync, then press Receive again.",
  };
}

/** Whether any other trusted device has written to this vault's folder. */
export function folderUsedByAnotherDevice(status: SyncStatusView | null): boolean {
  return !!status?.devices.some((d) => !d.is_self && d.trusted);
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}
