<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Item detail. Secret fields render masked by default; per-field Reveal/Copy
  buttons call reveal_field on an explicit click. Revealed values live only in
  the component-local `revealed` map, which is RESET whenever the item changes
  (see the $effect) — never a persisted store. TOTP items show a live code with
  a seconds-remaining ring.
-->
<script lang="ts">
  import {
    getItem,
    revealField,
    totp as totpApi,
    deleteItem,
    listAttachments,
    addAttachment,
    getAttachment,
    deleteAttachment,
  } from "../lib/api";
  import type { ItemView, TotpView, AttachmentView } from "../lib/types";
  import { MASK, typeLabel, formatTimestamp, groupTotp, humanSize } from "../lib/format";
  import { formatDotenv, buildRunCommand } from "../lib/envset";
  import { copyToClipboard } from "../lib/clipboard";
  import { toast } from "../lib/toast";
  import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";

  interface Props {
    vault: string;
    /** The vault's display name (for the `localpass run --vault` command). */
    vaultName?: string;
    itemId: string;
    /** Called when the user clicks Edit (the parent opens the form). */
    onEdit?: (id: string) => void;
    /** Called after the item is moved to trash (the parent refreshes). */
    onDeleted?: () => void;
  }
  let { vault, vaultName = "", itemId, onEdit, onDeleted }: Props = $props();

  let item = $state<ItemView | null>(null);
  let error = $state("");
  let loading = $state(false);

  // Delete confirmation dialog state.
  let confirmingDelete = $state(false);
  let deleting = $state(false);

  async function doDelete() {
    if (deleting) return;
    deleting = true;
    try {
      await deleteItem(vault, itemId);
      toast("Moved to trash", "ok");
      confirmingDelete = false;
      onDeleted?.();
    } catch (err) {
      toast(typeof err === "string" ? err : "Delete failed", "error");
    } finally {
      deleting = false;
    }
  }

  // Revealed secret values, keyed by field name. Component-local only.
  let revealed = $state<Record<string, string>>({});
  let revealBusy = $state<Record<string, boolean>>({});

  // TOTP live state.
  let totp = $state<TotpView | null>(null);
  let totpTimer: ReturnType<typeof setInterval> | undefined;

  // --- Export as .env (env_set items) ----------------------------------
  // The assembled .env text and the values it contains are COMPONENT-LOCAL
  // ONLY — never a store — and are cleared on Hide and whenever the item
  // changes (see load()). Each entry is revealed individually via revealField
  // (gesture-driven, audit-logged by the daemon); there is no bulk-dump command.
  let envExport = $state<string | null>(null);
  let exporting = $state(false);

  async function exportEnv() {
    if (exporting || !item) return;
    exporting = true;
    try {
      const pairs: { key: string; value: string }[] = [];
      // Field names on an env_set item ARE the entry KEYs. Reveal each in turn.
      for (const f of item.fields) {
        const value = await revealField(vault, itemId, f.name);
        pairs.push({ key: f.name, value });
      }
      envExport = formatDotenv(pairs);
    } catch (err) {
      toast(typeof err === "string" ? err : "Export failed", "error");
    } finally {
      exporting = false;
    }
  }

  function hideEnvExport() {
    // Clear the assembled secret text from component-local state.
    envExport = null;
  }

  async function copyEnvExport() {
    if (envExport === null) return;
    const ok = await copyToClipboard(envExport);
    toast(ok ? "Copied .env to clipboard" : "Copy failed", ok ? "ok" : "error");
  }

  // --- Use in your dev server (run command) ----------------------------
  // Contains NO secret — only the item title, the vault name, and the user's
  // own dev command. Not gated.
  let devCommand = $state("");
  const runCommand = $derived(
    item ? buildRunCommand(item.title, vaultName, devCommand) : "",
  );

  async function copyRunCommand() {
    const ok = await copyToClipboard(runCommand);
    toast(ok ? "Command copied" : "Copy failed", ok ? "ok" : "error");
  }

  // --- Attachments ------------------------------------------------------
  // The attachment list is NON-SECRET metadata (id / filename / size). Crucially
  // the attachment PLAINTEXT never enters the webview: attaching passes the OS
  // file-picker's SOURCE path to the daemon (which reads it), and saving passes
  // a native save-dialog DEST path to the daemon (which writes it). Only paths +
  // metadata cross the command bridge — a stronger boundary than reveal_field.
  // We still reset this list on item change (below, in load()) to stay tidy.
  let attachments = $state<AttachmentView[]>([]);
  let attachmentsError = $state("");
  let attaching = $state(false);
  // Per-attachment busy flags (Save / Remove), keyed by attachment id.
  let attachBusy = $state<Record<string, boolean>>({});
  // Remove-confirmation: the attachment id awaiting a confirm, or null.
  let confirmingRemove = $state<string | null>(null);

  async function loadAttachments() {
    attachmentsError = "";
    try {
      attachments = await listAttachments(vault, itemId);
    } catch (err) {
      attachments = [];
      attachmentsError = typeof err === "string" ? err : "Could not list attachments.";
    }
  }

  async function attachFile() {
    if (attaching) return;
    // Native OPEN dialog → returns the picked SOURCE path (a string) or null.
    let picked: string | null;
    try {
      const result = await openDialog({ multiple: false, directory: false, title: "Choose a file to attach" });
      picked = typeof result === "string" ? result : null;
    } catch (err) {
      toast(typeof err === "string" ? err : "Could not open the file picker", "error");
      return;
    }
    if (!picked) return; // user cancelled
    attaching = true;
    try {
      // The daemon reads `picked` itself; the file bytes never cross into JS.
      await addAttachment(vault, itemId, picked);
      await loadAttachments();
      toast("File attached", "ok");
    } catch (err) {
      toast(typeof err === "string" ? err : "Attach failed", "error");
    } finally {
      attaching = false;
    }
  }

  async function saveAttachment(att: AttachmentView) {
    if (attachBusy[att.id]) return;
    // Native SAVE dialog → returns the chosen DEST path (a string) or null.
    let dest: string | null;
    try {
      dest = await saveDialog({ defaultPath: att.filename, title: "Save attachment as" });
    } catch (err) {
      toast(typeof err === "string" ? err : "Could not open the save dialog", "error");
      return;
    }
    if (!dest) return; // user cancelled
    attachBusy = { ...attachBusy, [att.id]: true };
    try {
      // The daemon decrypts and writes to `dest` itself — plaintext never in JS.
      // The native save dialog already confirmed any overwrite, so force = true.
      const saved = await getAttachment(vault, itemId, att.id, dest, true);
      toast(`Saved ${saved.filename} to ${dest}`, "ok");
    } catch (err) {
      toast(typeof err === "string" ? err : "Save failed", "error");
    } finally {
      attachBusy = { ...attachBusy, [att.id]: false };
    }
  }

  async function removeAttachment(att: AttachmentView) {
    if (attachBusy[att.id]) return;
    attachBusy = { ...attachBusy, [att.id]: true };
    try {
      await deleteAttachment(vault, itemId, att.id);
      confirmingRemove = null;
      await loadAttachments();
      toast("Attachment removed", "ok");
    } catch (err) {
      toast(typeof err === "string" ? err : "Remove failed", "error");
    } finally {
      attachBusy = { ...attachBusy, [att.id]: false };
    }
  }

  async function load() {
    loading = true;
    error = "";
    // Clear any previously revealed secrets before showing a new item.
    revealed = {};
    // Clear the assembled .env export (secret) and the transient dev command.
    envExport = null;
    devCommand = "";
    totp = null;
    stopTotp();
    // Clear attachment list state on item change (non-secret metadata, but keep
    // it tidy — same discipline as the other per-item state above).
    attachments = [];
    attachmentsError = "";
    attachBusy = {};
    confirmingRemove = null;
    try {
      const it = await getItem(vault, itemId);
      item = it;
      if (it.type_str === "totp") {
        await startTotp();
      }
      // Attachments hang off any item type; load them once the item is known.
      await loadAttachments();
    } catch (err) {
      item = null;
      error = typeof err === "string" ? err : "Could not load the item.";
    } finally {
      loading = false;
    }
  }

  async function reveal(name: string) {
    if (revealBusy[name]) return;
    revealBusy = { ...revealBusy, [name]: true };
    try {
      const value = await revealField(vault, itemId, name);
      revealed = { ...revealed, [name]: value };
    } catch (err) {
      toast(typeof err === "string" ? err : "Reveal failed", "error");
    } finally {
      revealBusy = { ...revealBusy, [name]: false };
    }
  }

  function hide(name: string) {
    const next = { ...revealed };
    delete next[name];
    revealed = next;
  }

  async function copyField(name: string) {
    // Reveal on demand if not already revealed, then copy — one gesture.
    let value = revealed[name];
    if (value === undefined) {
      try {
        value = await revealField(vault, itemId, name);
      } catch (err) {
        toast(typeof err === "string" ? err : "Copy failed", "error");
        return;
      }
    }
    const ok = await copyToClipboard(value);
    toast(ok ? "Copied to clipboard" : "Copy failed", ok ? "ok" : "error");
  }

  async function copyPlain(value: string) {
    const ok = await copyToClipboard(value);
    toast(ok ? "Copied to clipboard" : "Copy failed", ok ? "ok" : "error");
  }

  async function startTotp() {
    await tickTotp();
    totpTimer = setInterval(tickTotp, 1000);
  }
  function stopTotp() {
    if (totpTimer) {
      clearInterval(totpTimer);
      totpTimer = undefined;
    }
  }
  async function tickTotp() {
    try {
      totp = await totpApi(vault, itemId);
    } catch (err) {
      error = typeof err === "string" ? err : "TOTP unavailable.";
      stopTotp();
    }
  }

  async function copyTotp() {
    if (!totp) return;
    const ok = await copyToClipboard(totp.code);
    toast(ok ? "Code copied" : "Copy failed", ok ? "ok" : "error");
  }

  // Reload whenever the selected item changes; clean up the TOTP timer on
  // teardown. Reading itemId/vault registers the dependency.
  $effect(() => {
    // Touch reactive deps so the effect re-runs on change.
    void itemId;
    void vault;
    load();
    return () => stopTotp();
  });

  function ringPct(t: TotpView): number {
    return Math.max(0, Math.min(100, (t.seconds_remaining / t.period) * 100));
  }
</script>

{#if loading && !item}
  <div class="empty">Loading…</div>
{:else if error && !item}
  <div class="detail">
    <div class="error" role="alert">{error}</div>
  </div>
{:else if item}
  <div class="detail">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem">
      <h2>{item.title}</h2>
      <div class="field-actions">
        <button class="btn btn-small" onclick={() => onEdit?.(itemId)}>Edit</button>
        <button
          class="btn btn-small"
          style="color:var(--danger);border-color:var(--danger)"
          onclick={() => (confirmingDelete = true)}
        >
          Delete
        </button>
      </div>
    </div>
    <p class="row-meta" style="margin-top:0">
      <span class="badge">{typeLabel(item.type_str)}</span>
      {#if item.favorite}<span class="badge">★ favorite</span>{/if}
      <span>Updated {formatTimestamp(item.updated_at)}</span>
      <span>· v{item.version}</span>
    </p>

    {#if confirmingDelete}
      <div class="error" role="alertdialog" aria-labelledby="del-title" style="color:var(--text);background:var(--bg-hover);border-color:var(--border)">
        <p id="del-title" style="margin:0 0 0.6rem">
          Move <strong>{item.title}</strong> to the trash? It is recoverable for
          30 days.
        </p>
        <div class="toolbar">
          <button
            class="btn btn-small"
            style="color:var(--danger);border-color:var(--danger)"
            onclick={doDelete}
            disabled={deleting}
          >
            {deleting ? "Deleting…" : "Delete"}
          </button>
          <button
            class="btn btn-small"
            onclick={() => (confirmingDelete = false)}
            disabled={deleting}
          >
            Cancel
          </button>
        </div>
      </div>
    {/if}

    {#if item.tags.length}
      <p class="row-meta">
        {#each item.tags as tag (tag)}<span class="badge">#{tag}</span>{/each}
      </p>
    {/if}

    {#if item.type_str === "totp"}
      <div class="field" style="grid-template-columns:1fr auto">
        <div class="totp">
          {#if totp}
            <span class="totp-code" aria-label={`Current code ${groupTotp(totp.code)}`}>
              {groupTotp(totp.code)}
            </span>
            <div
              class="ring"
              style={`--pct:${ringPct(totp)}`}
              role="img"
              aria-label={`${totp.seconds_remaining} seconds remaining`}
            >
              <span aria-hidden="true">{totp.seconds_remaining}</span>
            </div>
          {:else}
            <span class="muted">Computing…</span>
          {/if}
        </div>
        <div class="field-actions">
          <button class="btn btn-small" onclick={copyTotp} disabled={!totp}>Copy</button>
        </div>
      </div>
    {/if}

    {#if item.notes}
      <div class="field-group" style="margin-top:1rem">
        <div class="field-name">Notes</div>
        <div style="white-space:pre-wrap;user-select:text">{item.notes}</div>
      </div>
    {/if}

    {#if item.fields.length}
      <div role="list" aria-label="Item fields" style="margin-top:0.5rem">
        {#each item.fields as f (f.name)}
          <div class="field" role="listitem">
            <div class="field-name" id={`fld-${f.name}`}>{f.name}</div>
            <div class="field-value" aria-labelledby={`fld-${f.name}`}>
              {#if f.secret}
                {#if revealed[f.name] !== undefined}
                  <span style="user-select:all">{revealed[f.name]}</span>
                {:else}
                  <span aria-hidden="true">{MASK}</span>
                  <span class="sr-only">hidden secret</span>
                {/if}
              {:else}
                <span style="user-select:text">{f.value || "—"}</span>
              {/if}
            </div>
            <div class="field-actions">
              {#if f.secret}
                {#if revealed[f.name] !== undefined}
                  <button class="btn btn-small btn-ghost" onclick={() => hide(f.name)}>
                    Hide
                  </button>
                {:else}
                  <button
                    class="btn btn-small"
                    onclick={() => reveal(f.name)}
                    disabled={revealBusy[f.name]}
                    aria-label={`Reveal ${f.name}`}
                  >
                    {revealBusy[f.name] ? "…" : "Reveal"}
                  </button>
                {/if}
                <button
                  class="btn btn-small"
                  onclick={() => copyField(f.name)}
                  aria-label={`Copy ${f.name}`}
                >
                  Copy
                </button>
              {:else if f.value}
                <button
                  class="btn btn-small btn-ghost"
                  onclick={() => copyPlain(f.value)}
                  aria-label={`Copy ${f.name}`}
                >
                  Copy
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {:else if !item.notes && item.type_str !== "totp"}
      <p class="muted" style="margin-top:1rem">This item has no fields.</p>
    {/if}

    {#if item.type_str === "env_set"}
      <!-- Use in your dev server: the run command (no secret). -->
      <div class="field-group" style="margin-top:1.5rem;border-top:1px solid var(--border);padding-top:1rem">
        <div class="field-name">Use in your dev server</div>
        <p class="hint" style="margin:0.25rem 0 0.6rem">
          Runs your command with these variables injected into its environment —
          nothing is written to disk. <code>op://</code> works as an alias for
          <code>localpass://</code> too.
        </p>
        <label for="dev-cmd" class="sr-only">Your dev command</label>
        <input
          id="dev-cmd"
          type="text"
          autocomplete="off"
          spellcheck="false"
          placeholder="npm run dev"
          bind:value={devCommand}
        />
        <div
          class="gen-output"
          style="margin-top:0.5rem;font-family:var(--mono);align-items:center"
        >
          <span class="val" style="user-select:all;white-space:pre-wrap;word-break:break-all">{runCommand}</span>
          <button class="btn btn-small" type="button" onclick={copyRunCommand}>Copy</button>
        </div>
      </div>

      <!-- Export as .env (reveals every entry; secret). -->
      <div class="field-group" style="margin-top:1.25rem">
        <div class="field-name">Export as .env</div>
        {#if envExport === null}
          <p class="hint" style="margin:0.25rem 0 0.6rem">
            Reveals every variable and assembles a <code>.env</code> you can copy.
          </p>
          <button
            class="btn btn-small"
            type="button"
            onclick={exportEnv}
            disabled={exporting || item.fields.length === 0}
          >
            {exporting ? "Revealing…" : "Export as .env"}
          </button>
        {:else}
          <div
            class="error"
            role="note"
            style="color:var(--text);background:var(--bg-hover);border-color:var(--border);margin:0.4rem 0"
          >
            <strong>Contains secret values.</strong> This block holds the real variable
            values. It is cleared when you hide it or leave this item.
          </div>
          <textarea
            readonly
            aria-label="Assembled .env content (secret)"
            rows={Math.min(12, Math.max(3, (envExport.match(/\n/g)?.length ?? 0) + 1))}
            style="width:100%;font-family:var(--mono);padding:0.55em 0.7em;border:1px solid var(--border);border-radius:6px;background:var(--bg-panel);color:var(--text);user-select:all">{envExport}</textarea>
          <div class="toolbar" style="margin-top:0.4rem">
            <button class="btn btn-small" type="button" onclick={copyEnvExport}>Copy</button>
            <button class="btn btn-small btn-ghost" type="button" onclick={hideEnvExport}>Hide</button>
          </div>
        {/if}
      </div>
    {/if}

    <!--
      Attachments (available on ALL item types). SECURITY: the attachment
      plaintext NEVER enters this webview. "Attach file" hands the daemon the OS
      picker's SOURCE path (the daemon reads it); "Save" hands the daemon a
      native save-dialog DEST path (the daemon writes it). Only paths + metadata
      (id / filename / size) cross the bridge — a stronger boundary than the
      per-field reveal, whose value does reach JS.
    -->
    <div class="field-group" style="margin-top:1.5rem;border-top:1px solid var(--border);padding-top:1rem">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:0.5rem">
        <div class="field-name">Attachments</div>
        <button class="btn btn-small" type="button" onclick={attachFile} disabled={attaching}>
          {attaching ? "Attaching…" : "+ Attach file"}
        </button>
      </div>
      <p class="hint" style="margin:0.25rem 0 0.6rem">
        Files are stored encrypted. Downloads are written straight to the file
        you choose — the contents never pass through this window.
      </p>

      {#if attachmentsError}
        <div class="error" role="alert" aria-live="polite">{attachmentsError}</div>
      {/if}

      <div aria-live="polite">
        {#if attachments.length}
          <div role="list" aria-label="Attachments">
            {#each attachments as att (att.id)}
              <div class="field" role="listitem" style="grid-template-columns:1fr auto">
                <div>
                  <span style="user-select:text">{att.filename}</span>
                  <span class="muted" style="margin-left:0.5rem">{humanSize(att.size)}</span>
                </div>
                {#if confirmingRemove === att.id}
                  <div class="field-actions">
                    <span class="sr-only" role="status">Confirm removing {att.filename}</span>
                    <span aria-hidden="true" class="muted" style="align-self:center">Remove?</span>
                    <button
                      class="btn btn-small"
                      style="color:var(--danger);border-color:var(--danger)"
                      onclick={() => removeAttachment(att)}
                      disabled={attachBusy[att.id]}
                    >
                      {attachBusy[att.id] ? "Removing…" : "Remove"}
                    </button>
                    <button
                      class="btn btn-small btn-ghost"
                      onclick={() => (confirmingRemove = null)}
                      disabled={attachBusy[att.id]}
                    >
                      Cancel
                    </button>
                  </div>
                {:else}
                  <div class="field-actions">
                    <button
                      class="btn btn-small"
                      onclick={() => saveAttachment(att)}
                      disabled={attachBusy[att.id]}
                      aria-label={`Save ${att.filename}`}
                    >
                      {attachBusy[att.id] ? "…" : "Save"}
                    </button>
                    <button
                      class="btn btn-small btn-ghost"
                      onclick={() => (confirmingRemove = att.id)}
                      aria-label={`Remove ${att.filename}`}
                    >
                      Remove
                    </button>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else if !attachmentsError}
          <p class="muted" style="margin:0">No attachments.</p>
        {/if}
      </div>
    </div>
  </div>
{/if}
