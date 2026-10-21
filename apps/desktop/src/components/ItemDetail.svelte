<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Item detail. Every field row is its own copy button (CopyRow); secret rows
  add an eye that reveals the value in place. Secret values are fetched only on
  an explicit gesture (reveal_field) and live only in the component-local
  `revealed` map, which is RESET whenever the item changes (see load()) and
  each value re-masks after REMASK_MS — never a persisted store. TOTP items
  show a live code with a seconds-remaining ring.
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
  import { MASK, typeLabel, fieldLabel, formatTimestamp, formatAgo, groupTotp, humanSize } from "../lib/format";
  import { formatDotenv, buildRunCommand } from "../lib/envset";
  import { copySecret, copySecretVia, copyToClipboard } from "../lib/clipboard";
  import { toast } from "../lib/toast";
  import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
  import Icon, { typeIcon } from "./Icon.svelte";
  import CopyRow from "./CopyRow.svelte";

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

  /** A revealed value goes back behind the mask after this long. */
  const REMASK_MS = 30_000;

  let item = $state<ItemView | null>(null);
  let error = $state("");
  let loading = $state(false);

  // Overflow menu + delete confirmation.
  let menuOpen = $state(false);
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
  const remaskTimers = new Map<string, ReturnType<typeof setTimeout>>();

  function clearRevealed() {
    for (const t of remaskTimers.values()) clearTimeout(t);
    remaskTimers.clear();
    revealed = {};
  }

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

  async function copyEnvExport() {
    if (envExport === null) return;
    const ok = await copySecret(envExport);
    toast(ok ? "Copied .env to clipboard" : "Copy failed", ok ? "ok" : "error");
  }

  // --- Use in your dev server (run command) ----------------------------
  // Contains NO secret — only the item title, the vault name, and the user's
  // own dev command. Not gated.
  let devCommand = $state("");
  const runCommand = $derived(item ? buildRunCommand(item.title, vaultName, devCommand) : "");

  // --- Attachments ------------------------------------------------------
  // The attachment list is NON-SECRET metadata (id / filename / size). The
  // attachment PLAINTEXT never enters the webview: attaching passes the OS
  // file-picker's SOURCE path to the daemon (which reads it), and saving passes
  // a native save-dialog DEST path to the daemon (which writes it).
  let attachments = $state<AttachmentView[]>([]);
  let attachmentsError = $state("");
  let attaching = $state(false);
  let attachBusy = $state<Record<string, boolean>>({});
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

  async function saveAttachment(att: AttachmentView): Promise<"webview" | null | undefined> {
    if (attachBusy[att.id]) return undefined;
    let dest: string | null;
    try {
      dest = await saveDialog({ defaultPath: att.filename, title: "Save attachment as" });
    } catch (err) {
      toast(typeof err === "string" ? err : "Could not open the save dialog", "error");
      return null;
    }
    if (!dest) return undefined; // user cancelled
    attachBusy = { ...attachBusy, [att.id]: true };
    try {
      // The daemon decrypts and writes to `dest` itself — plaintext never in JS.
      // The native save dialog already confirmed any overwrite, so force = true.
      const saved = await getAttachment(vault, itemId, att.id, dest, true);
      toast(`Saved ${saved.filename}`, "ok");
      return "webview";
    } catch (err) {
      toast(typeof err === "string" ? err : "Save failed", "error");
      return null;
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
    clearRevealed();
    envExport = null;
    devCommand = "";
    totp = null;
    stopTotp();
    attachments = [];
    attachmentsError = "";
    attachBusy = {};
    confirmingRemove = null;
    menuOpen = false;
    confirmingDelete = false;
    try {
      const it = await getItem(vault, itemId);
      item = it;
      if (it.type_str === "totp") {
        await startTotp();
      }
      await loadAttachments();
    } catch (err) {
      item = null;
      error = typeof err === "string" ? err : "Could not load the item.";
    } finally {
      loading = false;
    }
  }

  async function toggleReveal(name: string) {
    if (revealed[name] !== undefined) {
      hide(name);
      return;
    }
    if (revealBusy[name]) return;
    revealBusy = { ...revealBusy, [name]: true };
    try {
      const value = await revealField(vault, itemId, name);
      revealed = { ...revealed, [name]: value };
      clearTimeout(remaskTimers.get(name));
      remaskTimers.set(name, setTimeout(() => hide(name), REMASK_MS));
    } catch (err) {
      toast(typeof err === "string" ? err : "Reveal failed", "error");
    } finally {
      revealBusy = { ...revealBusy, [name]: false };
    }
  }

  function hide(name: string) {
    clearTimeout(remaskTimers.get(name));
    remaskTimers.delete(name);
    const next = { ...revealed };
    delete next[name];
    revealed = next;
  }

  /** Copy a secret field: reveal on demand (one gesture), copy, never keep it
   *  revealed as a side effect. */
  async function copySecretField(name: string): Promise<"native" | "webview" | null> {
    let value = revealed[name];
    if (value === undefined) {
      try {
        value = await revealField(vault, itemId, name);
      } catch (err) {
        toast(typeof err === "string" ? err : "Copy failed", "error");
        return null;
      }
    }
    return copySecretVia(value);
  }

  async function copyPlain(value: string): Promise<"native" | "webview" | null> {
    return (await copyToClipboard(value)) ? "webview" : null;
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

  async function copyTotp(): Promise<"native" | "webview" | null> {
    if (!totp) return null;
    return copySecretVia(totp.code);
  }

  // Reload whenever the selected item changes; clean up timers on teardown.
  $effect(() => {
    void itemId;
    void vault;
    load();
    return () => {
      stopTotp();
      clearRevealed();
    };
  });

  // Close the overflow menu on any outside click.
  $effect(() => {
    if (!menuOpen) return;
    const close = () => (menuOpen = false);
    const t = setTimeout(() => window.addEventListener("click", close, { once: true }));
    return () => {
      clearTimeout(t);
      window.removeEventListener("click", close);
    };
  });

  function ringPct(t: TotpView): number {
    return Math.max(0, Math.min(1, t.seconds_remaining / t.period));
  }
  const RING = 2 * Math.PI * 15;
</script>

{#if loading && !item}
  <div class="empty">Loading…</div>
{:else if error && !item}
  <div class="page">
    <div class="error" role="alert">{error}</div>
  </div>
{:else if item}
  <article class="page detail">
    <header class="d-head">
      <span class="type-glyph" aria-hidden="true"><Icon name={typeIcon(item.type_str)} size={20} /></span>
      <div class="d-title">
        <h2>{item.title}</h2>
        <p class="d-meta">
          <span>{typeLabel(item.type_str)}</span>
          <span aria-hidden="true">·</span>
          <time title={formatTimestamp(item.updated_at)}>Updated {formatAgo(item.updated_at)}</time>
          {#if item.favorite}<span class="badge"><Icon name="star" size={11} /> Favorite</span>{/if}
          {#each item.tags as tag (tag)}<span class="tag">{tag}</span>{/each}
        </p>
      </div>
      <div class="d-actions">
        <button class="btn btn-sm" onclick={() => onEdit?.(itemId)}><Icon name="edit" size={14} /> Edit</button>
        <div class="menu-anchor">
          <button
            class="icon-btn"
            aria-label="More actions"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
            onclick={(e) => { e.stopPropagation(); menuOpen = !menuOpen; }}
          >
            <Icon name="more" size={18} />
          </button>
          {#if menuOpen}
            <div class="menu" role="menu" style="right:0;top:36px">
              <button role="menuitem" onclick={() => { menuOpen = false; attachFile(); }} disabled={attaching}>
                <Icon name="paperclip" size={15} /> Attach a file…
              </button>
              <hr />
              <button role="menuitem" class="danger" onclick={() => { menuOpen = false; confirmingDelete = true; }}>
                <Icon name="trash" size={15} /> Move to trash…
              </button>
            </div>
          {/if}
        </div>
      </div>
    </header>

    {#if error}
      <div class="error" role="alert">{error}</div>
    {/if}

    <div class="copy-rows fields" role="list" aria-label="Fields">
      {#if item.type_str === "totp"}
        <div role="listitem">
          <CopyRow label="One-time code" display={totp ? groupTotp(totp.code) : "…"} secret copy={copyTotp}>
            {#snippet value()}
              <span class="totp-code" aria-label={totp ? `Current code ${groupTotp(totp.code)}` : "Computing"}>
                {totp ? groupTotp(totp.code) : "··· ···"}
              </span>
            {/snippet}
            {#snippet trailing()}
              {#if totp}
                <svg class="ring" viewBox="0 0 36 36" role="img" aria-label={`${totp.seconds_remaining} seconds remaining`}>
                  <circle cx="18" cy="18" r="15" class="track" />
                  <circle
                    cx="18"
                    cy="18"
                    r="15"
                    class="fill"
                    stroke-dasharray={RING}
                    stroke-dashoffset={RING * (1 - ringPct(totp))}
                    class:low={totp.seconds_remaining <= 5}
                  />
                  <text x="18" y="22" text-anchor="middle">{totp.seconds_remaining}</text>
                </svg>
              {/if}
            {/snippet}
          </CopyRow>
        </div>
      {/if}

      {#each item.fields as f (f.name)}
        {#if f.secret || f.value}
          <div role="listitem">
            {#if f.secret}
              <CopyRow
                label={fieldLabel(f.name, item.type_str)}
                display={revealed[f.name] ?? MASK}
                secret
                revealed={revealed[f.name] !== undefined}
                revealBusy={revealBusy[f.name]}
                copy={() => copySecretField(f.name)}
                onToggleReveal={() => toggleReveal(f.name)}
              />
            {:else}
              <CopyRow label={fieldLabel(f.name, item.type_str)} display={f.value} copy={() => copyPlain(f.value)} />
            {/if}
          </div>
        {/if}
      {/each}
    </div>

    {#if item.fields.length === 0 && !item.notes && item.type_str !== "totp"}
      <p class="muted" style="margin-top:16px">This item has no fields.</p>
    {/if}

    {#if item.notes}
      <section class="section">
        <h3 class="sub-h">Notes</h3>
        <p class="notes-body">{item.notes}</p>
      </section>
    {/if}

    {#if item.type_str === "env_set"}
      <section class="section">
        <h3 class="sub-h">Run with these variables</h3>
        <p class="hint" style="margin:0 0 8px">
          Injected into the process at start; nothing is written to disk.
        </p>
        <label for="dev-cmd" class="sr-only">Your dev command</label>
        <input id="dev-cmd" type="text" class="mono" autocomplete="off" spellcheck="false" placeholder="npm run dev" bind:value={devCommand} />
        <div style="margin-top:6px">
          <CopyRow label="Command" display={runCommand} copy={() => copyPlain(runCommand)} />
        </div>
      </section>

      <section class="section">
        <div class="section-head">
          <h3>Export as .env</h3>
          {#if envExport === null}
            <button class="btn btn-sm" type="button" onclick={exportEnv} disabled={exporting || item.fields.length === 0}>
              {exporting ? "Revealing…" : "Reveal all as .env"}
            </button>
          {:else}
            <div class="toolbar">
              <button class="btn btn-sm" type="button" onclick={copyEnvExport}><Icon name="copy" size={14} /> Copy</button>
              <button class="btn btn-sm btn-quiet" type="button" onclick={() => (envExport = null)}>Hide</button>
            </div>
          {/if}
        </div>
        {#if envExport !== null}
          <div class="callout warn" role="note">
            <span class="icon"><Icon name="alert" size={15} /></span>
            <span>These are the real values. They clear when you hide them or leave this item.</span>
          </div>
          <div class="code-block">
            <pre aria-label="Assembled .env content (secret)">{envExport}</pre>
          </div>
        {/if}
      </section>
    {/if}

    <!--
      Attachments (all item types). SECURITY: the plaintext NEVER enters this
      webview. Attaching hands the daemon the OS picker's SOURCE path; saving
      hands it a native save-dialog DEST path. Only paths + metadata cross.
    -->
    <section class="section">
      <div class="section-head">
        <h3>Attachments</h3>
        <button class="btn btn-sm btn-quiet" type="button" onclick={attachFile} disabled={attaching}>
          <Icon name="paperclip" size={14} /> {attaching ? "Attaching…" : "Attach file"}
        </button>
      </div>
      {#if attachmentsError}
        <div class="error" role="alert">{attachmentsError}</div>
      {/if}
      <div aria-live="polite">
        {#if attachments.length}
          <div class="copy-rows" role="list" aria-label="Attachments">
            {#each attachments as att (att.id)}
              <div role="listitem" class="att">
                {#if confirmingRemove === att.id}
                  <div class="att-confirm">
                    <span class="ellipsis">Remove <strong>{att.filename}</strong>?</span>
                    <div class="toolbar">
                      <button class="btn btn-sm btn-danger" onclick={() => removeAttachment(att)} disabled={attachBusy[att.id]}>
                        {attachBusy[att.id] ? "Removing…" : "Remove"}
                      </button>
                      <button class="btn btn-sm btn-quiet" onclick={() => (confirmingRemove = null)} disabled={attachBusy[att.id]}>
                        Cancel
                      </button>
                    </div>
                  </div>
                {:else}
                  <CopyRow label="File" display={att.filename} meta={humanSize(att.size)} plain hint="Click to save" done="Saved" copy={() => saveAttachment(att)}>
                    {#snippet trailing()}
                      <button
                        type="button"
                        class="icon-btn"
                        aria-label={`Remove ${att.filename}`}
                        title="Remove"
                        onclick={(e) => { e.stopPropagation(); confirmingRemove = att.id; }}
                        onkeydown={(e) => e.stopPropagation()}
                      >
                        <Icon name="trash" size={16} />
                      </button>
                    {/snippet}
                  </CopyRow>
                {/if}
              </div>
            {/each}
          </div>
        {:else if !attachmentsError}
          <p class="faint att-empty">Files you attach are stored encrypted with this item.</p>
        {/if}
      </div>
    </section>

    <p class="foot faint">Version {item.version} · created {formatTimestamp(item.created_at)}</p>
  </article>
{/if}

{#if confirmingDelete && item}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    aria-label="Cancel"
    onclick={() => (confirmingDelete = false)}
    onkeydown={(e) => { if (e.key === "Escape") confirmingDelete = false; }}
  >
    <div
      class="modal-card"
      role="alertdialog"
      tabindex="-1"
      aria-modal="true"
      aria-labelledby="del-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape") confirmingDelete = false; }}
    >
      <h2 id="del-title" class="modal-title">Move “{item.title}” to the trash?</h2>
      <p class="muted">You can restore it from the trash for 30 days.</p>
      <div class="modal-actions">
        <button class="btn" onclick={() => (confirmingDelete = false)} disabled={deleting}>Cancel</button>
        <!-- svelte-ignore a11y_autofocus -->
        <button class="btn btn-danger" onclick={doDelete} disabled={deleting} autofocus>
          {deleting ? "Moving…" : "Move to trash"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .detail {
    max-width: 760px;
  }
  .d-head {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: start;
    gap: 12px;
    margin-bottom: 14px;
  }
  .type-glyph {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    margin-top: 1px;
    border-radius: 8px;
    background: var(--bg-hover);
    color: var(--text-muted);
  }
  .d-title h2 {
    font-size: 20px;
    overflow-wrap: anywhere;
  }
  .d-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin-top: 4px;
    color: var(--text-muted);
    font-size: 12.5px;
  }
  .d-actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .menu-anchor {
    position: relative;
  }
  .fields {
    margin: 0 -10px;
  }
  .totp-code {
    display: block;
    font-family: var(--mono);
    font-size: 26px;
    font-weight: 600;
    letter-spacing: 0.06em;
    line-height: 1.25;
    font-variant-numeric: tabular-nums;
  }
  .ring {
    width: 30px;
    height: 30px;
    margin-right: 6px;
  }
  .ring circle {
    fill: none;
    stroke-width: 3;
  }
  .ring .track {
    stroke: var(--border-strong);
  }
  .ring .fill {
    stroke: var(--accent);
    stroke-linecap: round;
    transform: rotate(-90deg);
    transform-origin: 18px 18px;
    transition: stroke-dashoffset 1s linear;
  }
  .ring .fill.low {
    stroke: var(--warning);
  }
  .ring text {
    font-size: 11px;
    font-family: var(--font);
    fill: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .sub-h {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-muted);
    font-family: var(--font);
    margin-bottom: 4px;
  }
  .notes-body {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    user-select: text;
  }
  .att-confirm {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    min-height: 52px;
    padding: 6px 10px;
  }
  .copy-rows:has(.att) {
    margin: 0 -10px;
  }
  .att-empty {
    font-size: 12.5px;
  }
  .foot {
    margin-top: 28px;
    font-size: 12px;
  }
  @media (max-width: 719px) {
    .d-head {
      grid-template-columns: minmax(0, 1fr) auto;
    }
    .type-glyph {
      display: none;
    }
  }
</style>
