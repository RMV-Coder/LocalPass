<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The add/edit item form. Type selector (create only — an item's type cannot
  change), required title, type-conditional fields, a password field with a
  "Generate" affordance (calls the backend generator), tags, and add/remove
  custom fields.

  SECRET BOUNDARY: on EDIT, secret fields are NOT prefilled. They show
  "•••• (unchanged)" and an optional new value input; leaving one blank preserves
  the current (unrevealed) value server-side. New secret values live only in
  component-local form state and go straight to the backend on submit — never a
  store, never echoed back.

  ENV-SET EXCEPTION: editing an env-set inherently means editing its variables,
  so on edit we reveal + prefill the existing entries (the same gesture-driven,
  audit-logged reveal path as "Export as .env"). This is deliberate: a partial
  edit must carry the full set, or the non-empty replace would drop the rest.
  Those values are wiped on teardown like every other secret here.
-->
<script lang="ts">
  import { createItem, updateItem, generatePassword, parseDotenv, revealField } from "../lib/api";
  import type { ItemView, NewItemInput, CustomFieldInput, EnvEntryInput } from "../lib/types";
  import { toast } from "../lib/toast";
  import Icon, { typeIcon } from "./Icon.svelte";

  interface Props {
    vault: string;
    /** The existing item (edit mode) or null (create mode). */
    existing?: ItemView | null;
    /** Called with the item id after a successful create/update. */
    onSaved: (id: string) => void;
    /** Called when the user cancels. */
    onCancel: () => void;
  }
  let { vault, existing = null, onSaved, onCancel }: Props = $props();

  const isEdit = $derived(existing !== null);

  const TYPES = [
    { value: "login", label: "Login" },
    { value: "note", label: "Secure note" },
    { value: "api_key", label: "API key" },
    { value: "env_set", label: "Env set" },
    { value: "ssh_key", label: "SSH key" },
    { value: "totp", label: "TOTP" },
  ];

  // Look up a non-secret field's value on the existing item (for prefill).
  // A one-time snapshot of the item to seed form state from. The parent remounts
  // this component (via `{#key}`) whenever the edited item changes, so reading
  // the initial `existing` here is intentional (not a reactive dependency). We
  // read through this plain function to keep the seeds out of the reactive graph.
  // svelte-ignore state_referenced_locally
  const seed = existing;
  function fieldVal(name: string): string {
    return seed?.fields.find((f) => f.name === name && !f.secret)?.value ?? "";
  }

  // Form state, seeded from the item snapshot when editing.
  let type_str = $state(seed?.type_str ?? "login");
  let title = $state(seed?.title ?? "");
  let notes = $state(seed?.notes ?? "");
  let tagsText = $state((seed?.tags ?? []).join(", "));
  let favorite = $state(seed?.favorite ?? false);

  // Login / api-key common.
  let username = $state(fieldVal("username"));
  let url = $state(fieldVal("url"));
  let apiKey = $state(fieldVal("key"));
  // Secret value inputs (blank on edit = keep current).
  let password = $state("");

  // env-set entries. On EDIT these are prefilled from the item's existing
  // variables so the user edits the FULL set — adding one entry must not drop
  // the rest (submitting a non-empty env_entries replaces all server-side). The
  // KEYs come from the item's fields; each VALUE is revealed via the same
  // gesture-driven, audit-logged path as "Export as .env". Values live only in
  // component-local state and are wiped on teardown (below).
  let envEntries = $state<EnvEntryInput[]>([]);
  let envLoading = $state(false);
  let envLoadError = $state("");
  let envLoaded = false; // guard so the reveal runs exactly once

  async function loadEnvEntriesForEdit() {
    if (envLoaded || !seed || seed.type_str !== "env_set") return;
    envLoaded = true;
    const keys = seed.fields.map((f) => f.name);
    if (keys.length === 0) return;
    envLoading = true;
    envLoadError = "";
    try {
      const loaded: EnvEntryInput[] = [];
      for (const key of keys) {
        loaded.push({ key, value: await revealField(vault, seed.id, key) });
      }
      envEntries = loaded;
    } catch (err) {
      // On failure leave envEntries empty: an empty env_entries on submit
      // PRESERVES the existing variables server-side, so nothing is lost — but
      // warn the user (adding a new entry while the rest are unloaded would
      // replace them). See the alert in the template.
      envLoadError =
        typeof err === "string" ? err : "Could not load the existing variables.";
    } finally {
      envLoading = false;
    }
  }

  // ssh-key.
  let sshAlgo = $state(fieldVal("algo"));
  let sshPublic = $state("");
  let sshPrivate = $state(""); // secret; blank on edit = keep
  let sshFingerprint = $state("");

  // totp.
  let totpSecret = $state(""); // secret; blank on edit = keep
  let totpAlgo = $state("SHA1");
  let totpDigits = $state(6);
  let totpPeriod = $state(30);
  let totpIssuer = $state("");
  let totpAccount = $state("");

  // Custom fields (create + edit). On edit we do NOT prefill secret custom
  // values; the user can set a new value or leave blank to preserve.
  let customFields = $state<CustomFieldInput[]>([]);

  let showSecret = $state(false);
  let genLen = $state(20);
  let genSymbols = $state(true);
  let busy = $state(false);
  let error = $state("");

  async function generate() {
    try {
      const g = await generatePassword(genLen, genSymbols);
      password = g.secret;
      toast("Password generated", "ok");
    } catch (err) {
      toast(typeof err === "string" ? err : "Generation failed", "error");
    }
  }

  function addCustom() {
    customFields = [...customFields, { name: "", value: "", secret: false }];
  }
  function removeCustom(i: number) {
    customFields = customFields.filter((_, idx) => idx !== i);
  }

  function addEnv() {
    envEntries = [...envEntries, { key: "", value: "" }];
  }
  function removeEnv(i: number) {
    envEntries = envEntries.filter((_, idx) => idx !== i);
  }

  // --- Paste .env import ------------------------------------------------
  // The pasted blob is transient form state: parsed into entries on Import,
  // then cleared. It is no more secret than the entries themselves and never
  // leaves the app (parsing runs in the Rust backend). Cleared on unmount too.
  let showPasteEnv = $state(false);
  let pasteEnvText = $state("");
  let pasteBusy = $state(false);

  // Merge parsed entries into `envEntries` with last-wins on duplicate keys
  // (dotenv semantics). When appending, existing entries keep their position but
  // a later duplicate key overwrites the earlier value. Blank-key rows from the
  // manual editor are dropped so they don't shadow a real key.
  function mergeLastWins(base: EnvEntryInput[], incoming: EnvEntryInput[]): EnvEntryInput[] {
    const order: string[] = [];
    const map = new Map<string, string>();
    for (const e of [...base, ...incoming]) {
      const key = e.key.trim();
      if (key.length === 0) continue;
      if (!map.has(key)) order.push(key);
      map.set(key, e.value);
    }
    return order.map((k) => ({ key: k, value: map.get(k) ?? "" }));
  }

  async function importEnv(mode: "append" | "replace") {
    if (pasteBusy) return;
    pasteBusy = true;
    error = "";
    try {
      const parsed = await parseDotenv(pasteEnvText);
      if (parsed.length === 0) {
        toast("No variables found in the pasted text", "error");
        return;
      }
      const incoming: EnvEntryInput[] = parsed.map((e) => ({ key: e.key, value: e.value }));
      const before = mode === "replace" ? [] : envEntries;
      // Count keys that already existed (append) or repeat within the paste —
      // these are overwritten last-wins, reported as a note.
      const beforeKeys = new Set(before.map((e) => e.key.trim()).filter((k) => k.length > 0));
      const seen = new Set<string>();
      let overwritten = 0;
      for (const e of incoming) {
        const k = e.key.trim();
        if (k.length === 0) continue;
        if (beforeKeys.has(k) || seen.has(k)) overwritten += 1;
        seen.add(k);
      }
      envEntries = mergeLastWins(before, incoming);
      // Clear the transient paste text after a successful import.
      pasteEnvText = "";
      showPasteEnv = false;
      const note =
        overwritten > 0
          ? ` (${overwritten} duplicate key${overwritten === 1 ? "" : "s"} overwritten, last wins)`
          : "";
      toast(`Imported ${incoming.length} variable${incoming.length === 1 ? "" : "s"}${note}`, "ok");
    } catch (err) {
      toast(typeof err === "string" ? err : "Could not parse the pasted .env", "error");
    } finally {
      pasteBusy = false;
    }
  }

  function buildInput(): NewItemInput {
    const tags = tagsText
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const input: NewItemInput = {
      type_str,
      title: title.trim(),
      notes,
      tags,
      favorite,
      custom_fields: customFields
        .filter((f) => f.name.trim().length > 0)
        .map((f) => ({ name: f.name.trim(), value: f.value, secret: f.secret })),
    };

    // undefined for a secret left blank on edit = preserve; on create an empty
    // string is fine (the field is simply omitted for logins).
    const secretOrKeep = (v: string): string | undefined =>
      isEdit && v.length === 0 ? undefined : v.length > 0 ? v : undefined;

    if (type_str === "login") {
      input.username = username;
      input.url = url;
      input.password = secretOrKeep(password);
    } else if (type_str === "api_key") {
      input.api_key = apiKey;
      input.url = url;
      input.password = secretOrKeep(password);
    } else if (type_str === "env_set") {
      input.env_entries = envEntries.filter((e) => e.key.trim().length > 0);
    } else if (type_str === "ssh_key") {
      input.ssh_algo = sshAlgo;
      input.ssh_public_openssh = sshPublic;
      input.ssh_fingerprint = sshFingerprint;
      input.ssh_private_pem = secretOrKeep(sshPrivate);
    } else if (type_str === "totp") {
      input.totp_secret_b32 = secretOrKeep(totpSecret);
      input.totp_algo = totpAlgo;
      input.totp_digits = totpDigits;
      input.totp_period = totpPeriod;
      input.totp_issuer = totpIssuer;
      input.totp_account = totpAccount;
    }
    return input;
  }

  // On an env-set edit, reveal + prefill the existing variables once. The parent
  // remounts this component per edited item (via {#key}), so this runs on mount.
  $effect(() => {
    loadEnvEntriesForEdit();
  });

  async function submit(e: Event) {
    e.preventDefault();
    if (busy || envLoading) return; // don't save mid-reveal (would drop entries)
    if (title.trim().length === 0) {
      error = "A title is required.";
      return;
    }
    busy = true;
    error = "";
    try {
      const input = buildInput();
      let id: string;
      if (isEdit && existing) {
        await updateItem(vault, existing.id, input);
        id = existing.id;
      } else {
        id = await createItem(vault, input);
      }
      // Clear any secret material from the form before leaving.
      password = "";
      sshPrivate = "";
      totpSecret = "";
      toast(isEdit ? "Item updated" : "Item created", "ok");
      onSaved(id);
    } catch (err) {
      error = typeof err === "string" ? err : "Could not save the item.";
    } finally {
      busy = false;
    }
  }

  // Wipe transient secret form state on teardown. The pasted .env blob is
  // transient form state too (it holds the same values as the entries), so it is
  // cleared here as well.
  $effect(() => () => {
    password = "";
    sshPrivate = "";
    totpSecret = "";
    pasteEnvText = "";
    // env values revealed for editing are secret too — wipe them on teardown.
    envEntries = [];
  });
</script>

<div class="page form-page">
  <div class="page-head">
    <div>
      <h2>{isEdit ? `Edit ${seed?.title ?? "item"}` : "New item"}</h2>
      {#if isEdit}<p class="sub">Secret fields you leave blank keep their current value.</p>{/if}
    </div>
  </div>

  <form onsubmit={submit} novalidate>
    {#if !isEdit}
      <div class="field-group">
        <span class="label" id="if-type-label">Type</span>
        <div class="type-pick" role="radiogroup" aria-labelledby="if-type-label">
          {#each TYPES as t (t.value)}
            <label class="type-opt" class:on={type_str === t.value}>
              <input type="radio" name="if-type" value={t.value} bind:group={type_str} />
              <Icon name={typeIcon(t.value)} size={16} />
              <span>{t.label}</span>
            </label>
          {/each}
        </div>
      </div>
    {/if}

    <div class="field-group">
      <label for="if-title">Title</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="if-title" type="text" bind:value={title} autocomplete="off" required autofocus={!isEdit} />
    </div>

    {#if type_str === "login" || type_str === "api_key"}
      {#if type_str === "api_key"}
        <div class="field-group">
          <label for="if-apikey">Key ID</label>
          <input id="if-apikey" type="text" class="mono" autocomplete="off" spellcheck="false" bind:value={apiKey} />
        </div>
      {:else}
        <div class="field-group">
          <label for="if-username">Username</label>
          <input id="if-username" type="text" autocomplete="off" spellcheck="false" bind:value={username} />
        </div>
      {/if}

      <div class="field-group">
        <label for="if-password">{type_str === "api_key" ? "Secret" : "Password"}</label>
        <div class="pw-row">
          <div class="input-affix">
            <input
              id="if-password"
              class="mono"
              type={showSecret ? "text" : "password"}
              autocomplete="new-password"
              spellcheck="false"
              placeholder={isEdit ? "Unchanged" : ""}
              bind:value={password}
            />
            <button
              type="button"
              class="icon-btn"
              aria-label={showSecret ? "Hide" : "Show"}
              aria-pressed={showSecret}
              onclick={() => (showSecret = !showSecret)}
            >
              <Icon name={showSecret ? "eye-off" : "eye"} size={17} />
            </button>
          </div>
          <button class="btn" type="button" onclick={() => { generate(); showSecret = true; }}>
            <Icon name="generator" size={15} /> Generate
          </button>
        </div>
        <div class="gen-opts">
          <label class="len">
            <span>Length</span>
            <input type="range" min="8" max="64" bind:value={genLen} aria-label="Generated length" />
            <span class="num">{genLen}</span>
          </label>
          <label class="check"><input type="checkbox" bind:checked={genSymbols} /> <span>Symbols</span></label>
        </div>
      </div>

      <div class="field-group">
        <label for="if-url">{type_str === "api_key" ? "Endpoint" : "Website"}</label>
        <input id="if-url" type="text" autocomplete="off" spellcheck="false" placeholder="https://" bind:value={url} />
      </div>
    {/if}

    {#if type_str === "ssh_key"}
      <div class="row2">
        <div class="field-group">
          <label for="if-ssh-algo">Algorithm</label>
          <input id="if-ssh-algo" type="text" class="mono" autocomplete="off" bind:value={sshAlgo} placeholder="ed25519" />
        </div>
        <div class="field-group">
          <label for="if-ssh-fp">Fingerprint</label>
          <input id="if-ssh-fp" type="text" class="mono" autocomplete="off" bind:value={sshFingerprint} />
        </div>
      </div>
      <div class="field-group">
        <label for="if-ssh-public">Public key (OpenSSH)</label>
        <input id="if-ssh-public" type="text" class="mono" autocomplete="off" spellcheck="false" bind:value={sshPublic} />
      </div>
      <div class="field-group">
        <label for="if-ssh-private">Private key (PEM)</label>
        <textarea
          id="if-ssh-private"
          class="mono"
          bind:value={sshPrivate}
          rows="4"
          spellcheck="false"
          placeholder={isEdit ? "Unchanged" : "Paste the private key (PEM or OpenSSH format)"}
        ></textarea>
      </div>
    {/if}

    {#if type_str === "totp"}
      <div class="field-group">
        <label for="if-totp-secret">Setup key (Base32)</label>
        <input
          id="if-totp-secret"
          type="text"
          class="mono"
          autocomplete="off"
          spellcheck="false"
          bind:value={totpSecret}
          placeholder={isEdit ? "Unchanged" : ""}
        />
      </div>
      <div class="row3">
        <div class="field-group">
          <label for="if-totp-algo">Algorithm</label>
          <select id="if-totp-algo" bind:value={totpAlgo}>
            <option value="SHA1">SHA1</option>
            <option value="SHA256">SHA256</option>
            <option value="SHA512">SHA512</option>
          </select>
        </div>
        <div class="field-group">
          <label for="if-totp-digits">Digits</label>
          <input id="if-totp-digits" type="number" min="6" max="10" bind:value={totpDigits} />
        </div>
        <div class="field-group">
          <label for="if-totp-period">Period (s)</label>
          <input id="if-totp-period" type="number" min="10" max="120" bind:value={totpPeriod} />
        </div>
      </div>
      <div class="row2">
        <div class="field-group">
          <label for="if-totp-issuer">Issuer</label>
          <input id="if-totp-issuer" type="text" autocomplete="off" bind:value={totpIssuer} />
        </div>
        <div class="field-group">
          <label for="if-totp-account">Account</label>
          <input id="if-totp-account" type="text" autocomplete="off" bind:value={totpAccount} />
        </div>
      </div>
    {/if}

    {#if type_str === "env_set"}
      <div class="field-group" role="group" aria-labelledby="env-h">
        <div class="section-head">
          <h3 id="env-h">Variables</h3>
          <button
            class="btn btn-sm btn-quiet"
            type="button"
            onclick={() => (showPasteEnv = !showPasteEnv)}
            aria-expanded={showPasteEnv}
            aria-controls="paste-env-area"
          >
            {showPasteEnv ? "Close paste" : "Paste .env"}
          </button>
        </div>
        {#if showPasteEnv}
          <div id="paste-env-area" class="paste-env">
            <label for="if-paste-env" class="sr-only">Raw .env content</label>
            <textarea
              id="if-paste-env"
              class="mono"
              bind:value={pasteEnvText}
              rows="5"
              spellcheck="false"
              autocomplete="off"
              placeholder={"# paste .env here\nDATABASE_URL=postgres://localhost/db\nexport API_KEY=abc123"}
            ></textarea>
            <div class="toolbar" style="margin-top:6px">
              <button
                class="btn btn-sm btn-primary"
                type="button"
                onclick={() => importEnv("append")}
                disabled={pasteBusy || pasteEnvText.trim().length === 0}
              >
                {pasteBusy ? "Importing…" : "Add to list"}
              </button>
              <button
                class="btn btn-sm"
                type="button"
                onclick={() => importEnv("replace")}
                disabled={pasteBusy || pasteEnvText.trim().length === 0}
              >
                Replace list
              </button>
              <span class="hint" style="margin:0">Comments and <code>export</code> are fine; a repeated key keeps the last value.</span>
            </div>
          </div>
        {/if}
        {#if envLoading}
          <p class="hint" role="status">Loading existing variables…</p>
        {:else if envLoadError}
          <div class="error" role="alert">
            {envLoadError} Adding variables now would replace the ones that did not load, so cancel and retry instead.
          </div>
        {/if}
        <div class="kv-list">
          {#each envEntries as entry, i (i)}
            <div class="kv">
              <input type="text" class="mono" placeholder="KEY" autocomplete="off" spellcheck="false" bind:value={entry.key} aria-label={`Variable ${i + 1} name`} />
              <input type="text" class="mono" placeholder="value" autocomplete="off" spellcheck="false" bind:value={entry.value} aria-label={`Variable ${i + 1} value`} />
              <button class="icon-btn" type="button" onclick={() => removeEnv(i)} aria-label={`Remove variable ${i + 1}`}><Icon name="x" size={15} /></button>
            </div>
          {/each}
        </div>
        <button class="btn btn-sm btn-quiet accent" type="button" onclick={addEnv}><Icon name="plus" size={14} /> Add variable</button>
      </div>
    {/if}

    <div class="field-group">
      <label for="if-notes">Notes</label>
      <textarea id="if-notes" bind:value={notes} rows="3"></textarea>
    </div>

    <div class="row2">
      <div class="field-group">
        <label for="if-tags">Tags</label>
        <input id="if-tags" type="text" autocomplete="off" bind:value={tagsText} placeholder="work, billing" />
      </div>
      <div class="field-group fav">
        <label class="check"><input type="checkbox" bind:checked={favorite} /> <span>Favorite</span></label>
      </div>
    </div>

    <div class="field-group" role="group" aria-labelledby="cf-h">
      <div class="section-head">
        <h3 id="cf-h">Custom fields</h3>
      </div>
      <div class="kv-list">
        {#each customFields as cf, i (i)}
          <div class="kv custom">
            <input type="text" placeholder="Name" autocomplete="off" bind:value={cf.name} aria-label={`Custom field ${i + 1} name`} />
            <input
              type={cf.secret ? "password" : "text"}
              class:mono={cf.secret}
              placeholder={isEdit && cf.secret ? "Unchanged" : "Value"}
              autocomplete="off"
              bind:value={cf.value}
              aria-label={`Custom field ${i + 1} value`}
            />
            <label class="check secret"><input type="checkbox" bind:checked={cf.secret} /> <span>Secret</span></label>
            <button class="icon-btn" type="button" onclick={() => removeCustom(i)} aria-label={`Remove custom field ${i + 1}`}><Icon name="x" size={15} /></button>
          </div>
        {/each}
      </div>
      <button class="btn btn-sm btn-quiet accent" type="button" onclick={addCustom}><Icon name="plus" size={14} /> Add field</button>
    </div>

    {#if error}
      <div class="error" role="alert" aria-live="assertive">{error}</div>
    {/if}

    <div class="form-actions">
      <button class="btn" type="button" onclick={onCancel} disabled={busy}>Cancel</button>
      <button class="btn btn-primary" type="submit" disabled={busy}>
        {busy ? "Saving…" : isEdit ? "Save changes" : "Save item"}
      </button>
    </div>
  </form>
</div>

<style>
  .form-page {
    max-width: 680px;
  }
  .type-pick {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .type-opt {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 32px;
    padding: 0 11px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    cursor: pointer;
    font-size: 13px;
    color: var(--text-muted);
  }
  .type-opt input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }
  .type-opt:has(input:focus-visible) {
    outline: 2px solid var(--focus);
    outline-offset: 2px;
  }
  .type-opt.on {
    border-color: var(--accent);
    background: var(--accent-tint);
    color: var(--text);
    font-weight: 600;
  }
  .type-opt.on :global(.icon) {
    color: var(--accent);
  }
  .pw-row {
    display: flex;
    gap: 6px;
  }
  .pw-row .input-affix {
    flex: 1;
  }
  .gen-opts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 16px;
    margin-top: 8px;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .len {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .len input {
    width: 140px;
  }
  .len .num {
    min-width: 2ch;
    color: var(--text);
  }
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0 12px;
  }
  .row3 {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0 12px;
  }
  .fav {
    align-self: end;
    padding-bottom: 8px;
  }
  .paste-env {
    margin-bottom: 10px;
  }
  .kv-list {
    display: grid;
    gap: 6px;
    margin-bottom: 6px;
  }
  .kv {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 3fr) auto;
    gap: 6px;
    align-items: center;
  }
  .kv.custom {
    grid-template-columns: minmax(0, 2fr) minmax(0, 3fr) auto auto;
  }
  .kv .secret {
    font-size: 12.5px;
    color: var(--text-muted);
    align-items: center;
  }
  .form-actions {
    position: sticky;
    bottom: 0;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 0 4px;
    margin-top: 8px;
    background: var(--bg-content);
    border-top: 1px solid var(--border);
  }
  @media (max-width: 719px) {
    .row2,
    .row3 {
      grid-template-columns: 1fr;
    }
    .kv,
    .kv.custom {
      grid-template-columns: minmax(0, 1fr) auto;
    }
    .kv.custom .secret {
      grid-column: 1;
    }
  }
</style>
