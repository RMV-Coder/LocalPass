<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The unlocked shell: vault sidebar, item list + search, and the detail/generator
  pane. Keyboard-navigable throughout (arrow keys move the item list; the search
  box drives `search`). No secret value is held here — only summaries and ids;
  reveals happen inside ItemDetail.
-->
<script lang="ts">
  import { listVaults, createVault, deleteVault, listItems, search as searchApi, getItem } from "../lib/api";
  import type { VaultView, ItemSummaryView, ItemView } from "../lib/types";
  import { typeLabel, formatTimestamp } from "../lib/format";
  import ItemDetail from "./ItemDetail.svelte";
  import ItemForm from "./ItemForm.svelte";
  import Generator from "./Generator.svelte";
  import Devices from "./Devices.svelte";
  import Security from "./Security.svelte";
  import Help from "./Help.svelte";

  interface Props {
    /** Called after the set of vaults changes (create/adopt) so the parent can
     *  refresh session-derived state like the header's vault count. */
    onVaultsChanged?: () => void;
  }
  let { onVaultsChanged }: Props = $props();

  let vaults = $state<VaultView[]>([]);
  let selectedVault = $state<string>(""); // vault id
  let items = $state<ItemSummaryView[]>([]);
  let selectedItem = $state<string>(""); // item id
  let query = $state("");
  let view = $state<"item" | "generator" | "form" | "devices" | "security" | "help">("item");
  let loadingItems = $state(false);
  let error = $state("");
  let itemListEl: HTMLUListElement | undefined = $state();

  // The item being edited in the form (null = create mode).
  let editing = $state<ItemView | null>(null);

  async function loadVaults() {
    try {
      vaults = await listVaults();
      if (vaults.length && !selectedVault) {
        await selectVault(vaults[0].id);
      }
    } catch (err) {
      error = typeof err === "string" ? err : "Could not list vaults.";
    }
  }

  async function selectVault(id: string) {
    selectedVault = id;
    selectedItem = "";
    query = "";
    view = "item";
    await refreshItems();
  }

  // New-vault inline form state.
  let creatingVault = $state(false);
  let newVaultName = $state("");
  let vaultBusy = $state(false);

  async function submitNewVault() {
    const name = newVaultName.trim();
    if (!name || vaultBusy) return;
    vaultBusy = true;
    error = "";
    try {
      const id = await createVault(name);
      newVaultName = "";
      creatingVault = false;
      await loadVaults();
      await selectVault(id); // jump into the new vault
      onVaultsChanged?.(); // refresh the header vault count
    } catch (err) {
      error = typeof err === "string" ? err : "Could not create the vault.";
    } finally {
      vaultBusy = false;
    }
  }

  async function refreshItems() {
    if (!selectedVault) return;
    loadingItems = true;
    error = "";
    try {
      items = query.trim()
        ? await searchApi(selectedVault, query.trim())
        : await listItems(selectedVault);
    } catch (err) {
      items = [];
      error = typeof err === "string" ? err : "Could not load items.";
    } finally {
      loadingItems = false;
    }
  }

  let searchDebounce: ReturnType<typeof setTimeout> | undefined;
  function onSearchInput() {
    if (searchDebounce) clearTimeout(searchDebounce);
    searchDebounce = setTimeout(refreshItems, 150);
  }

  function selectItem(id: string) {
    selectedItem = id;
    view = "item";
  }

  // Open the create form (no existing item).
  function startAdd() {
    editing = null;
    selectedItem = "";
    view = "form";
  }

  // Open the edit form: fetch the (masked) item so the form can prefill
  // non-secret fields. Secret fields are NOT prefilled (they start as
  // "•••• unchanged" in the form).
  async function startEdit(id: string) {
    try {
      editing = await getItem(selectedVault, id);
      view = "form";
    } catch (err) {
      error = typeof err === "string" ? err : "Could not load the item to edit.";
    }
  }

  // After a create/update: refresh the list and select the saved item.
  async function onFormSaved(id: string) {
    editing = null;
    view = "item";
    await refreshItems();
    selectedItem = id;
  }

  function onFormCancel() {
    editing = null;
    view = "item";
  }

  // After a delete: clear selection and refresh the list.
  async function onItemDeleted() {
    selectedItem = "";
    view = "item";
    await refreshItems();
  }

  // --- Vault deletion (typed-confirmation destructive action) ---
  let deletingVault = $state(false);
  let deleteConfirmText = $state("");
  let deleteBusy = $state(false);
  // The exact phrase the user must type to confirm, e.g. `Delete Work`.
  const deletePhrase = $derived(`Delete ${currentVaultName}`);

  function openDeleteVault() {
    deleteConfirmText = "";
    deletingVault = true;
  }
  function cancelDeleteVault() {
    deletingVault = false;
    deleteConfirmText = "";
  }
  async function submitDeleteVault() {
    if (deleteBusy || !selectedVault || deleteConfirmText !== deletePhrase) return;
    deleteBusy = true;
    error = "";
    try {
      await deleteVault(selectedVault);
      deletingVault = false;
      deleteConfirmText = "";
      selectedItem = "";
      view = "item";
      selectedVault = ""; // force loadVaults() to pick the first remaining vault
      await loadVaults();
      if (vaults.length === 0) {
        items = [];
      }
      onVaultsChanged?.(); // refresh the header vault count
    } catch (err) {
      error = typeof err === "string" ? err : "Could not delete the vault.";
    } finally {
      deleteBusy = false;
    }
  }

  function onItemKeydown(e: KeyboardEvent, index: number) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const delta = e.key === "ArrowDown" ? 1 : -1;
      const next = Math.max(0, Math.min(items.length - 1, index + delta));
      const btns = itemListEl?.querySelectorAll<HTMLButtonElement>("button.row");
      btns?.[next]?.focus();
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectItem(items[index].id);
    }
  }

  $effect(() => {
    loadVaults();
  });

  const currentVaultName = $derived(
    vaults.find((v) => v.id === selectedVault)?.name ?? "",
  );

  // Which single screen the mobile layout shows (desktop shows all panes at
  // once and ignores this). Drives the `data-mobile` attribute the CSS keys on
  // and the active state of the bottom tab bar.
  const mobileScreen = $derived(
    view === "generator"
      ? "generator"
      : view === "security"
        ? "security"
        : view === "devices"
          ? "devices"
          : view === "help"
            ? "help"
            : view === "form"
              ? "form"
              : selectedItem
                ? "detail"
                : "list",
  );

  // Bottom-tab navigation: switch section, and returning to Items clears any
  // selected item so the tab lands on the list rather than a stale detail.
  function goTab(next: "item" | "generator" | "security" | "devices" | "help") {
    view = next;
    if (next === "item") selectedItem = "";
  }
</script>

<!-- The inline new-vault form, shared between the desktop sidebar and the
     mobile Items screen (only one is visible at a time). -->
{#snippet newVaultForm()}
  <form class="new-vault" onsubmit={(e) => { e.preventDefault(); submitNewVault(); }}>
    <input
      type="text"
      placeholder="Vault name (e.g. work)"
      aria-label="New vault name"
      bind:value={newVaultName}
      autocomplete="off"
      disabled={vaultBusy}
    />
    <div class="new-vault-actions">
      <button class="btn btn-small btn-primary" type="submit" disabled={vaultBusy || !newVaultName.trim()}>
        {vaultBusy ? "Creating…" : "Create"}
      </button>
      <button class="btn btn-small" type="button" onclick={() => { creatingVault = false; }} disabled={vaultBusy}>
        Cancel
      </button>
    </div>
  </form>
{/snippet}

<div
  class="shell {selectedItem || view === 'generator' || view === 'devices' || view === 'security' || view === 'help' ? 'show-items' : ''}"
  data-mobile={mobileScreen}
>
  <!-- Vault sidebar -->
  <nav class="pane vault-pane" aria-label="Vaults">
    <div class="pane-header" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
      <p class="pane-title" style="margin:0">Vaults</p>
      <button
        class="btn btn-small"
        onclick={() => { creatingVault = !creatingVault; newVaultName = ""; }}
        aria-expanded={creatingVault}
        title="Create a new vault"
      >+ New</button>
    </div>
    {#if creatingVault}{@render newVaultForm()}{/if}
    {#if vaults.length === 0}
      <p class="empty">No vaults yet.</p>
    {:else}
      <ul class="list">
        {#each vaults as v (v.id)}
          <li>
            <button
              class="row"
              aria-current={v.id === selectedVault}
              onclick={() => selectVault(v.id)}
            >
              <span class="row-title">{v.name}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="pane-header" style="position:static;border-top:1px solid var(--border);border-bottom:none">
      <button
        class="row {view === 'generator' ? 'selected' : ''}"
        aria-current={view === "generator"}
        onclick={() => {
          view = "generator";
          selectedItem = "";
        }}
      >
        <span class="row-title">Generator</span>
      </button>
      <button
        class="row {view === 'security' ? 'selected' : ''}"
        aria-current={view === "security"}
        onclick={() => {
          view = "security";
          selectedItem = "";
        }}
      >
        <span class="row-title">Security</span>
      </button>
      <button
        class="row {view === 'devices' ? 'selected' : ''}"
        aria-current={view === "devices"}
        onclick={() => {
          view = "devices";
          selectedItem = "";
        }}
      >
        <span class="row-title">Devices &amp; Sync</span>
      </button>
      <button
        class="row {view === 'help' ? 'selected' : ''}"
        aria-current={view === "help"}
        onclick={() => {
          view = "help";
          selectedItem = "";
        }}
      >
        <span class="row-title">Help</span>
      </button>
    </div>
  </nav>

  <!-- Item list + search -->
  <section class="pane item-pane" aria-label="Items">
    <div class="pane-header">
      <!-- Mobile only: the vault picker + New (the desktop sidebar is hidden). -->
      <div class="mobile-vault-controls">
        <div class="mvc-row">
          <label class="sr-only" for="m-vault-select">Vault</label>
          <select id="m-vault-select" value={selectedVault} onchange={(e) => selectVault(e.currentTarget.value)}>
            {#each vaults as v (v.id)}
              <option value={v.id}>{v.name}</option>
            {/each}
          </select>
          <button
            class="btn btn-small"
            onclick={() => { creatingVault = !creatingVault; newVaultName = ""; }}
            aria-expanded={creatingVault}
          >+ New</button>
        </div>
        {#if creatingVault}{@render newVaultForm()}{/if}
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:0.5rem">
        <p class="pane-title">{currentVaultName || "Items"}</p>
        <button
          class="btn btn-small btn-primary"
          onclick={startAdd}
          disabled={!selectedVault}
          aria-label="Add item"
        >
          + Add
        </button>
      </div>
      <div style="margin-top:0.5rem">
        <label for="item-search" class="sr-only">Search items</label>
        <input
          id="item-search"
          type="search"
          placeholder="Search…"
          bind:value={query}
          oninput={onSearchInput}
          autocomplete="off"
          spellcheck="false"
        />
      </div>
      {#if selectedVault}
        <div class="vault-danger-row">
          <button type="button" class="link-danger" onclick={openDeleteVault}>
            Delete vault…
          </button>
        </div>
      {/if}
    </div>

    {#if error}
      <div class="error" role="alert" style="margin:0.6rem">{error}</div>
    {/if}

    {#if loadingItems}
      <p class="empty">Loading…</p>
    {:else if items.length === 0}
      <p class="empty">{query ? "No matches." : "No items in this vault."}</p>
    {:else}
      <ul class="list" bind:this={itemListEl} role="listbox" aria-label="Items" tabindex="-1">
        {#each items as it, i (it.id)}
          <li role="presentation">
            <button
              class="row"
              role="option"
              aria-selected={it.id === selectedItem}
              class:selected={it.id === selectedItem}
              onclick={() => selectItem(it.id)}
              onkeydown={(e) => onItemKeydown(e, i)}
            >
              <span class="row-title">{it.title}</span>
              <span class="row-meta">
                <span class="badge">{typeLabel(it.type_str)}</span>
                <span>{formatTimestamp(it.updated_at)}</span>
              </span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <!-- Detail / generator / form -->
  <main class="pane" aria-label="Details" aria-live="polite">
    <!-- Mobile only (item detail / form): return to the item list. -->
    <button
      class="mobile-back btn btn-small"
      onclick={() => { selectedItem = ""; editing = null; view = "item"; }}
    >← Items</button>
    {#if view === "generator"}
      <Generator />
    {:else if view === "security"}
      <Security vault={selectedVault} vaultName={currentVaultName} />
    {:else if view === "help"}
      <Help />
    {:else if view === "devices"}
      <Devices
        {vaults}
        {selectedVault}
        onVaultsChanged={async () => { await loadVaults(); onVaultsChanged?.(); }}
      />
    {:else if view === "form" && selectedVault}
      {#key editing?.id ?? "new"}
        <ItemForm
          vault={selectedVault}
          existing={editing}
          onSaved={onFormSaved}
          onCancel={onFormCancel}
        />
      {/key}
    {:else if selectedItem && selectedVault}
      {#key selectedItem}
        <ItemDetail
          vault={selectedVault}
          vaultName={currentVaultName}
          itemId={selectedItem}
          onEdit={startEdit}
          onDeleted={onItemDeleted}
        />
      {/key}
    {:else}
      <div class="empty">
        <p>Select an item to view its details.</p>
        <p class="muted">Secret fields stay masked until you reveal them.</p>
      </div>
    {/if}
  </main>
</div>

<!-- Mobile only: fixed bottom tab bar (hidden on desktop via CSS). -->
<nav class="mobile-tabbar" aria-label="Sections">
  <button
    class:active={mobileScreen === "list" || mobileScreen === "detail" || mobileScreen === "form"}
    onclick={() => goTab("item")}
  >
    <span class="ico" aria-hidden="true">🔑</span><span>Items</span>
  </button>
  <button class:active={mobileScreen === "generator"} onclick={() => goTab("generator")}>
    <span class="ico" aria-hidden="true">🎲</span><span>Generator</span>
  </button>
  <button class:active={mobileScreen === "security"} onclick={() => goTab("security")}>
    <span class="ico" aria-hidden="true">🛡️</span><span>Security</span>
  </button>
  <button class:active={mobileScreen === "devices"} onclick={() => goTab("devices")}>
    <span class="ico" aria-hidden="true">🔗</span><span>Devices</span>
  </button>
  <button class:active={mobileScreen === "help"} onclick={() => goTab("help")}>
    <span class="ico" aria-hidden="true">❔</span><span>Help</span>
  </button>
</nav>

<!-- Destructive: delete the selected vault, gated by a typed confirmation. -->
{#if deletingVault}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    aria-label="Cancel"
    onclick={cancelDeleteVault}
    onkeydown={(e) => { if (e.key === "Escape") cancelDeleteVault(); }}
  >
    <!-- Stop clicks inside the card from closing the modal. -->
    <div
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="del-vault-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape") cancelDeleteVault(); }}
    >
      <h2 id="del-vault-title" class="modal-title">Delete this vault?</h2>
      <p>
        This permanently unlists <strong>{currentVaultName}</strong> and everything
        inside it. It can’t be undone from the app.
      </p>
      <p class="muted">
        Type <code class="confirm-phrase">{deletePhrase}</code> to confirm.
      </p>
      <form onsubmit={(e) => { e.preventDefault(); submitDeleteVault(); }}>
        <label class="sr-only" for="del-vault-confirm">Confirmation phrase</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          id="del-vault-confirm"
          type="text"
          bind:value={deleteConfirmText}
          placeholder={deletePhrase}
          autocomplete="off"
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
          autofocus
          disabled={deleteBusy}
        />
        {#if error}<p class="error" role="alert" style="margin-top:0.6rem">{error}</p>{/if}
        <div class="modal-actions">
          <button type="button" class="btn" onclick={cancelDeleteVault} disabled={deleteBusy}>
            Cancel
          </button>
          <button
            type="submit"
            class="btn btn-danger"
            disabled={deleteBusy || deleteConfirmText !== deletePhrase}
          >
            {deleteBusy ? "Deleting…" : "Delete vault"}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}
