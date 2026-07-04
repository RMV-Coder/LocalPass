<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The unlocked shell: vault sidebar, item list + search, and the detail/generator
  pane. Keyboard-navigable throughout (arrow keys move the item list; the search
  box drives `search`). No secret value is held here — only summaries and ids;
  reveals happen inside ItemDetail.
-->
<script lang="ts">
  import { listVaults, listItems, search as searchApi } from "../lib/api";
  import type { VaultView, ItemSummaryView } from "../lib/types";
  import { typeLabel, formatTimestamp } from "../lib/format";
  import ItemDetail from "./ItemDetail.svelte";
  import Generator from "./Generator.svelte";

  let vaults = $state<VaultView[]>([]);
  let selectedVault = $state<string>(""); // vault id
  let items = $state<ItemSummaryView[]>([]);
  let selectedItem = $state<string>(""); // item id
  let query = $state("");
  let view = $state<"item" | "generator">("item");
  let loadingItems = $state(false);
  let error = $state("");
  let itemListEl: HTMLUListElement | undefined = $state();

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
</script>

<div class="shell {selectedItem || view === 'generator' ? 'show-items' : ''}">
  <!-- Vault sidebar -->
  <nav class="pane vault-pane" aria-label="Vaults">
    <div class="pane-header">
      <p class="pane-title">Vaults</p>
    </div>
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
    </div>
  </nav>

  <!-- Item list + search -->
  <section class="pane item-pane" aria-label="Items">
    <div class="pane-header">
      <p class="pane-title">{currentVaultName || "Items"}</p>
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

  <!-- Detail / generator -->
  <main class="pane" aria-label="Details" aria-live="polite">
    {#if view === "generator"}
      <Generator />
    {:else if selectedItem && selectedVault}
      {#key selectedItem}
        <ItemDetail vault={selectedVault} itemId={selectedItem} />
      {/key}
    {:else}
      <div class="empty">
        <p>Select an item to view its details.</p>
        <p class="muted">Secret fields stay masked until you reveal them.</p>
      </div>
    {/if}
  </main>
</div>
