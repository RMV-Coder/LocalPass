<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The unlocked shell (DESIGN.md "Layout"): a sidebar (vaults, tools, and the
  ambient status strip), the item list with search, and the content pane.
  Tool screens span the list + content columns; below 1000px the sidebar
  becomes an icon rail; below 720px it is one screen at a time with a bottom
  tab bar. Keyboard-navigable throughout (arrow keys move the item list,
  Ctrl+K searches, Ctrl+N adds, Ctrl+L locks). No secret value is held here —
  only summaries and ids; reveals happen inside ItemDetail.
-->
<script lang="ts">
  import {
    listVaults,
    createVault,
    deleteVault,
    listItems,
    listTrash,
    untrashItem,
    search as searchApi,
    getItem,
    syncStatus,
    listPeers,
  } from "../lib/api";
  import type {
    VaultView,
    ItemSummaryView,
    ItemView,
    TrashEntryView,
    SessionState,
  } from "../lib/types";
  import { typeLabel, formatTimestamp, formatAge, formatCountdown, isoTimestamp } from "../lib/format";
  import { summarizeSync, type SyncSummary } from "../lib/syncsummary";
  import { updates } from "../lib/updates";
  import Icon, { type IconName, typeIcon } from "./Icon.svelte";
  import Mark from "./Mark.svelte";
  import ItemDetail from "./ItemDetail.svelte";
  import ItemForm from "./ItemForm.svelte";
  import Generator from "./Generator.svelte";
  import Devices from "./Devices.svelte";
  import Security from "./Security.svelte";
  import Help from "./Help.svelte";
  import Dev from "./Dev.svelte";
  import Settings from "./Settings.svelte";

  type UnlockedSession = Extract<SessionState, { state: "unlocked" }>;

  interface Props {
    session: UnlockedSession;
    /** When the vault will auto-lock (ms since epoch), or null if never. */
    lockDeadline: number | null;
    onLock: () => void;
    /** Called after the set of vaults changes (create/adopt/delete). */
    onVaultsChanged?: () => void;
  }
  let { session, lockDeadline, onLock, onVaultsChanged }: Props = $props();

  /** The mobile vault picker's "New vault…" entry. */
  const NEW_VAULT = "__new_vault__";

  type View = "item" | "form" | "generator" | "security" | "devices" | "dev" | "settings" | "help" | "more";

  let vaults = $state<VaultView[]>([]);
  let selectedVault = $state<string>(""); // vault id
  let items = $state<ItemSummaryView[]>([]);
  let selectedItem = $state<string>(""); // item id
  let view = $state<View>("item");
  let loadingItems = $state(false);
  let error = $state("");
  let itemListEl: HTMLUListElement | undefined = $state();
  let searchEl: HTMLInputElement | undefined = $state();

  // The item being edited in the form (null = create mode).
  let editing = $state<ItemView | null>(null);

  const currentVaultName = $derived(vaults.find((v) => v.id === selectedVault)?.name ?? "");
  const vaultNames = $derived(new Map(vaults.map((v) => [v.id, v.name])));

  async function loadVaults() {
    try {
      vaults = await listVaults();
      if (vaults.length && !vaults.some((v) => v.id === selectedVault)) {
        await selectVault(vaults[0].id);
      }
    } catch (err) {
      error = typeof err === "string" ? err : "Could not list vaults.";
    }
  }

  async function selectVault(id: string, keepView = false) {
    selectedVault = id;
    selectedItem = "";
    if (!keepView) view = "item";
    showTrash = false;
    trash = [];
    if (scope === "vault") query = "";
    await refreshItems();
    void refreshSync();
  }

  // --- New vault (inline form in the sidebar / mobile list) ---
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
      await selectVault(id);
      onVaultsChanged?.();
    } catch (err) {
      error = typeof err === "string" ? err : "Could not create the vault.";
    } finally {
      vaultBusy = false;
    }
  }

  // --- Items + search ---
  let query = $state("");
  /** "vault" searches the selected vault; "all" searches every vault. */
  let scope = $state<"vault" | "all">("vault");
  /** Search-all results: each hit with the vault it came from. */
  let allHits = $state<{ vault: string; item: ItemSummaryView }[]>([]);

  async function refreshItems() {
    if (!selectedVault) return;
    loadingItems = true;
    error = "";
    try {
      const q = query.trim();
      if (scope === "all" && q) {
        const lists = await Promise.all(
          vaults.map(async (v) => (await searchApi(v.id, q)).map((item) => ({ vault: v.id, item }))),
        );
        allHits = lists.flat();
        items = [];
      } else {
        allHits = [];
        items = q ? await searchApi(selectedVault, q) : await listItems(selectedVault);
      }
    } catch (err) {
      items = [];
      allHits = [];
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
  function clearSearch() {
    query = "";
    refreshItems();
    searchEl?.focus();
  }
  function setScope(next: "vault" | "all") {
    scope = next;
    refreshItems();
    searchEl?.focus();
  }

  function selectItem(id: string) {
    selectedItem = id;
    editing = null;
    view = "item";
  }

  async function openHit(vault: string, id: string) {
    if (vault !== selectedVault) {
      selectedVault = vault;
      showTrash = false;
      void refreshSync();
    }
    selectItem(id);
  }

  function startAdd() {
    if (!selectedVault) return;
    editing = null;
    selectedItem = "";
    view = "form";
  }

  // Open the edit form: fetch the (masked) item so the form can prefill
  // non-secret fields. Secret fields are NOT prefilled.
  async function startEdit(id: string) {
    try {
      editing = await getItem(selectedVault, id);
      view = "form";
    } catch (err) {
      error = typeof err === "string" ? err : "Could not load the item to edit.";
    }
  }

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

  async function onItemDeleted() {
    selectedItem = "";
    view = "item";
    await refreshItems();
    if (showTrash) await refreshTrash();
  }

  // --- Trash (deleted items, recoverable for 30 days) ---
  let showTrash = $state(false);
  let trash = $state<TrashEntryView[]>([]);
  let trashLoading = $state(false);
  let restoringId = $state("");

  async function refreshTrash() {
    if (!selectedVault) return;
    trashLoading = true;
    try {
      trash = await listTrash(selectedVault);
    } catch (err) {
      trash = [];
      error = typeof err === "string" ? err : "Could not load the trash.";
    } finally {
      trashLoading = false;
    }
  }

  async function toggleTrash() {
    showTrash = !showTrash;
    if (showTrash) await refreshTrash();
  }

  async function restoreFromTrash(id: string) {
    if (restoringId) return;
    restoringId = id;
    error = "";
    try {
      await untrashItem(selectedVault, id);
      await refreshTrash();
      await refreshItems();
      selectItem(id);
    } catch (err) {
      error = typeof err === "string" ? err : "Could not restore the item.";
    } finally {
      restoringId = "";
    }
  }

  // --- Vault menu: share, delete (typed confirmation) ---
  let vaultMenu = $state(false);
  let deletingVault = $state(false);
  let deleteConfirmText = $state("");
  let deleteBusy = $state(false);
  let deleteError = $state("");
  const deletePhrase = $derived(`Delete ${currentVaultName}`);

  function openDeleteVault() {
    vaultMenu = false;
    deleteConfirmText = "";
    deleteError = "";
    deletingVault = true;
  }
  function cancelDeleteVault() {
    deletingVault = false;
    deleteConfirmText = "";
  }
  async function submitDeleteVault() {
    if (deleteBusy || !selectedVault || deleteConfirmText !== deletePhrase) return;
    deleteBusy = true;
    deleteError = "";
    try {
      await deleteVault(selectedVault);
      deletingVault = false;
      deleteConfirmText = "";
      selectedItem = "";
      view = "item";
      selectedVault = "";
      await loadVaults();
      if (vaults.length === 0) items = [];
      onVaultsChanged?.();
    } catch (err) {
      deleteError = typeof err === "string" ? err : "Could not delete the vault.";
    } finally {
      deleteBusy = false;
    }
  }

  // --- Sync summary for the status strip (fetched on events, never polled:
  // every sync request resets the idle auto-lock, so a poll would keep the
  // vault awake) ---
  let sync = $state<SyncSummary | null>(null);
  async function refreshSync() {
    const vid = selectedVault;
    if (!vid) return;
    try {
      const [st, peers] = await Promise.all([syncStatus(vid), listPeers()]);
      if (vid === selectedVault) sync = summarizeSync(st, peers);
    } catch {
      sync = null;
    }
  }

  // --- The lock countdown (coarse; DESIGN.md: no per-second ticking) ---
  let now = $state(Date.now());
  $effect(() => {
    const remaining = lockDeadline === null ? Infinity : lockDeadline - now;
    const step = remaining < 61_000 ? 1000 : 15_000;
    const t = setTimeout(() => (now = Date.now()), step);
    return () => clearTimeout(t);
  });
  const lockIn = $derived(lockDeadline === null ? null : Math.max(0, (lockDeadline - now) / 1000));

  // --- Navigation ---
  type ToolView = "generator" | "security" | "devices" | "dev" | "settings";
  const tools: { view: ToolView; label: string; icon: IconName }[] = [
    { view: "generator", label: "Generator", icon: "generator" },
    { view: "security", label: "Security", icon: "security" },
    { view: "devices", label: "Devices", icon: "devices" },
    { view: "dev", label: "Developer", icon: "dev" },
    { view: "settings", label: "Settings", icon: "settings" },
  ];
  function openTool(next: View) {
    view = next;
    selectedItem = "";
    editing = null;
  }

  const layout = $derived(view === "item" || view === "form" ? "vault" : "tool");
  // Which single screen the phone layout shows.
  const mobileScreen = $derived(
    view === "item" && !selectedItem ? "list" : "content",
  );
  const mobileTab = $derived(
    view === "item" || view === "form"
      ? "vault"
      : view === "generator" || view === "devices"
        ? view
        : "more",
  );

  function onItemKeydown(e: KeyboardEvent, index: number, count: number) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.max(0, Math.min(count - 1, index + (e.key === "ArrowDown" ? 1 : -1)));
      itemListEl?.querySelectorAll<HTMLButtonElement>("button.item-row")[next]?.focus();
    }
  }

  // Global shortcuts. Ctrl on Windows/Linux, Cmd on macOS.
  $effect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === "k" || k === "f") {
        e.preventDefault();
        if (view !== "item" && view !== "form") view = "item";
        selectedItem = selectedItem && window.innerWidth >= 720 ? selectedItem : "";
        queueMicrotask(() => searchEl?.focus());
      } else if (k === "n" && !e.shiftKey) {
        e.preventDefault();
        startAdd();
      } else if (k === "l") {
        e.preventDefault();
        onLock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  // Close the vault menu on any outside click.
  $effect(() => {
    if (!vaultMenu) return;
    const close = () => (vaultMenu = false);
    const t = setTimeout(() => window.addEventListener("click", close, { once: true }));
    return () => {
      clearTimeout(t);
      window.removeEventListener("click", close);
    };
  });

  $effect(() => {
    loadVaults();
  });
</script>

{#snippet newVaultForm()}
  <form class="new-vault" onsubmit={(e) => { e.preventDefault(); submitNewVault(); }}>
    <!-- svelte-ignore a11y_autofocus -->
    <input
      type="text"
      placeholder="Vault name"
      aria-label="New vault name"
      bind:value={newVaultName}
      autocomplete="off"
      autofocus
      disabled={vaultBusy}
      onkeydown={(e) => { if (e.key === "Escape") creatingVault = false; }}
    />
    <div class="toolbar">
      <button class="btn btn-sm btn-primary" type="submit" disabled={vaultBusy || !newVaultName.trim()}>
        {vaultBusy ? "Creating…" : "Create"}
      </button>
      <button class="btn btn-sm btn-quiet" type="button" onclick={() => (creatingVault = false)} disabled={vaultBusy}>
        Cancel
      </button>
    </div>
  </form>
{/snippet}

{#snippet statusLines(compact: boolean)}
  {#if session.agent_session}
    <button class="st-line" onclick={() => openTool("dev")} title="An AI agent is connected. Changes and approvals ask for your master password.">
      <i class="dot accent"></i><span><b>AI agent connected</b></span>
    </button>
  {/if}
  {#if session.agent_fill_secs}
    <button class="st-line" onclick={() => openTool("dev")}>
      <i class="dot warn"></i><span>Agent autofill is armed</span>
    </button>
  {/if}
  {#if session.pairing_mode_secs}
    <button class="st-line" onclick={() => openTool("devices")}>
      <i class="dot accent"></i><span>Pairing mode is on</span>
    </button>
  {/if}
  {#if sync && sync.tone !== "idle"}
    <button class="st-line" onclick={() => openTool("devices")} title={`${currentVaultName}: ${sync.headline}`}>
      <i class="dot {sync.tone === 'ok' ? 'ok' : sync.tone === 'danger' ? 'danger' : 'warn'}"></i>
      <span>{sync.headline}</span>
    </button>
  {/if}
  {#if !compact}
    <div class="st-line static">
      <Icon name="lock" size={13} />
      <span>{lockIn === null ? "Auto-lock is off" : `Locks in ${formatCountdown(lockIn)}`}</span>
    </div>
  {/if}
{/snippet}

{#if session.agent_session}
  <div class="agent-banner" role="status">
    <Icon name="agent" size={15} /> An AI agent is connected. Changes ask for your master password.
  </div>
{/if}

<div class="shell" data-layout={layout} data-mobile={mobileScreen}>
  <!-- ============================== Sidebar ============================== -->
  <nav class="sidebar" aria-label="LocalPass">
    <div class="sb-top">
      <span class="lockup">
        <Mark size={22} />
        <span class="word rail-hide">LocalPass</span>
      </span>
      <button class="icon-btn rail-hide" onclick={onLock} aria-label="Lock" title="Lock (Ctrl+L)">
        <Icon name="lock" size={17} />
      </button>
    </div>

    <div class="sb-scroll">
      <div class="sb-label rail-hide">
        <span>Vaults</span>
        <button
          class="icon-btn sm"
          onclick={() => { creatingVault = !creatingVault; newVaultName = ""; }}
          aria-expanded={creatingVault}
          aria-label="New vault"
          title="New vault"
        >
          <Icon name="plus" size={14} />
        </button>
      </div>
      {#if creatingVault}<div class="rail-hide">{@render newVaultForm()}</div>{/if}
      <ul class="nav" aria-label="Vaults">
        {#each vaults as v (v.id)}
          <li>
            <button
              class="nav-row"
              aria-current={v.id === selectedVault && layout === "vault" ? "page" : undefined}
              class:in-vault={v.id === selectedVault}
              onclick={() => selectVault(v.id)}
              title={v.name}
            >
              <span class="avatar" aria-hidden="true">{v.name.slice(0, 1).toUpperCase()}</span>
              <span class="ellipsis rail-hide">{v.name}</span>
            </button>
          </li>
        {/each}
      </ul>

      <ul class="nav tools" aria-label="Tools">
        {#each tools as t (t.view)}
          <li>
            <button
              class="nav-row"
              aria-current={view === t.view ? "page" : undefined}
              onclick={() => openTool(t.view)}
              title={t.label}
            >
              <Icon name={t.icon} size={17} />
              <span class="ellipsis rail-hide">{t.label}</span>
              {#if t.view === "settings" && $updates.available}
                <span class="nav-badge rail-hide">Update</span>
                <i class="dot accent rail-only" aria-label="Update available"></i>
              {/if}
            </button>
          </li>
        {/each}
      </ul>
    </div>

    <div class="status-strip rail-hide" aria-label="Status">
      {@render statusLines(false)}
    </div>
    <div class="rail-foot rail-only">
      {#if session.agent_session}
        <span class="rail-agent" title="AI agent connected"><Icon name="agent" size={17} /></span>
      {/if}
      <button class="icon-btn" onclick={onLock} aria-label="Lock" title="Lock (Ctrl+L)">
        <Icon name="lock" size={17} />
      </button>
    </div>
  </nav>

  <!-- ============================== Item list ============================== -->
  <section class="list-pane" aria-label="Items">
    <div class="lp-head">
      <!-- Phone: the vault picker and lock live here (no sidebar). -->
      <div class="lp-mobile">
        <span class="lockup"><Mark size={22} /></span>
        <label class="sr-only" for="m-vault-select">Vault</label>
        <div class="vault-select">
          <select
            id="m-vault-select"
            value={selectedVault}
            onchange={(e) => {
              const v = e.currentTarget.value;
              if (v === NEW_VAULT) {
                e.currentTarget.value = selectedVault;
                creatingVault = true;
                newVaultName = "";
              } else {
                selectVault(v);
              }
            }}
          >
            {#each vaults as v (v.id)}
              <option value={v.id}>{v.name}</option>
            {/each}
            <option value={NEW_VAULT}>New vault…</option>
          </select>
          <Icon name="chevron-down" size={14} />
        </div>
        <button class="icon-btn add" onclick={startAdd} disabled={!selectedVault} aria-label="New item">
          <Icon name="plus" size={20} />
        </button>
        <button class="icon-btn" onclick={onLock} aria-label="Lock"><Icon name="lock" size={18} /></button>
      </div>
      {#if creatingVault}<div class="mobile-only">{@render newVaultForm()}</div>{/if}

      <div class="lp-title desktop-only">
        <h2 class="ellipsis" title={currentVaultName}>{currentVaultName || "No vault"}</h2>
        <button class="icon-btn sm add" onclick={startAdd} disabled={!selectedVault} aria-label="New item" title="New item (Ctrl+N)">
          <Icon name="plus" size={16} />
        </button>
        <div class="menu-anchor">
          <button
            class="icon-btn sm"
            aria-label="Vault actions"
            aria-haspopup="menu"
            aria-expanded={vaultMenu}
            onclick={(e) => { e.stopPropagation(); vaultMenu = !vaultMenu; }}
            disabled={!selectedVault}
          >
            <Icon name="more" size={16} />
          </button>
          {#if vaultMenu}
            <div class="menu" role="menu" style="right:0;top:30px">
              <button role="menuitem" onclick={() => { vaultMenu = false; openTool("devices"); }}>
                <Icon name="devices" size={15} /> Sync or share…
              </button>
              <hr />
              <button role="menuitem" class="danger" onclick={openDeleteVault}>
                <Icon name="trash" size={15} /> Delete vault…
              </button>
            </div>
          {/if}
        </div>
      </div>

      <div class="search">
        <Icon name="search" size={15} />
        <label for="item-search" class="sr-only">Search items</label>
        <input
          id="item-search"
          type="search"
          bind:this={searchEl}
          placeholder={scope === "all" ? "Search all vaults" : `Search ${currentVaultName || "items"}`}
          bind:value={query}
          oninput={onSearchInput}
          onkeydown={(e) => {
            if (e.key === "Escape" && query) { e.preventDefault(); clearSearch(); }
            if (e.key === "ArrowDown") {
              e.preventDefault();
              itemListEl?.querySelector<HTMLButtonElement>("button.item-row")?.focus();
            }
          }}
          autocomplete="off"
          spellcheck="false"
        />
        {#if query}
          <button class="icon-btn sm" onclick={clearSearch} aria-label="Clear search"><Icon name="x" size={14} /></button>
        {:else}
          <kbd class="kbd desktop-only" aria-hidden="true">Ctrl K</kbd>
        {/if}
      </div>
      <div class="lp-sub">
        {#if vaults.length > 1}
          <div class="seg scope" role="group" aria-label="Search in">
            <button aria-pressed={scope === "vault"} onclick={() => setScope("vault")}>This vault</button>
            <button aria-pressed={scope === "all"} onclick={() => setScope("all")}>All vaults</button>
          </div>
        {/if}
        <span class="faint num">
          {scope === "all" && query.trim() ? allHits.length : items.length}
          {(scope === "all" && query.trim() ? allHits.length : items.length) === 1 ? "item" : "items"}
        </span>
      </div>
    </div>

    {#if error}
      <div class="error" role="alert" style="margin:8px 12px">{error}</div>
    {/if}

    <div class="lp-scroll">
      {#if loadingItems && items.length === 0 && allHits.length === 0}
        <p class="empty">Loading…</p>
      {:else if scope === "all" && query.trim()}
        {#if allHits.length === 0}
          <p class="empty">Nothing matches “{query.trim()}” in any vault.</p>
        {:else}
          <ul class="rows" bind:this={itemListEl} role="listbox" aria-label="Search results">
            {#each allHits as h, i (h.vault + h.item.id)}
              <li role="presentation">
                <button
                  class="item-row"
                  role="option"
                  aria-selected={h.item.id === selectedItem}
                  onclick={() => openHit(h.vault, h.item.id)}
                  onkeydown={(e) => onItemKeydown(e, i, allHits.length)}
                >
                  <Icon name={typeIcon(h.item.type_str)} size={18} />
                  <span class="ir-main">
                    <span class="ir-title" title={h.item.title}>{h.item.title}</span>
                    <span class="ir-sub">{vaultNames.get(h.vault) ?? ""} · {typeLabel(h.item.type_str)}</span>
                  </span>
                  <time class="ir-age" datetime={isoTimestamp(h.item.updated_at)}>{formatAge(h.item.updated_at)}</time>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      {:else if scope === "all"}
        <p class="empty">Type to search every vault.</p>
      {:else if items.length === 0}
        <div class="empty">
          {#if query}
            <p>Nothing matches “{query.trim()}”.</p>
            {#if vaults.length > 1}
              <button class="btn btn-sm" style="margin-top:10px" onclick={() => setScope("all")}>Search all vaults</button>
            {/if}
          {:else}
            <Icon name="vault" size={28} />
            <p>This vault is empty.</p>
            <button class="btn btn-sm btn-primary" style="margin-top:12px" onclick={startAdd} disabled={!selectedVault}>
              Add the first item
            </button>
          {/if}
        </div>
      {:else}
        <ul class="rows" bind:this={itemListEl} role="listbox" aria-label="Items">
          {#each items as it, i (it.id)}
            <li role="presentation">
              <button
                class="item-row"
                role="option"
                aria-selected={it.id === selectedItem}
                onclick={() => selectItem(it.id)}
                onkeydown={(e) => onItemKeydown(e, i, items.length)}
              >
                <Icon name={typeIcon(it.type_str)} size={18} />
                <span class="ir-main">
                  <span class="ir-title" title={it.title}>{it.title}</span>
                  <span class="ir-sub">{typeLabel(it.type_str)}{it.tags.length ? ` · ${it.tags.join(", ")}` : ""}</span>
                </span>
                <time class="ir-age" datetime={isoTimestamp(it.updated_at)} title={`Updated ${formatTimestamp(it.updated_at)}`}>
                  {formatAge(it.updated_at)}
                </time>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <!-- Trash: deleted items, recoverable for 30 days (PRD §4.10). Collapsed by
         default; loads (decrypts titles) only when opened. -->
    {#if selectedVault && scope === "vault"}
      <div class="lp-foot">
        <button class="trash-toggle" aria-expanded={showTrash} onclick={toggleTrash} title="Deleted items stay here for 30 days">
          <Icon name="trash" size={15} />
          <span>Trash</span>
          {#if showTrash && !trashLoading}<span class="faint num">{trash.length}</span>{/if}
          <span class="chev" class:open={showTrash}><Icon name="chevron" size={13} /></span>
        </button>
        {#if showTrash}
          <div class="trash-list">
            {#if trashLoading}
              <p class="empty">Loading…</p>
            {:else if trash.length === 0}
              <p class="empty">Nothing here. Deleted items stay for 30 days.</p>
            {:else}
              <ul class="plain-list" aria-label="Deleted items">
                {#each trash as t (t.id)}
                  <li>
                    <span class="ir-main">
                      <span class="ir-title">{t.title}</span>
                      <span class="ir-sub">
                        <time datetime={isoTimestamp(t.deleted_at)} title={`Deleted ${formatTimestamp(t.deleted_at)}`}>
                          Deleted {formatAge(t.deleted_at)}
                        </time>
                      </span>
                    </span>
                    <button class="btn btn-sm" onclick={() => restoreFromTrash(t.id)} disabled={restoringId !== ""}>
                      {restoringId === t.id ? "Restoring…" : "Restore"}
                    </button>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </section>

  <!-- ============================== Content ============================== -->
  <main class="content-pane" aria-label="Details">
    {#if view === "item" || view === "form"}
      <div class="mobile-bar">
        <button class="btn btn-quiet" onclick={() => { selectedItem = ""; editing = null; view = "item"; }}>
          <Icon name="back" size={18} /> {currentVaultName || "Items"}
        </button>
      </div>
    {/if}

    {#if view === "generator"}
      <Generator />
    {:else if view === "security"}
      <Security vault={selectedVault} vaultName={currentVaultName} />
    {:else if view === "dev"}
      <Dev {vaults} {selectedVault} agentConnected={!!session.agent_session} sshIdentities={session.ssh_identity_count ?? 0} />
    {:else if view === "help"}
      <Help />
    {:else if view === "settings"}
      <Settings onOpenHelp={() => openTool("help")} />
    {:else if view === "devices"}
      <Devices
        {vaults}
        {selectedVault}
        onVaultsChanged={async () => { await loadVaults(); onVaultsChanged?.(); }}
        onSyncChanged={refreshSync}
      />
    {:else if view === "more"}
      <div class="page more">
        <div class="page-head"><h2>More</h2></div>
        <ul class="plain-list more-list">
          {#each [{ v: "security", l: "Security", i: "security" }, { v: "dev", l: "Developer", i: "dev" }, { v: "settings", l: "Settings", i: "settings" }, { v: "help", l: "Help", i: "help" }] as m (m.v)}
            <li>
              <button class="more-row" onclick={() => openTool(m.v as View)}>
                <Icon name={m.i as IconName} size={20} />
                <span>{m.l}</span>
                {#if m.v === "settings" && $updates.available}<span class="badge accent">Update</span>{/if}
                <Icon name="chevron" size={16} />
              </button>
            </li>
          {/each}
        </ul>
        <div class="section status-more" aria-label="Status">
          {@render statusLines(false)}
        </div>
      </div>
    {:else if view === "form" && selectedVault}
      {#key editing?.id ?? "new"}
        <ItemForm vault={selectedVault} existing={editing} onSaved={onFormSaved} onCancel={onFormCancel} />
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
      <div class="placeholder desktop-only">
        <Mark size={44} variant="inverse" />
        <p>Select an item, or press <kbd class="kbd">Ctrl K</kbd> to search.</p>
        <p class="faint">Values stay masked until you reveal or copy them.</p>
      </div>
    {/if}
  </main>
</div>

<!-- Phone: the bottom tab bar (hidden on desktop). -->
<nav class="tabbar mobile-only" aria-label="Sections">
  <button aria-current={mobileTab === "vault" ? "page" : undefined} onclick={() => { view = "item"; selectedItem = ""; }}>
    <Icon name="vault" size={22} /><span>Vault</span>
  </button>
  <button aria-current={mobileTab === "generator" ? "page" : undefined} onclick={() => openTool("generator")}>
    <Icon name="generator" size={22} /><span>Generator</span>
  </button>
  <button aria-current={mobileTab === "devices" ? "page" : undefined} onclick={() => openTool("devices")}>
    <Icon name="devices" size={22} /><span>Devices</span>
  </button>
  <button aria-current={mobileTab === "more" ? "page" : undefined} onclick={() => openTool("more")}>
    <Icon name="more" size={22} /><span>More</span>
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
    <div
      class="modal-card"
      role="dialog"
      tabindex="-1"
      aria-modal="true"
      aria-labelledby="del-vault-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape") cancelDeleteVault(); }}
    >
      <h2 id="del-vault-title" class="modal-title">Delete “{currentVaultName}”?</h2>
      <p class="muted">
        The vault and everything in it disappear from this app. This can’t be
        undone from LocalPass.
      </p>
      <p class="muted">Type <code class="confirm-phrase">{deletePhrase}</code> to confirm.</p>
      <form onsubmit={(e) => { e.preventDefault(); submitDeleteVault(); }}>
        <label class="sr-only" for="del-vault-confirm">Confirmation phrase</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          id="del-vault-confirm"
          type="text"
          style="margin-top:12px"
          bind:value={deleteConfirmText}
          placeholder={deletePhrase}
          autocomplete="off"
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
          autofocus
          disabled={deleteBusy}
        />
        {#if deleteError}<p class="error" role="alert">{deleteError}</p>{/if}
        <div class="modal-actions">
          <button type="button" class="btn" onclick={cancelDeleteVault} disabled={deleteBusy}>Cancel</button>
          <button type="submit" class="btn btn-danger" disabled={deleteBusy || deleteConfirmText !== deletePhrase}>
            {deleteBusy ? "Deleting…" : "Delete vault"}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  /* ---- sidebar ---- */
  .sb-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 12px 10px 8px 14px;
    min-height: 52px;
  }
  .lockup {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    min-width: 0;
  }
  .word {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 14.5px;
    letter-spacing: -0.01em;
  }
  .sb-scroll {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    padding-bottom: 8px;
  }
  .sb-label {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 8px 2px 16px;
    font-size: 12px;
    color: var(--text-faint);
  }
  .new-vault {
    padding: 4px 10px 8px;
    display: grid;
    gap: 6px;
  }
  .nav {
    list-style: none;
    margin: 0;
    padding: 2px 8px;
  }
  .nav.tools {
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border);
  }
  .nav-row {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    height: var(--row-h);
    padding: 0 8px;
    border: 0;
    border-radius: var(--radius);
    background: none;
    color: var(--text);
    text-align: left;
    font-size: 13.5px;
    cursor: pointer;
  }
  .nav-row:hover {
    background: var(--bg-hover);
  }
  .nav-row :global(.icon) {
    color: var(--text-muted);
  }
  .nav-row[aria-current="page"] {
    background: var(--accent-tint);
    font-weight: 600;
  }
  .nav-row[aria-current="page"] :global(.icon) {
    color: var(--accent);
  }
  .avatar {
    flex: none;
    display: grid;
    place-items: center;
    width: 20px;
    height: 20px;
    border-radius: 5px;
    background: var(--bg-active);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 700;
  }
  .nav-row[aria-current="page"] .avatar {
    background: var(--accent-fill);
    color: var(--on-accent);
  }
  .nav-badge {
    margin-left: auto;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--accent);
  }
  .status-strip {
    border-top: 1px solid var(--border);
    padding: 8px 8px 10px;
    display: grid;
    gap: 1px;
  }
  .st-line {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    width: 100%;
    min-height: 26px;
    padding: 3px 8px;
    border: 0;
    border-radius: 5px;
    background: none;
    color: var(--text-muted);
    font-size: 12px;
    text-align: left;
    cursor: pointer;
  }
  .st-line:not(.static):hover {
    background: var(--bg-hover);
    color: var(--text);
  }
  .st-line.static {
    cursor: default;
  }
  .st-line span {
    min-width: 0;
    overflow-wrap: anywhere;
    line-height: 1.35;
  }
  .st-line .dot,
  .st-line :global(.icon) {
    align-self: flex-start;
    margin-top: 4px;
  }
  .st-line b {
    color: var(--text);
    font-weight: 600;
  }
  .st-line :global(.icon) {
    color: var(--text-faint);
  }
  .rail-only {
    display: none !important;
  }
  .rail-foot {
    border-top: 1px solid var(--border);
    padding: 8px;
    display: grid;
    justify-items: center;
    gap: 6px;
  }
  .rail-agent {
    color: var(--accent);
  }

  /* Compact desktop: icon rail. */
  @media (max-width: 999px) and (min-width: 720px) {
    .sb-top {
      justify-content: center;
      padding: 14px 0 10px;
    }
    .nav {
      padding: 2px 8px;
    }
    .nav-row {
      justify-content: center;
      padding: 0;
      height: 36px;
      position: relative;
    }
    .nav-row .dot {
      position: absolute;
      top: 6px;
      right: 6px;
    }
    .dot.rail-only {
      display: inline-block !important;
    }
    .rail-foot.rail-only {
      display: grid !important;
    }
  }

  /* ---- list pane ---- */
  .lp-head {
    padding: 12px 12px 6px;
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 8px;
  }
  .add {
    color: var(--accent);
  }
  .lp-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding-left: 4px;
    min-height: 28px;
  }
  .lp-title h2 {
    flex: 1;
    font-size: 15px;
  }
  .menu-anchor {
    position: relative;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 6px;
    height: var(--control-h);
    padding: 0 4px 0 10px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    background: var(--bg-content);
    color: var(--text-faint);
  }
  .search:focus-within {
    outline: 2px solid var(--focus);
    outline-offset: 0;
    border-color: transparent;
  }
  .search input {
    flex: 1;
    height: 100%;
    border: 0;
    padding: 0;
    background: transparent;
    outline: none;
  }
  .search input::-webkit-search-cancel-button {
    display: none;
  }
  .search .kbd {
    margin-right: 4px;
  }
  .lp-sub {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-left: 4px;
    font-size: 12px;
    min-height: 30px;
  }
  .scope button {
    height: 24px;
    padding: 0 9px;
    font-size: 12px;
  }
  .lp-scroll {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
  }
  .rows {
    list-style: none;
    margin: 0;
    padding: 2px 6px 8px;
  }
  .item-row {
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    align-items: center;
    gap: 10px;
    width: 100%;
    min-height: 46px;
    padding: 6px 10px;
    border: 0;
    border-radius: var(--radius);
    background: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .item-row:hover {
    background: var(--bg-hover);
  }
  .item-row[aria-selected="true"] {
    background: var(--accent-tint);
  }
  .item-row :global(.icon) {
    color: var(--text-muted);
  }
  .item-row[aria-selected="true"] :global(.icon) {
    color: var(--accent);
  }
  .ir-main {
    display: grid;
    min-width: 0;
    flex: 1;
  }
  .ir-title {
    font-weight: 600;
    font-size: 13.5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ir-sub {
    font-size: 12px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ir-age {
    font-size: 11.5px;
    color: var(--text-faint);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .lp-foot {
    border-top: 1px solid var(--border);
    padding: 4px 6px;
    max-height: 45%;
    overflow-y: auto;
  }
  .trash-toggle {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    height: 32px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius);
    background: none;
    color: var(--text-muted);
    font-size: 13px;
    cursor: pointer;
  }
  .trash-toggle:hover {
    background: var(--bg-hover);
    color: var(--text);
  }
  .chev {
    margin-left: auto;
    display: flex;
    transition: transform var(--dur) var(--ease-out);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .trash-list {
    padding: 0 10px 6px;
  }
  .trash-list .empty {
    padding: 10px 0;
  }

  /* ---- content ---- */
  .placeholder {
    height: 100%;
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 10px;
    color: var(--text-muted);
    text-align: center;
    padding: 24px;
  }
  .placeholder :global(.mark) {
    opacity: 0.5;
    margin-bottom: 6px;
  }

  /* ---- phone ---- */
  .lp-mobile {
    display: none;
    align-items: center;
    gap: 4px;
  }
  .lp-mobile .lockup {
    margin-right: 6px;
  }
  .vault-select {
    position: relative;
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
  }
  .vault-select select {
    appearance: none;
    border: 0;
    background: transparent;
    font-family: var(--font-display);
    font-size: 18px;
    font-weight: 600;
    padding: 0 24px 0 0;
    height: 40px;
    text-overflow: ellipsis;
  }
  .vault-select :global(.icon) {
    position: absolute;
    right: 4px;
    pointer-events: none;
    color: var(--text-muted);
  }
  .mobile-bar {
    display: none;
    align-items: center;
    padding: 6px 6px 0;
  }
  .mobile-bar .btn {
    padding-left: 6px;
    color: var(--text-muted);
  }
  .agent-banner {
    display: none;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    font-size: 13px;
    background: var(--accent-tint);
    color: var(--text);
  }
  .more-list {
    margin-top: -6px;
  }
  .more-row {
    display: flex;
    align-items: center;
    gap: 14px;
    width: 100%;
    min-height: 52px;
    padding: 0 4px;
    border: 0;
    background: none;
    color: var(--text);
    font-size: 15px;
    text-align: left;
    cursor: pointer;
  }
  .more-row > span:not(.badge) {
    flex: 1;
  }
  .more-row :global(.icon) {
    color: var(--text-muted);
  }
  .status-more {
    display: grid;
    gap: 4px;
  }
  @media (max-width: 719px) {
    .lp-mobile,
    .mobile-bar,
    .agent-banner {
      display: flex;
    }
    .lp-head {
      padding-top: 6px;
    }
    .item-row {
      min-height: 56px;
    }
  }
</style>
