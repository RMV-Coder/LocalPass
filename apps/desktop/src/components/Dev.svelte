<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The "Dev" tab: how to drive this vault from a terminal (CLI) and from an AI
  coding agent (MCP), the arm control for agent-triggered browser autofill, plus
  a viewer for the local audit log so you can see what those surfaces actually
  did.

  SECRET BOUNDARY: nothing here reveals a value. The CLI/MCP sections are static
  reference text. The audit viewer shows METADATA ONLY — the daemon's audit
  records carry ids, kind labels, timestamps, and caller attribution, and the
  log itself stores no names at all (it is plaintext on disk, while names are
  ciphertext everywhere else). Item ids are resolved to titles HERE, at display
  time, against the unlocked session's own item lists; an unresolvable id falls
  back to a short id. No title is ever sent toward the log.

  The agent-fill control is likewise value-free: it sends item IDS one way and
  reads a remaining-seconds count back (agent-fill.md §7). The credential it
  authorises never passes through this window — the daemon releases it to the
  browser extension over the native-messaging path, and only there.
-->
<script lang="ts">
  import { untrack } from "svelte";
  import {
    listItems,
    auditList,
    devEnv,
    setAgentFillMode,
    agentFillSecs,
  } from "../lib/api";
  import type { AgentFillTargetView, AuditRecordView, VaultView } from "../lib/types";
  import {
    formatArmCountdown,
    loginTargets,
    pruneSelection,
    scopeSummary,
  } from "../lib/agentfill";
  import {
    sourceLabel,
    isAlarming,
    titleIndex,
    vaultIndex,
    resolveItemTitle,
    isResolved,
    callerLabel,
    operationLabel,
    formatAuditTime,
    shortId,
  } from "../lib/audit";
  import { copyToClipboard } from "../lib/clipboard";
  import { toast } from "../lib/toast";
  import { lastSeenBySource } from "../lib/activity";
  import { formatAgo } from "../lib/format";
  import Icon from "./Icon.svelte";
  import CopyRow from "./CopyRow.svelte";

  interface Props {
    /** Every vault the unlocked session can see — used to resolve audit ids to
     *  titles at display time. */
    vaults: VaultView[];
    /** The currently selected vault id, used in the example commands so they
     *  are copy-and-run rather than copy-and-edit. */
    selectedVault?: string;
    /** An AI agent session is open right now (from the passive status). */
    agentConnected?: boolean;
    /** SSH identities the built-in agent serves right now. */
    sshIdentities?: number;
  }
  let { vaults, selectedVault = "", agentConnected = false, sshIdentities = 0 }: Props = $props();

  // --- Environment (paths quoted by the guides) ---
  let profile = $state("");
  let localpassPath = $state<string | null>(null);
  /** The command an MCP client should launch. Falls back to the bare name when
   *  no executable was found, with a visible caveat below the snippet. */
  const cliCommand = $derived(localpassPath ?? "localpass");

  // The selected vault's NAME is what a CLI `--vault` flag wants (it accepts a
  // name or an id); fall back to `personal`, the CLI's own default.
  const vaultName = $derived(
    vaults.find((v) => v.id === selectedVault)?.name ?? "personal",
  );

  // --- Audit viewer state ---
  /** How many records to request. The backend clamps to the daemon's own cap. */
  let limit = $state(100);
  const LIMITS = [50, 100, 250, 1000];
  let records = $state<AuditRecordView[]>([]);
  let loading = $state(false);
  let error = $state("");
  let loadedAt = $state(0);
  /** id → title, built from the vaults this session can see. */
  let titles = $state<Map<string, string>>(new Map());
  const vaultNames = $derived(vaultIndex(vaults));

  /** Fetch the item lists of every visible vault and index id → title.
   *
   *  This is the whole id-resolution strategy: the log stores ids, the unlocked
   *  session can decrypt titles, and the join happens in the UI. `list_items`
   *  returns summaries only — no field values ever enter this index. */
  async function loadTitles() {
    const lists = await Promise.all(
      vaults.map((v) => listItems(v.id).catch(() => [])),
    );
    titles = titleIndex(lists);
  }

  async function refresh() {
    if (loading) return;
    loading = true;
    error = "";
    try {
      // Titles first, so a row never flashes an id it could have resolved.
      await loadTitles();
      records = await auditList(limit);
      loadedAt = Date.now();
    } catch (err) {
      records = [];
      error = typeof err === "string" ? err : "Could not read the activity log.";
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    devEnv()
      .then((e) => {
        profile = e.profile;
        localpassPath = e.localpass_path;
      })
      .catch(() => {
        /* Paths are a nicety; the guides still read correctly without them. */
      });
    // Load once on mount. `refresh()` reads `loading` (and `vaults`)
    // synchronously and writes `loading` again when it settles, so calling it
    // tracked made this effect re-run itself forever — a continuous
    // list_items + audit_list loop that, with a fast bridge, starved the UI
    // thread. The Refresh button covers manual reloads.
    untrack(() => {
      refresh();
      void refreshArm();
    });
  });

  // --- Copy-able snippets ---
  const injectExample = $derived(
    `localpass run --no-input -e "DATABASE_URL=localpass://${vaultName}/Prod DB/password" -- npm run dev`,
  );
  const rotateExample = $derived(
    `localpass generate --length 32 | localpass item edit "Prod DB" --vault ${vaultName} --password -`,
  );
  const mcpSnippet = $derived(
    JSON.stringify(
      {
        mcpServers: {
          localpass: {
            command: cliCommand,
            args: ["mcp", ...(profile ? ["--profile", profile] : [])],
          },
        },
      },
      null,
      2,
    ),
  );

  // --- What is using the vault (derived from the audit log) ---
  const lastSeen = $derived(lastSeenBySource(records));
  function lastSeenText(source: string): string {
    const t = lastSeen.get(source);
    if (!records.length) return loading ? "Reading activity…" : "No activity read yet";
    return t ? `Last used ${formatAgo(t)}` : `No use in the last ${records.length} records`;
  }
  /** Used in the last 10 minutes. */
  function recentlyActive(source: string): boolean {
    const t = lastSeen.get(source);
    return t !== undefined && Date.now() - t < 10 * 60_000;
  }

  // --- Activity filters ---
  const SOURCES = [
    { id: "all", label: "All" },
    { id: "gui", label: "App" },
    { id: "cli", label: "CLI" },
    { id: "mcp", label: "MCP" },
    { id: "native_host", label: "Browser" },
    { id: "ssh_agent", label: "SSH" },
  ];
  let sourceFilter = $state("all");
  let logQuery = $state("");
  const visible = $derived(
    records.filter((r) => {
      if (sourceFilter !== "all" && (r.source ?? "unknown") !== sourceFilter) return false;
      const q = logQuery.trim().toLowerCase();
      if (!q) return true;
      const hay = [
        operationLabel(r),
        sourceLabel(r.source),
        callerLabel(r),
        resolveItemTitle(r.item_id, titles),
        r.vault_id ? (vaultNames.get(r.vault_id) ?? "") : "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    }),
  );

  async function copyPlain(text: string): Promise<"native" | "webview" | null> {
    return (await copyToClipboard(text)) ? "webview" : null;
  }

  async function copy(text: string, what: string) {
    const ok = await copyToClipboard(text);
    toast(ok ? `${what} copied` : "Could not copy", ok ? "ok" : "error");
  }

  /** The five tools `localpass mcp` exposes (docs/specs/mcp-server.md §5). */
  const MCP_TOOLS: { name: string; blurb: string }[] = [
    { name: "list_vaults", blurb: "Vault ids and names. No secret." },
    {
      name: "list_items",
      blurb: "Item titles and FIELD NAMES, with every secret value masked.",
    },
    { name: "get_item", blurb: "One item, masked. There is deliberately no reveal argument." },
    {
      name: "run_with_secrets",
      blurb:
        "Runs a command with secrets injected into its environment, then scrubs every injected value out of the captured output.",
    },
    {
      name: "totp_code",
      blurb:
        "A six-digit code — a short-lived derivative, never the seed. The one value that may cross.",
    },
  ];

  // --- Agent-fill arm window (agent-fill.md §7) ---
  // A time-boxed (3-minute) window that must be ON before an AI agent can have
  // the browser extension fill a login WITHOUT the user's click, scoped to the
  // items picked below and no others. Modelled on pairing mode (Devices.svelte):
  // the daemon owns the deadline and the scope and enforces both server-side; we
  // fetch the remaining seconds on mount and after each toggle, then tick them
  // down locally so the control flips to OFF exactly when the window lapses —
  // with no click from the user.

  /** The vault the picker lists logins from, and that ids are resolved in.
   *  Falls back to the first visible vault when no row is selected. */
  const fillVaultId = $derived(selectedVault || vaults[0]?.id || "");
  const fillVaultName = $derived(
    vaults.find((v) => v.id === fillVaultId)?.name ?? "",
  );

  /** The logins on offer — titles and ids only, never a value. */
  let targets = $state<AgentFillTargetView[]>([]);
  let targetsError = $state("");
  /** The checked ids (raw checkbox state; see `scope` for the usable form). */
  let selected = $state<string[]>([]);
  /** The checked ids that still exist in the current list — what we actually
   *  arm with. Derived rather than written back, so switching vaults can never
   *  arm an item the user cannot see. */
  const scope = $derived(pruneSelection(selected, targets));

  let armSecs = $state<number | null>(null);
  let armBusy = $state(false);
  let armError = $state("");
  const armed = $derived(armSecs !== null && armSecs > 0);
  /** What the OPEN window covers, snapshotted when this window armed it. The
   *  daemon reports the remaining time but not the scope, so a window armed
   *  elsewhere (or before this tab mounted) shows the countdown with no list —
   *  better than inventing one. */
  let armedScope = $state("");

  /** One announcement per state change for screen readers. The visible
   *  countdown is deliberately NOT a live region: it would speak every second. */
  const armAnnouncement = $derived(
    armed
      ? `Agent fill armed${armedScope ? `, covering ${armedScope}` : ""}.`
      : "Agent fill is off.",
  );

  /** Reload the pickable logins whenever the vault in play changes. */
  $effect(() => {
    const vid = fillVaultId;
    if (!vid) {
      targets = [];
      return;
    }
    listItems(vid)
      .then((list) => {
        targets = loginTargets(list);
        targetsError = "";
      })
      .catch(() => {
        targets = [];
        targetsError = "Could not read this vault's logins.";
      });
  });

  async function refreshArm() {
    try {
      armSecs = await agentFillSecs();
      if (armSecs === null) armedScope = "";
    } catch (err) {
      armError = typeof err === "string" ? err : "Could not read the agent-fill window.";
    }
  }

  async function arm() {
    if (armBusy || scope.length === 0) return;
    armBusy = true;
    armError = "";
    const covering = scopeSummary(scope, targets);
    try {
      await setAgentFillMode(true, scope, fillVaultId || null);
      armedScope = covering;
      await refreshArm();
      // The arm is an audit record; show it without making the user hit Refresh.
      await refresh();
    } catch (err) {
      armedScope = "";
      armError = typeof err === "string" ? err : "Could not arm agent fill.";
    } finally {
      armBusy = false;
    }
  }

  async function disarm() {
    if (armBusy) return;
    armBusy = true;
    armError = "";
    try {
      await setAgentFillMode(false, [], null);
      armedScope = "";
      await refreshArm();
      await refresh();
    } catch (err) {
      armError = typeof err === "string" ? err : "Could not turn off agent fill.";
    } finally {
      armBusy = false;
    }
  }

  // Local 1-second countdown. At zero it re-syncs with the daemon (the authority
  // on expiry), so a window that lapses on its own flips this control to OFF
  // with no interaction at all.
  $effect(() => {
    const id = setInterval(() => {
      if (armSecs === null) return;
      if (armSecs <= 1) {
        armSecs = null;
        armedScope = "";
        void refreshArm();
      } else {
        armSecs -= 1;
      }
    }, 1000);
    return () => clearInterval(id);
  });
</script>

<div class="page dev">
  <div class="page-head">
    <div>
      <h2>Developer</h2>
      <p class="sub">The CLI, AI agents and the browser extension use this vault through the same local service.</p>
    </div>
    <div class="actions">
      <button class="btn btn-sm" type="button" onclick={refresh} disabled={loading}>
        <Icon name="refresh" size={14} /> {loading ? "Loading…" : "Refresh"}
      </button>
    </div>
  </div>

  <!-- ================= What is using the vault ================= -->
  <section class="surfaces" aria-label="What is using this vault">
    <div class="set-row">
      <div class="surf">
        <span class="surf-ico"><Icon name="agent" size={18} /></span>
        <span>
          <span class="t">AI agents (MCP)</span>
          <span class="d">{lastSeenText("mcp")}</span>
        </span>
      </div>
      {#if agentConnected}
        <span class="badge accent"><i class="dot accent"></i> Connected now</span>
      {:else}
        <span class="badge">Not connected</span>
      {/if}
    </div>
    <div class="set-row">
      <div class="surf">
        <span class="surf-ico"><Icon name="dev" size={18} /></span>
        <span>
          <span class="t">Command line</span>
          <span class="d">{lastSeenText("cli")}</span>
        </span>
      </div>
      {#if recentlyActive("cli")}<span class="badge ok">Active</span>{/if}
    </div>
    <div class="set-row">
      <div class="surf">
        <span class="surf-ico"><Icon name="external" size={18} /></span>
        <span>
          <span class="t">Browser extension</span>
          <span class="d">{lastSeenText("native_host")}</span>
        </span>
      </div>
      {#if armed}
        <span class="badge warn">Agent fill armed</span>
      {:else if recentlyActive("native_host")}
        <span class="badge ok">Active</span>
      {/if}
    </div>
    <div class="set-row">
      <div class="surf">
        <span class="surf-ico"><Icon name="type-ssh_key" size={18} /></span>
        <span>
          <span class="t">SSH agent</span>
          <span class="d">
            {sshIdentities ? `Serving ${sshIdentities} key${sshIdentities === 1 ? "" : "s"}` : "No SSH keys loaded"} · {lastSeenText("ssh_agent")}
          </span>
        </span>
      </div>
    </div>
  </section>

  <!-- ================= Agent fill (agent-fill.md) ================= -->
  <section class="section" aria-labelledby="dev-fill-h">
    <div class="section-head">
      <h3 id="dev-fill-h">Let an agent fill logins</h3>
      {#if armed}
        <span class="badge warn">Armed · <span class="mono">{formatArmCountdown(armSecs)}</span></span>
      {/if}
    </div>
    <p class="hint" style="margin-top:0">
      Normally the browser extension fills a login only when you click <strong>Fill</strong>.
      Arming removes that click for three minutes, for the logins you tick, so an AI agent
      using this vault can sign in for you.
    </p>

    <!-- The consent text. This control is the entire security delta of the
         feature (agent-fill.md §4), so the trade is stated here rather than
         implied, including the part LocalPass cannot enforce (§3). -->
    <ul class="consent">
      <li><strong>Only these logins, only for three minutes.</strong> The window closes itself.</li>
      <li><strong>Only matching sites.</strong> The service checks the page against each login's saved website; the agent cannot ask its way past that.</li>
      <li>
        <strong>The value does land in the page.</strong> The agent never receives the password,
        but an agent that runs its own JavaScript in that page could read what was typed. Arm
        this only for an agent you would trust with the account.
      </li>
      <li><strong>Nothing is silent.</strong> Every fill shows a notification and two rows in the activity log below (the request from <span class="badge">MCP</span>, the fill from <span class="badge">Browser</span>).</li>
    </ul>

    {#if targetsError}
      <div class="error" role="alert">{targetsError}</div>
    {:else if targets.length === 0}
      <p class="hint">No logins in {fillVaultName || "this vault"} yet. Only logins with a website can be armed.</p>
    {:else}
      <div class="picker" role="group" aria-labelledby="dev-fill-h">
        {#each targets as t (t.id)}
          <label class="check pick">
            <input type="checkbox" value={t.id} bind:group={selected} disabled={armed || armBusy} />
            <span>{t.title}</span>
          </label>
        {/each}
      </div>
    {/if}

    <div class="arm-row">
      {#if armed}
        <button class="btn" type="button" onclick={disarm} disabled={armBusy}>{armBusy ? "…" : "Turn off now"}</button>
        <span class="hint" style="margin:0">{armedScope ? `Covers ${armedScope}.` : ""} Locking the vault also ends it.</span>
      {:else}
        <button class="btn btn-primary" type="button" onclick={arm} disabled={armBusy || scope.length === 0}>
          {armBusy ? "…" : scope.length ? `Arm ${scope.length} login${scope.length === 1 ? "" : "s"} for 3 minutes` : "Arm for 3 minutes"}
        </button>
        {#if scope.length === 0 && targets.length}<span class="hint" style="margin:0">Tick at least one login.</span>{/if}
      {/if}
      <!-- Speaks once per state change; the countdown is not a live region. -->
      <span class="sr-only" role="status">{armAnnouncement}</span>
    </div>
    {#if armError}<div class="error" role="alert">{armError}</div>{/if}
  </section>

  <!-- ================= Activity log ================= -->
  <section class="section" aria-labelledby="dev-audit-h">
    <div class="section-head">
      <h3 id="dev-audit-h">Activity</h3>
      <div class="toolbar">
        <label class="sr-only" for="dev-audit-limit">Records to read</label>
        <select id="dev-audit-limit" class="limit" bind:value={limit} onchange={refresh} disabled={loading}>
          {#each LIMITS as n (n)}<option value={n}>Last {n}</option>{/each}
        </select>
      </div>
    </div>

    <div class="log-filters">
      <div class="seg" role="group" aria-label="Filter by source">
        {#each SOURCES as s (s.id)}
          <button aria-pressed={sourceFilter === s.id} onclick={() => (sourceFilter = s.id)}>{s.label}</button>
        {/each}
      </div>
      <div class="search-box">
        <Icon name="search" size={14} />
        <label class="sr-only" for="dev-log-q">Filter activity</label>
        <input id="dev-log-q" type="search" placeholder="Filter" bind:value={logQuery} autocomplete="off" spellcheck="false" />
      </div>
    </div>

    {#if error}
      <div class="error" role="alert">{error}</div>
    {:else if loading && records.length === 0}
      <p class="empty">Loading…</p>
    {:else if records.length === 0}
      <p class="empty">No activity recorded yet.</p>
    {:else if visible.length === 0}
      <p class="empty">Nothing matches that filter.</p>
    {:else}
      <div class="log" role="table" aria-label="Activity">
        <div class="log-row log-head" role="row">
          <span role="columnheader">When</span>
          <span role="columnheader">Source</span>
          <span role="columnheader">What</span>
          <span role="columnheader">Item</span>
        </div>
        {#each visible as r (r.seq)}
          <div class="log-row" class:alarm={isAlarming(r.kind)} role="row">
            <span role="cell" class="when" title={formatAuditTime(r.timestamp)}>{formatAgo(r.timestamp)}</span>
            <span role="cell">
              <span class="badge src {r.source ?? 'unknown'}" title={callerLabel(r)}>{sourceLabel(r.source)}</span>
            </span>
            <span role="cell" class="op">
              {#if isAlarming(r.kind)}<Icon name="alert" size={13} />{/if}
              {operationLabel(r)}
            </span>
            <span role="cell" class="item">
              {#if isResolved(r.item_id, titles)}
                {resolveItemTitle(r.item_id, titles)}
              {:else if r.item_id}
                <span class="mono faint" title="This item is not in an unlocked vault">{shortId(r.item_id)}</span>
              {:else if r.vault_id}
                <span class="faint">vault {vaultNames.get(r.vault_id) ?? shortId(r.vault_id)}</span>
              {:else}
                <span class="faint">—</span>
              {/if}
            </span>
          </div>
        {/each}
      </div>
      <p class="hint">
        {visible.length} of {records.length} records from this device's log{loadedAt ? `, read ${formatAuditTime(loadedAt)}` : ""}.
        The log stores ids only (it is plaintext on disk); titles are resolved here. The full,
        tamper-evident log: <code>localpass audit</code>.
      </p>
    {/if}
  </section>

  <!-- ================= Guides ================= -->
  <section class="section guides">
    <details class="disclosure">
      <summary>
        <Icon name="dev" size={16} /> Use from the command line
        <span class="chev"><Icon name="chevron" size={14} /></span>
      </summary>
      <div class="body">
        <p class="hint" style="margin-top:0">
          {#if localpassPath}
            The CLI is at <code class="wrap-anywhere">{localpassPath}</code>.
          {:else}
            Install the CLI as <code>localpass</code> on your <code>PATH</code>.
          {/if}
          Unlock once with <code>localpass unlock</code>; later commands use the running service and need no password.
        </p>

        <h4>Inject secrets into a process</h4>
        <p class="hint">References are resolved at start and handed to the child's environment. Nothing is written to disk.</p>
        <div class="snippet"><CopyRow label="Command" display={injectExample} copy={() => copyPlain(injectExample)} /></div>
        <ul class="ref">
          <li><code>localpass://&lt;vault&gt;/&lt;item&gt;/&lt;field&gt;</code>: names or ids; <code>op://</code> works too.</li>
          <li><code>--no-input</code> makes a script fail instead of waiting on a prompt.</li>
          <li><code>-e KEY=REF</code> repeats and wins over <code>--env-set</code> / <code>--env-file</code>. Everything after <code>--</code> runs.</li>
        </ul>

        <h4>Rotate a password without printing it</h4>
        <div class="callout warn" role="note">
          <span class="icon"><Icon name="alert" size={15} /></span>
          <span><code>item add --generate</code> prints the new password to stdout, so it lands in scrollback and CI logs. In scripts, pipe it straight into an edit:</span>
        </div>
        <div class="snippet"><CopyRow label="Command" display={rotateExample} copy={() => copyPlain(rotateExample)} /></div>
        <p class="hint"><code>--password -</code> reads stdin, so this needs an unlocked service (no terminal is left to prompt on).</p>
      </div>
    </details>

    <details class="disclosure">
      <summary>
        <Icon name="agent" size={16} /> Connect an AI agent (MCP)
        <span class="chev"><Icon name="chevron" size={14} /></span>
      </summary>
      <div class="body">
        <div class="callout ok" role="note">
          <span class="icon"><Icon name="security" size={15} /></span>
          <span>
            <strong>No secret ever enters the agent's transcript.</strong> Items come back masked,
            <code>run_with_secrets</code> scrubs injected values from captured output, and there are no
            write tools. While an agent is connected, changes in this app ask for your master password.
          </span>
        </div>
        <p class="hint">Add this to your MCP client's configuration, then run <code>localpass unlock</code> before starting the agent:</p>
        <div class="code-block">
          <pre class="scroll" aria-label="MCP registration snippet">{mcpSnippet}</pre>
          <button class="icon-btn" type="button" onclick={() => copy(mcpSnippet, "Snippet")} aria-label="Copy snippet"><Icon name="copy" size={16} /></button>
        </div>
        {#if !localpassPath}
          <p class="hint">No <code>localpass</code> executable was found, so the snippet uses the bare name. Use an absolute path if your client does not inherit your shell's <code>PATH</code>.</p>
        {/if}
        <h4>Tools it exposes</h4>
        <ul class="plain-list tools-list" aria-label="MCP tools">
          {#each MCP_TOOLS as t (t.name)}
            <li><code class="tool-name">{t.name}</code><span class="hint" style="margin:0">{t.blurb}</span></li>
          {/each}
        </ul>
      </div>
    </details>
  </section>
</div>

<style>
  .dev {
    max-width: 820px;
  }
  .surfaces {
    border-radius: var(--radius-lg);
    background: var(--bg-hover);
    padding: 2px 16px;
  }
  .surfaces .set-row + .set-row {
    border-top-color: var(--border-strong);
  }
  .surf {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
  }
  .surf > span:last-child {
    display: grid;
    min-width: 0;
  }
  .surf-ico {
    color: var(--text-muted);
  }
  .consent {
    margin: 10px 0 12px;
    padding-left: 18px;
    font-size: 13px;
    line-height: 1.55;
    color: var(--text-muted);
  }
  .consent li + li {
    margin-top: 4px;
  }
  .consent strong {
    color: var(--text);
  }
  .picker {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 4px 16px;
    max-height: 12rem;
    overflow-y: auto;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .pick {
    align-items: center;
    padding: 4px 0;
  }
  .pick span {
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .arm-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 12px;
  }
  .limit {
    width: auto;
    height: 28px;
    font-size: 12.5px;
  }
  .log-filters {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 8px;
  }
  .log-filters .seg {
    flex-wrap: wrap;
  }
  .search-box {
    flex: 1 1 160px;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 32px;
    padding: 0 8px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    color: var(--text-faint);
    background: var(--bg-content);
  }
  .search-box:focus-within {
    outline: 2px solid var(--focus);
    border-color: transparent;
  }
  .search-box input {
    border: 0;
    height: 100%;
    padding: 0;
    background: transparent;
    outline: none;
  }
  .log {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    /* Stacks by its own width, not the viewport: the log sits in a pane. */
    container-type: inline-size;
  }
  .log-row {
    display: grid;
    grid-template-columns: 6rem 5.5rem minmax(0, 1fr) minmax(0, 1fr);
    gap: 10px;
    align-items: center;
    padding: 7px 12px;
    font-size: 13px;
  }
  .log-row + .log-row {
    border-top: 1px solid var(--border);
  }
  .log-head {
    background: var(--bg-hover);
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 500;
  }
  .log-row.alarm {
    background: var(--danger-tint);
  }
  .when {
    color: var(--text-muted);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  .op {
    display: flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
  }
  .alarm .op {
    color: var(--danger);
  }
  .item {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .src.mcp {
    background: var(--accent-tint);
    color: var(--accent);
  }
  @container (max-width: 560px) {
    .log-head {
      display: none;
    }
    .log-row {
      grid-template-columns: auto minmax(0, 1fr);
      grid-template-areas: "src op" "when item";
      row-gap: 2px;
    }
    .log-row > :nth-child(1) {
      grid-area: when;
    }
    .log-row > :nth-child(2) {
      grid-area: src;
    }
    .log-row > :nth-child(3) {
      grid-area: op;
    }
    .log-row > :nth-child(4) {
      grid-area: item;
      color: var(--text-muted);
    }
  }
  .guides {
    margin-top: 30px;
  }
  .guides h4 {
    font-size: 13px;
    margin: 16px 0 4px;
  }
  .snippet {
    margin: 6px -10px;
  }
  .ref {
    margin: 6px 0 0;
    padding-left: 18px;
    font-size: 12.5px;
    color: var(--text-muted);
    line-height: 1.6;
  }
  .tools-list li {
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 12px;
  }
  .tool-name {
    min-width: 9rem;
    font-weight: 600;
  }
</style>
