<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The "Dev" tab: how to drive this vault from a terminal (CLI) and from an AI
  coding agent (MCP), plus a viewer for the local audit log so you can see what
  those surfaces actually did.

  SECRET BOUNDARY: nothing here reveals a value. The CLI/MCP sections are static
  reference text. The audit viewer shows METADATA ONLY — the daemon's audit
  records carry ids, kind labels, timestamps, and caller attribution, and the
  log itself stores no names at all (it is plaintext on disk, while names are
  ciphertext everywhere else). Item ids are resolved to titles HERE, at display
  time, against the unlocked session's own item lists; an unresolvable id falls
  back to a short id. No title is ever sent toward the log.
-->
<script lang="ts">
  import { listItems, auditList, devEnv } from "../lib/api";
  import type { AuditRecordView, VaultView } from "../lib/types";
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

  interface Props {
    /** Every vault the unlocked session can see — used to resolve audit ids to
     *  titles at display time. */
    vaults: VaultView[];
    /** The currently selected vault id, used in the example commands so they
     *  are copy-and-run rather than copy-and-edit. */
    selectedVault?: string;
  }
  let { vaults, selectedVault = "" }: Props = $props();

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
    refresh();
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
</script>

<div class="detail dev">
  <h2>Dev tools</h2>
  <p class="muted" style="margin-top:0">
    Drive this vault from a terminal or an AI coding agent — and see exactly what
    they did.
  </p>

  <!-- ================= CLI ================= -->
  <section class="field-group dev-section" aria-labelledby="dev-cli-h">
    <div class="field-name" id="dev-cli-h">Command line</div>
    <p class="hint" style="margin-top:0.35rem">
      {#if localpassPath}
        The CLI is at <code class="mono dev-path">{localpassPath}</code>.
      {:else}
        Install the CLI as <code class="mono">localpass</code> on your
        <code class="mono">PATH</code>.
      {/if}
      {#if profile}
        It shares this app's profile: <code class="mono dev-path">{profile}</code>.
      {/if}
    </p>
    <p class="hint">
      Unlock once with <code class="mono">localpass unlock</code> and the running
      service holds the session — later commands need no password, and the GUI and
      CLI see the same vault.
    </p>

    <div class="dev-sub">Inject secrets into a process</div>
    <p class="hint" style="margin-top:0.2rem">
      The pattern that keeps secrets off disk entirely: references are resolved at
      spawn and handed to the child's environment. Nothing is written anywhere.
    </p>
    <div class="gen-output dev-snippet">
      <span class="val">{injectExample}</span>
      <button class="btn btn-small" type="button" onclick={() => copy(injectExample, "Command")}>
        Copy
      </button>
    </div>
    <ul class="dev-list">
      <li>
        <code class="mono">localpass://&lt;vault&gt;/&lt;item&gt;/&lt;field&gt;</code>
        — vault is a name or id, item a title or id, field a field name (or an
        env-set key). <code class="mono">op://</code> is an accepted alias.
      </li>
      <li>
        <code class="mono">--no-input</code> is global: it forbids interactive
        prompts, so a script fails instead of hanging on one.
      </li>
      <li>
        <code class="mono">-e KEY=REF</code> is repeatable and wins over
        <code class="mono">--env-set &lt;item&gt;</code> and
        <code class="mono">--env-file &lt;path&gt;</code>. Everything after
        <code class="mono">--</code> is the command to run.
      </li>
    </ul>

    <div class="dev-sub">Add and edit items</div>
    <ul class="dev-list">
      <li>
        <code class="mono">localpass item add --type login --title "Prod DB" --username alice</code>
        — types are <code class="mono">login</code>, <code class="mono">note</code>,
        <code class="mono">api_key</code>, <code class="mono">env_set</code>,
        <code class="mono">ssh_key</code>, <code class="mono">totp</code>.
      </li>
      <li>
        <code class="mono">localpass item edit "Prod DB" --username bob</code> —
        the first argument is a title or id; the supplied flags overlay the
        current payload.
      </li>
      <li>
        <code class="mono">localpass generate --length 24</code> prints a password
        to <strong>stdout</strong> (its entropy goes to stderr), so it pipes
        cleanly. Add <code class="mono">--words 6</code> for a passphrase.
      </li>
    </ul>

    <!-- The gotcha the owner asked to call out explicitly. -->
    <div class="error dev-warn" role="note">
      <strong><code class="mono">item add --generate</code> prints the generated
      password to stdout.</strong>
      That line lands in your terminal scrollback, your shell transcript, and any
      CI log capturing the run. It is fine for a human at a terminal who wants to
      see the value once — it is the wrong tool inside a script.
    </div>
    <p class="hint" style="margin-top:0.2rem">
      The safe pattern is to generate and pipe the value straight into an edit, so
      it never reaches stdout. <code class="mono">--password -</code> reads the
      value from stdin:
    </p>
    <div class="gen-output dev-snippet">
      <span class="val">{rotateExample}</span>
      <button class="btn btn-small" type="button" onclick={() => copy(rotateExample, "Command")}>
        Copy
      </button>
    </div>
    <p class="hint">
      This needs an <strong>unlocked service</strong> (run
      <code class="mono">localpass unlock</code> first, or keep this window
      unlocked). The pipe occupies stdin, so the CLI has no terminal left to
      prompt for a master password on — with a held session it never needs to ask.
    </p>
  </section>

  <!-- ================= MCP ================= -->
  <section class="field-group dev-section" aria-labelledby="dev-mcp-h">
    <div class="field-name" id="dev-mcp-h">MCP server (for AI agents)</div>
    <p class="hint" style="margin-top:0.35rem">
      <code class="mono">localpass mcp</code> speaks the Model Context Protocol on
      stdin/stdout, so an AI coding agent can <em>spend</em> a secret without ever
      receiving a copy of it. It is an ordinary daemon client — no network
      listener, no new storage, no new trust boundary.
    </p>

    <div class="dev-guarantee" role="note">
      <p style="margin:0 0 0.25rem"><strong>No secret ever enters the transcript.</strong></p>
      <p class="hint" style="margin:0">
        Every tool result is copied verbatim into the agent's context — logged,
        replayed, and for a hosted model sent to a third party. So no tool returns
        a secret value: items come back masked at the source <em>and</em> through a
        masking choke point, and <code class="mono">run_with_secrets</code> scrubs
        every injected value out of the child's captured output and refuses to
        return the output at all if any survived. There are also no write tools —
        a confused or prompt-injected agent cannot create, edit, delete or export
        anything through this surface.
      </p>
    </div>

    <div class="dev-sub">Register it with your MCP client</div>
    <p class="hint" style="margin-top:0.2rem">
      Most clients take a JSON server map. Paste this into your client's MCP
      configuration:
    </p>
    <div class="dev-snippet">
      <pre class="dev-code" aria-label="MCP registration snippet">{mcpSnippet}</pre>
      <div class="toolbar" style="margin-top:0.4rem">
        <button class="btn btn-small" type="button" onclick={() => copy(mcpSnippet, "Snippet")}>
          Copy snippet
        </button>
      </div>
    </div>
    {#if !localpassPath}
      <p class="hint">
        No <code class="mono">localpass</code> executable was found beside this app
        or on <code class="mono">PATH</code>, so the snippet uses the bare name —
        replace it with an absolute path if your MCP client does not inherit your
        shell's <code class="mono">PATH</code>.
      </p>
    {/if}
    <p class="hint">
      Run <code class="mono">localpass unlock</code> before starting the agent. The
      server then takes the daemon route and holds no key material of its own; it
      serves until its client closes stdin, and idles out with the same auto-lock
      as everything else.
    </p>

    <div class="dev-sub">Tools it exposes</div>
    <div role="list" aria-label="MCP tools">
      {#each MCP_TOOLS as t (t.name)}
        <div class="dev-tool" role="listitem">
          <code class="mono dev-tool-name">{t.name}</code>
          <span class="hint" style="margin:0">{t.blurb}</span>
        </div>
      {/each}
    </div>
    <p class="hint">
      Every action an agent takes through these tools is recorded below with
      <span class="badge">MCP</span> as its source.
    </p>
  </section>

  <!-- ================= Audit log ================= -->
  <section class="field-group dev-section" aria-labelledby="dev-audit-h">
    <div class="dev-audit-head">
      <div class="field-name" id="dev-audit-h">Recent activity</div>
      <div class="toolbar">
        <label class="sr-only" for="dev-audit-limit">Records to show</label>
        <select id="dev-audit-limit" bind:value={limit} onchange={refresh} disabled={loading}>
          {#each LIMITS as n (n)}
            <option value={n}>last {n}</option>
          {/each}
        </select>
        <button class="btn btn-small" type="button" onclick={refresh} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>
    </div>
    <p class="hint" style="margin-top:0.2rem">
      This device's local audit log — what the CLI, this window, an MCP agent, the
      browser extension, and the SSH agent each did. Metadata only: the log
      records <strong>ids, never names</strong>, because it is plaintext on disk
      while your titles are encrypted. Titles below are resolved here, in this
      window, from your unlocked vaults.
    </p>

    {#if error}
      <div class="error" role="alert">{error}</div>
    {:else if loading && records.length === 0}
      <p class="empty">Loading…</p>
    {:else if records.length === 0}
      <p class="empty">No activity recorded yet.</p>
    {:else}
      <div class="dev-log" role="table" aria-label="Recent activity">
        <div class="dev-log-row dev-log-head" role="row">
          <span role="columnheader">When</span>
          <span role="columnheader">Source</span>
          <span role="columnheader">Caller</span>
          <span role="columnheader">Operation</span>
          <span role="columnheader">Item</span>
        </div>
        {#each records as r (r.seq)}
          <div class="dev-log-row" class:alarm={isAlarming(r.kind)} role="row">
            <span role="cell" class="dev-when">{formatAuditTime(r.timestamp)}</span>
            <span role="cell">
              <span class="badge dev-src {r.source ?? 'unknown'}">{sourceLabel(r.source)}</span>
            </span>
            <span role="cell" class="dev-caller mono">{callerLabel(r)}</span>
            <span role="cell">{operationLabel(r)}</span>
            <span role="cell" class="dev-item">
              {#if isResolved(r.item_id, titles)}
                {resolveItemTitle(r.item_id, titles)}
              {:else if r.item_id}
                <span class="mono muted" title="This item is no longer in an unlocked vault">
                  {shortId(r.item_id)}
                </span>
              {:else if r.vault_id}
                <span class="muted">
                  vault {vaultNames.get(r.vault_id) ?? shortId(r.vault_id)}
                </span>
              {:else}
                <span class="muted">—</span>
              {/if}
            </span>
          </div>
        {/each}
      </div>
      <p class="hint">
        Showing the most recent {records.length}
        record{records.length === 1 ? "" : "s"}{loadedAt
          ? ` · read ${formatAuditTime(loadedAt)}`
          : ""}. The full, tamper-evident log is on disk — read it with
        <code class="mono">localpass audit</code>.
      </p>
    {/if}
  </section>
</div>

<style>
  .dev {
    max-width: 720px;
  }
  .dev-section {
    margin-top: 1.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid var(--border);
  }
  .dev-section:first-of-type {
    border-top: none;
    padding-top: 0;
  }
  .dev-sub {
    margin-top: 1rem;
    font-weight: 600;
  }
  .dev-list {
    margin: 0.35rem 0 0;
    padding-left: 1.2rem;
    line-height: 1.6;
    color: var(--text-muted);
    font-size: 0.85em;
  }
  .dev-list li {
    margin-bottom: 0.35rem;
  }
  /* Long absolute paths must wrap rather than widen the pane. */
  .dev-path {
    overflow-wrap: anywhere;
  }
  .dev-snippet {
    margin-top: 0.5rem;
  }
  .dev-snippet .val {
    white-space: pre-wrap;
  }
  .dev-code {
    margin: 0;
    padding: 0.6em 0.7em;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-panel);
    font-family: var(--mono);
    font-size: 0.85em;
    line-height: 1.5;
    /* A wide snippet scrolls inside its own box; the pane never scrolls
       sideways. */
    overflow-x: auto;
    user-select: all;
  }
  /* A note, not an error: reuse `.error`'s box but neutral colours, exactly as
     Help.svelte and ItemDetail.svelte do for their advisories. */
  .dev-warn {
    color: var(--text);
    background: var(--bg-hover);
    border-color: var(--border);
    border-left: 3px solid var(--danger);
    margin: 0.75rem 0 0.35rem;
  }
  .dev-guarantee {
    margin: 0.75rem 0;
    padding: 0.8rem 0.9rem;
    border: 1px solid var(--border);
    border-left: 3px solid var(--ok);
    border-radius: 6px;
    background: var(--bg-panel);
  }
  .dev-tool {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.5rem;
    padding: 0.4rem 0;
    border-bottom: 1px solid var(--border);
  }
  .dev-tool-name {
    font-weight: 600;
    min-width: 9.5rem;
  }

  /* --- Audit log table --- */
  .dev-audit-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    flex-wrap: wrap;
  }
  .dev-log {
    margin-top: 0.6rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .dev-log-row {
    display: grid;
    grid-template-columns: 6.5rem 5rem 9rem 1fr 1fr;
    gap: 0.6rem;
    align-items: baseline;
    padding: 0.45rem 0.7rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85em;
  }
  .dev-log-row:last-child {
    border-bottom: none;
  }
  .dev-log-head {
    background: var(--bg-panel);
    color: var(--text-muted);
    font-size: 0.72em;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: 700;
  }
  .dev-log-row.alarm {
    background: var(--danger-bg);
  }
  .dev-when,
  .dev-caller {
    color: var(--text-muted);
    font-size: 0.95em;
  }
  .dev-caller,
  .dev-item {
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .dev-src.gui {
    border-color: var(--accent);
  }
  .dev-src.mcp,
  .dev-src.native_host {
    border-color: color-mix(in srgb, var(--accent) 50%, var(--border));
  }

  /* Narrow panes (and the mobile single-screen layout): the five-column grid
     stops working long before the text does, so each record becomes a stacked
     card with its columns labelled by position rather than by a header row. */
  @media (max-width: 720px) {
    .dev-log-head {
      display: none;
    }
    .dev-log-row {
      grid-template-columns: 1fr;
      gap: 0.15rem;
      padding: 0.6rem 0.7rem;
    }
    .dev-log-row > :global(*) {
      min-width: 0;
    }
  }
</style>
