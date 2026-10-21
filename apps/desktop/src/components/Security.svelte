<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Security ("Watchtower") tab: an offline password-health audit of the selected
  vault. Flags weak / short / common / reused passwords.

  SECRET BOUNDARY: this view NEVER receives a secret value. The daemon computes
  the analysis and returns metadata only (title, field, length, an entropy
  estimate, and issue flags). No reveal happens here.
-->
<script lang="ts">
  import { passwordHealth } from "../lib/api";
  import type { PasswordHealthView } from "../lib/types";
  import Icon from "./Icon.svelte";

  interface Props {
    /** The selected vault id to audit. */
    vault: string;
    /** The vault's display name (for the header). */
    vaultName?: string;
  }
  let { vault, vaultName = "" }: Props = $props();

  let report = $state<PasswordHealthView[]>([]);
  let loading = $state(false);
  let error = $state("");
  let loadedVault = "";

  async function load() {
    if (!vault) return;
    loading = true;
    error = "";
    try {
      report = await passwordHealth(vault);
      loadedVault = vault;
    } catch (err) {
      report = [];
      error = typeof err === "string" ? err : "Could not run the security check.";
    } finally {
      loading = false;
    }
  }

  // Re-run when the selected vault changes (and on mount).
  $effect(() => {
    if (vault && vault !== loadedVault) {
      load();
    }
  });

  const flagged = $derived(report.filter((r) => r.issues.length > 0));
  const counts = $derived({
    total: report.length,
    weak: report.filter((r) => r.issues.includes("weak")).length,
    reused: report.filter((r) => r.issues.includes("reused")).length,
    common: report.filter((r) => r.issues.includes("common")).length,
    short: report.filter((r) => r.issues.includes("short")).length,
  });

  // Weakest first (lowest entropy), then by title.
  const sortedFlagged = $derived(
    [...flagged].sort(
      (a, b) => a.entropy_bits - b.entropy_bits || a.title.localeCompare(b.title),
    ),
  );

  const ISSUE_LABEL: Record<string, string> = {
    weak: "Weak",
    short: "Too short",
    common: "Common password",
    reused: "Reused",
  };
</script>

<div class="page security">
  <div class="page-head">
    <div>
      <h2>Security</h2>
      <p class="sub">Password health for {vaultName || "this vault"}, checked on this device.</p>
    </div>
    <div class="actions">
      <button class="btn btn-sm" onclick={load} disabled={loading}>
        <Icon name="refresh" size={14} /> {loading ? "Checking…" : "Check again"}
      </button>
    </div>
  </div>

  {#if error}
    <div class="error" role="alert">{error}</div>
  {:else if loading && report.length === 0}
    <p class="empty">Checking…</p>
  {:else if counts.total === 0}
    <div class="empty">
      <Icon name="security" size={28} />
      <p>No passwords to check in this vault yet.</p>
    </div>
  {:else}
    <p class="summary" role="status">
      <span class="num strong">{counts.total}</span> checked
      {#if counts.weak}<span class="sep">·</span><span class="num bad">{counts.weak}</span> weak{/if}
      {#if counts.reused}<span class="sep">·</span><span class="num warn">{counts.reused}</span> reused{/if}
      {#if counts.common}<span class="sep">·</span><span class="num bad">{counts.common}</span> common{/if}
      {#if counts.short}<span class="sep">·</span><span class="num warn">{counts.short}</span> too short{/if}
    </p>

    {#if sortedFlagged.length === 0}
      <div class="callout ok" role="status">
        <span class="icon"><Icon name="check" size={16} /></span>
        <span>All passwords look healthy: nothing weak, reused, common or too short.</span>
      </div>
    {:else}
      <div class="section">
        <div class="section-head">
          <h3>To fix</h3>
          <span class="faint">Weakest first</span>
        </div>
        <ul class="plain-list" aria-label="Passwords to fix">
          {#each sortedFlagged as r (r.item_id + r.field)}
            <li class="flag">
              <span class="strength-dot {r.strength}" title={r.strength} aria-hidden="true"></span>
              <span class="flag-main">
                <span class="flag-title">
                  {r.title}{#if r.field !== "password"} <span class="faint">· {r.field}</span>{/if}
                </span>
                <span class="flag-meta">
                  {r.length} characters · {Math.round(r.entropy_bits)} bits{r.age_days && r.age_days >= 1
                    ? ` · ${r.age_days} days old`
                    : ""}
                </span>
              </span>
              <span class="flag-issues">
                {#each r.issues as issue (issue)}
                  <span class="badge {issue === 'reused' || issue === 'short' ? 'warn' : 'danger'}">{ISSUE_LABEL[issue] ?? issue}</span>
                {/each}
              </span>
            </li>
          {/each}
        </ul>
        <p class="hint">Open an item and choose Edit to set a new one; Generate makes a strong one.</p>
      </div>
    {/if}
  {/if}
</div>

<style>
  .security {
    max-width: 700px;
  }
  .summary {
    font-size: 15px;
    color: var(--text-muted);
  }
  .summary .num {
    color: var(--text);
    font-weight: 600;
  }
  .summary .num.bad {
    color: var(--danger);
  }
  .summary .num.warn {
    color: var(--warning);
  }
  .summary .sep {
    margin: 0 6px;
    color: var(--text-faint);
  }
  .flag {
    align-items: center;
  }
  .flag-main {
    flex: 1;
    min-width: 0;
    display: grid;
  }
  .flag-title {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .flag-meta {
    font-size: 12px;
    color: var(--text-muted);
  }
  .flag-issues {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    justify-content: flex-end;
  }
  .strength-dot {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-faint);
  }
  .strength-dot.weak {
    background: var(--danger);
  }
  .strength-dot.fair {
    background: var(--warning);
  }
  .strength-dot.strong,
  .strength-dot.excellent {
    background: var(--success);
  }
  @media (max-width: 719px) {
    .flag {
      flex-wrap: wrap;
    }
    .flag-issues {
      width: 100%;
      justify-content: flex-start;
      padding-left: 20px;
    }
  }
</style>
