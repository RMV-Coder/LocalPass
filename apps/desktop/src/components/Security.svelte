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

<div class="detail security">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem">
    <div>
      <h2 style="margin-bottom:0.15rem">Security check</h2>
      <p class="muted" style="margin:0">
        Offline audit of {vaultName ? `“${vaultName}”` : "this vault"} — no network,
        no secret values shown.
      </p>
    </div>
    <button class="btn btn-small" onclick={load} disabled={loading}>
      {loading ? "Scanning…" : "Rescan"}
    </button>
  </div>

  {#if error}
    <div class="error" role="alert" style="margin-top:1rem">{error}</div>
  {:else if loading && report.length === 0}
    <p class="empty">Scanning…</p>
  {:else if counts.total === 0}
    <p class="empty" style="margin-top:1.5rem">No passwords to check in this vault yet.</p>
  {:else}
    <!-- Summary chips -->
    <div class="sec-summary" role="group" aria-label="Summary">
      <div class="sec-chip">
        <span class="sec-num">{counts.total}</span>
        <span class="sec-lbl">checked</span>
      </div>
      <div class="sec-chip {counts.weak ? 'weak' : ''}">
        <span class="sec-num">{counts.weak}</span><span class="sec-lbl">weak</span>
      </div>
      <div class="sec-chip {counts.reused ? 'fair' : ''}">
        <span class="sec-num">{counts.reused}</span><span class="sec-lbl">reused</span>
      </div>
      <div class="sec-chip {counts.common ? 'weak' : ''}">
        <span class="sec-num">{counts.common}</span><span class="sec-lbl">common</span>
      </div>
      <div class="sec-chip {counts.short ? 'fair' : ''}">
        <span class="sec-num">{counts.short}</span><span class="sec-lbl">short</span>
      </div>
    </div>

    {#if sortedFlagged.length === 0}
      <div class="sec-allclear">
        <p class="strong" style="margin:0 0 0.25rem">All passwords look healthy. ✓</p>
        <p class="hint" style="margin:0">
          Nothing weak, reused, common, or too short in this vault.
        </p>
      </div>
    {:else}
      <p class="hint" style="margin:1.25rem 0 0.5rem">
        {sortedFlagged.length} password{sortedFlagged.length === 1 ? "" : "s"} to review —
        re-generate them from an item's <strong>Edit</strong> screen or the
        <strong>Generator</strong>.
      </p>
      <div role="list" aria-label="Flagged passwords">
        {#each sortedFlagged as r (r.item_id + r.field)}
          <div class="sec-row" role="listitem">
            <div class="sec-row-main">
              <span class="sec-title">{r.title}</span>
              {#if r.field !== "password"}<span class="badge">{r.field}</span>{/if}
              <span class="strength-dot {r.strength}" title={r.strength}></span>
              <span class="muted sec-meta">
                {Math.round(r.entropy_bits)} bits · {r.length} chars{r.age_days &&
                r.age_days >= 1
                  ? ` · ${r.age_days}d old`
                  : ""}
              </span>
            </div>
            <div class="sec-issues">
              {#each r.issues as issue (issue)}
                <span class="badge sec-issue {issue}">{ISSUE_LABEL[issue] ?? issue}</span>
              {/each}
            </div>
          </div>
        {/each}
      </div>
    {/if}

    <p class="hint" style="margin-top:1.25rem">
      Checks run entirely on this device against a bundled common-password list —
      nothing is sent anywhere.
    </p>
  {/if}
</div>

<style>
  .security {
    max-width: 640px;
  }
  .sec-summary {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    margin: 1.25rem 0 0.5rem;
  }
  .sec-chip {
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 4.2rem;
    padding: 0.5rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-panel);
  }
  .sec-chip.weak {
    border-color: var(--danger);
  }
  .sec-chip.fair {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  }
  .sec-num {
    font-size: 1.25rem;
    font-weight: 700;
    font-family: var(--mono);
  }
  .sec-lbl {
    font-size: 0.72rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .sec-allclear {
    margin-top: 1.5rem;
    padding: 1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-panel);
  }
  .sec-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.55rem 0;
    border-bottom: 1px solid var(--border);
  }
  .sec-row-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    min-width: 0;
  }
  .sec-title {
    font-weight: 600;
  }
  .sec-meta {
    font-size: 0.8rem;
  }
  .sec-issues {
    display: flex;
    gap: 0.3rem;
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .strength-dot {
    width: 0.6rem;
    height: 0.6rem;
    border-radius: 50%;
    display: inline-block;
    background: var(--text-muted);
  }
  .strength-dot.weak {
    background: var(--danger);
  }
  .strength-dot.fair {
    background: color-mix(in srgb, var(--danger) 55%, var(--ok));
  }
  .strength-dot.strong,
  .strength-dot.excellent {
    background: var(--ok);
  }
  .sec-issue.reused {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  }
  .sec-issue.common,
  .sec-issue.weak,
  .sec-issue.short {
    border-color: var(--danger);
    color: var(--danger);
  }
</style>
