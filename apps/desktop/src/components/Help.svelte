<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Static help / quick-start guide. No daemon calls, no secret state — just
  reference content rendered from the sidebar "Help" tab.
-->
<script lang="ts">
  // A keyboard-shortcut row helper keeps the markup tidy.
  const shortcuts: { keys: string[]; action: string }[] = [
    { keys: ["↑", "↓"], action: "Move through the item list" },
    { keys: ["Enter"], action: "Open the focused item" },
    { keys: ["Tab"], action: "Move between controls (fully keyboard-operable)" },
  ];
</script>

<div class="detail help">
  <h2>Help &amp; quick guide</h2>
  <p class="muted" style="margin-top:0">
    LocalPass keeps your passwords, API keys, SSH keys, TOTP codes and
    <code>.env</code> secrets encrypted on <strong>this device</strong> — no cloud.
  </p>

  <div class="error" role="note" style="color:var(--text);background:var(--bg-hover);border-color:var(--border)">
    <strong>Pre-1.0 — not yet audited.</strong> Please don't store irreplaceable
    real secrets yet. The on-disk format may still change before 1.0.
  </div>

  <section class="field-group help-section">
    <div class="field-name">Getting started</div>
    <ol class="help-list">
      <li><strong>Save your Emergency Kit.</strong> It holds your Secret Key, which
        together with your master password unlocks the vault. Store it offline.</li>
      <li><strong>Add items</strong> with <span class="badge">+ Add</span> in the
        item list — pick a type, fill the fields, save.</li>
      <li><strong>Reveal &amp; copy</strong> secrets with the per-field buttons in
        an item's detail view. Values stay masked until you ask.</li>
      <li><strong>Create more vaults</strong> with <span class="badge">+ New</span>
        to keep, say, personal and work secrets apart.</li>
    </ol>
  </section>

  <section class="field-group help-section">
    <div class="field-name">Keyboard &amp; navigation</div>
    <div class="help-keys">
      {#each shortcuts as s (s.action)}
        <div class="help-key-row">
          <span class="help-keycaps">
            {#each s.keys as k (k)}<kbd class="kbd">{k}</kbd>{/each}
          </span>
          <span>{s.action}</span>
        </div>
      {/each}
    </div>
    <p class="hint">Use the search box at the top of the item list to filter as you type.</p>
  </section>

  <section class="field-group help-section">
    <div class="field-name">Item types</div>
    <p class="hint" style="margin-top:0">
      <span class="badge">Login</span>
      <span class="badge">Secure note</span>
      <span class="badge">API key</span>
      <span class="badge">Env set</span>
      <span class="badge">SSH key</span>
      <span class="badge">TOTP</span>
    </p>
    <ul class="help-list">
      <li><strong>TOTP</strong> items show a live 6-digit code with a countdown ring.</li>
      <li><strong>SSH keys</strong> are served by the built-in agent while unlocked —
        the private key never leaves the daemon.</li>
      <li><strong>Attachments</strong> can be added to any item. They're stored
        encrypted and written straight to the file you choose on download — the
        contents never pass through this window.</li>
    </ul>
  </section>

  <section class="field-group help-section">
    <div class="field-name">.env &amp; dev servers</div>
    <p class="hint" style="margin-top:0">
      An <strong>Env set</strong> holds your <code>KEY=value</code> variables. On its
      detail view, <em>“Use in your dev server”</em> builds a
      <code class="mono">localpass run</code> command that injects the variables into
      your process — nothing is written to disk. <em>“Export as .env”</em> assembles
      a copyable <code>.env</code> when you need one.
    </p>
  </section>

  <section class="field-group help-section">
    <div class="field-name">Devices &amp; sync</div>
    <p class="hint" style="margin-top:0">
      Open the <strong>Devices &amp; Sync</strong> tab to link another machine you
      own: exchange device identities, confirm the fingerprint, share a vault, and
      sync through a shared folder. Everything stays end-to-end encrypted; there's
      no server in the middle.
    </p>
  </section>

  <section class="field-group help-section">
    <div class="field-name">Security &amp; recovery</div>
    <ul class="help-list">
      <li><strong>No cloud reset.</strong> Losing your master password, Secret Key,
        <em>and</em> all your devices means the data is gone — by design. This is why
        the Emergency Kit matters.</li>
      <li><strong>Masked by default.</strong> Secrets are hidden until you explicitly
        reveal or copy them, and every reveal is recorded in the local audit log.</li>
      <li><strong>Auto-lock.</strong> The vault locks itself after a period of
        inactivity; unlock again with your master password.</li>
    </ul>
    <p class="hint">
      Learn more in the project README and <code class="mono">SECURITY.md</code> at
      <code class="mono">github.com/RMV-Coder/LocalPass</code>.
    </p>
  </section>
</div>

<style>
  .help {
    max-width: 640px;
  }
  .help-section {
    margin-top: 1.25rem;
  }
  .help-list {
    margin: 0.35rem 0 0;
    padding-left: 1.2rem;
    line-height: 1.6;
  }
  .help-list li {
    margin-bottom: 0.35rem;
  }
  .help-keys {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin-top: 0.35rem;
  }
  .help-key-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }
  .help-keycaps {
    display: inline-flex;
    gap: 0.25rem;
    min-width: 4.5rem;
  }
  .kbd {
    font-family: var(--mono);
    font-size: 0.8em;
    line-height: 1;
    padding: 0.25em 0.5em;
    border: 1px solid var(--border);
    border-bottom-width: 2px;
    border-radius: 5px;
    background: var(--bg-elevated);
    color: var(--text);
  }
</style>
