<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Static help / quick-start guide. No daemon calls, no secret state — just
  reference content, reached from Settings (and More on a phone).
-->
<script lang="ts">
  const shortcuts: { keys: string[]; action: string }[] = [
    { keys: ["Ctrl", "K"], action: "Search (Ctrl F works too)" },
    { keys: ["Ctrl", "N"], action: "New item in this vault" },
    { keys: ["Ctrl", "L"], action: "Lock now" },
    { keys: ["↑", "↓"], action: "Move through the list" },
    { keys: ["Enter"], action: "Open an item, or copy the focused field" },
    { keys: ["Esc"], action: "Clear the search, close a dialog" },
  ];
</script>

<div class="page help">
  <div class="page-head">
    <div>
      <h2>Help</h2>
      <p class="sub">LocalPass keeps passwords, API keys, SSH keys, one-time codes and <code>.env</code> sets encrypted on this device. No cloud.</p>
    </div>
  </div>

  <div class="callout warn" role="note">
    <span><strong>Before 1.0.</strong> LocalPass has not had an external audit yet and the on-disk format may still change. Keep a copy of anything irreplaceable elsewhere.</span>
  </div>

  <section class="section">
    <h3>Everyday use</h3>
    <ul class="help-list">
      <li><strong>Copy:</strong> click any field. Copied passwords stay out of clipboard history and clear after 30 seconds.</li>
      <li><strong>Reveal:</strong> the eye on a secret field shows it in place; it hides again after 30 seconds or when you leave the item.</li>
      <li><strong>Search:</strong> searches the open vault; switch to <em>All vaults</em> to look everywhere.</li>
      <li><strong>Trash:</strong> deleted items wait at the bottom of the list for 30 days before they are gone.</li>
    </ul>
  </section>

  <section class="section">
    <h3>Keyboard</h3>
    <div class="keys">
      {#each shortcuts as s (s.action)}
        <div class="key-row">
          <span class="caps">{#each s.keys as k (k)}<kbd class="kbd">{k}</kbd>{/each}</span>
          <span>{s.action}</span>
        </div>
      {/each}
    </div>
    <p class="hint">On macOS use ⌘ instead of Ctrl.</p>
  </section>

  <section class="section">
    <h3>Item types</h3>
    <ul class="help-list">
      <li><strong>Login</strong>, <strong>Secure note</strong>, <strong>API key</strong>.</li>
      <li><strong>One-time code (TOTP):</strong> a live 6-digit code with a countdown.</li>
      <li><strong>SSH key:</strong> served by the built-in SSH agent while unlocked; the private key never leaves the service.</li>
      <li><strong>Env set:</strong> <code>KEY=value</code> variables. Its page builds a <code>localpass run</code> command that injects them into your dev server without writing a file.</li>
      <li><strong>Attachments</strong> can go on any item. Saving writes straight to the file you choose; the contents never pass through this window.</li>
    </ul>
  </section>

  <section class="section">
    <h3>Devices and sync</h3>
    <p class="body">
      <strong>Devices</strong> links another machine you own through a shared folder (Dropbox,
      Syncthing, a USB stick). Everything in the folder is encrypted and signed, so the folder
      itself does not need to be trusted. You compare a fingerprint once when you pair.
    </p>
  </section>

  <section class="section">
    <h3>Recovery</h3>
    <ul class="help-list">
      <li><strong>No reset.</strong> Your master password and Secret Key are the only way in. The Secret Key is stored on each device you use; keep your Emergency Kit offline for a new one.</li>
      <li>Lose the password, the Secret Key <em>and</em> every device, and the data is gone. That is the design.</li>
      <li>The vault locks itself after a while without use. Windows Hello (Settings) can unlock it on this device.</li>
    </ul>
    <p class="hint">More in <code>README.md</code> and <code>SECURITY.md</code> at <code>github.com/RMV-Coder/LocalPass</code>.</p>
  </section>
</div>

<style>
  .help {
    max-width: 680px;
  }
  .help h3 {
    font-size: 14px;
    margin-bottom: 6px;
  }
  .help-list {
    margin: 0;
    padding-left: 18px;
    line-height: 1.6;
  }
  .help-list li + li {
    margin-top: 4px;
  }
  .body {
    line-height: 1.6;
  }
  .keys {
    display: grid;
    gap: 6px;
  }
  .key-row {
    display: grid;
    grid-template-columns: 120px minmax(0, 1fr);
    align-items: center;
    gap: 12px;
  }
  .caps {
    display: inline-flex;
    gap: 4px;
  }
</style>
