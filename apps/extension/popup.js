// SPDX-License-Identifier: MPL-2.0
//
// LocalPass extension — popup UI logic.
//
// Flow on open:
//   1. Resolve the active tab -> its page origin.
//   2. Ask the host for `status`.
//        available:false      -> "start the desktop app"
//        locked:true          -> "unlock LocalPass"
//        unlocked             -> ask `credentials_for` and render candidates.
//   3. On a candidate click, ask `fill` for that one item, then inject the
//      username/password into the active tab via chrome.scripting. Never submit.
//
// The password returned by `fill` is used transiently to build the injection
// call and is never stored, logged, or retained in any global.

"use strict";

// --- DOM handles -----------------------------------------------------------

const stateEl = document.getElementById("lp-state");
const listEl = document.getElementById("lp-list");
const originEl = document.getElementById("lp-origin");
const refreshBtn = document.getElementById("lp-refresh");

// --- Active-tab context ----------------------------------------------------

let activeTabId = null;
let pageOrigin = null; // e.g. "https://example.com"
let pageHost = null; // e.g. "example.com"

// --- Host bridge -----------------------------------------------------------

/**
 * Send a request to the background service worker, which relays it to the
 * native host. Resolves with the host's JSON reply, or throws a clean Error.
 */
function callHost(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ cmd: "host", payload }, (res) => {
      const lastErr = chrome.runtime.lastError;
      if (lastErr) {
        reject(new Error(lastErr.message || "extension messaging error"));
        return;
      }
      if (!res || !res.ok) {
        reject(new Error((res && res.error) || "native host error"));
        return;
      }
      resolve(res.reply);
    });
  });
}

// --- Rendering helpers -----------------------------------------------------

function showMessage(text, opts) {
  const isError = opts && opts.error;
  listEl.hidden = true;
  listEl.replaceChildren();
  stateEl.hidden = false;

  const p = document.createElement("p");
  p.className = isError ? "lp-msg lp-error" : "lp-msg";
  // Support an optional bold lead line.
  if (opts && opts.lead) {
    const strong = document.createElement("strong");
    strong.textContent = opts.lead;
    p.appendChild(strong);
    p.appendChild(document.createElement("br"));
  }
  p.appendChild(document.createTextNode(text));
  stateEl.replaceChildren(p);
}

function renderCandidates(candidates) {
  stateEl.hidden = true;
  listEl.replaceChildren();
  listEl.hidden = false;

  for (const c of candidates) {
    const li = document.createElement("li");

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "lp-item";

    const main = document.createElement("span");
    main.className = "lp-item-main";

    const title = document.createElement("div");
    title.className = "lp-item-title";
    title.textContent = c.title || "(untitled)";

    const user = document.createElement("div");
    user.className = "lp-item-user";
    user.textContent = c.username || "";

    main.appendChild(title);
    main.appendChild(user);

    const tag = document.createElement("span");
    tag.className = "lp-tag";
    tag.textContent = c.vault || "";

    const hint = document.createElement("span");
    hint.className = "lp-fill-hint";
    hint.textContent = "Fill";

    btn.appendChild(main);
    if (c.vault) btn.appendChild(tag);
    btn.appendChild(hint);

    btn.addEventListener("click", () => onFill(c.item_id));

    li.appendChild(btn);
    listEl.appendChild(li);
  }
}

// --- Fill injection --------------------------------------------------------

/**
 * Runs in the PAGE (injected via chrome.scripting.executeScript). Self-contained
 * — it may not reference anything from the popup's scope.
 *
 * Finds the best visible password field, then the best matching username field
 * (a visible text/email input in the same form, preceding the password field;
 * else the first visible text/email input on the page). Sets values through the
 * native setter and dispatches input+change so frameworks (React, Vue, …) react.
 * Never submits the form. Does not log the password.
 *
 * Returns a small status object the popup can display.
 */
function fillCredentials(username, password) {
  function isVisible(el) {
    if (!el) return false;
    if (el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.visibility === "collapse" ||
      parseFloat(style.opacity) === 0
    ) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function setNativeValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && typeof desc.set === "function") {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  const pwFields = Array.from(
    document.querySelectorAll('input[type="password"]')
  ).filter(isVisible);

  if (pwFields.length === 0) {
    return { filled: false, reason: "no_password_field" };
  }

  const pwField = pwFields[0];

  // Candidate username inputs: visible text/email/tel or unspecified-type text.
  const userSelector =
    'input[type="text"], input[type="email"], input[type="tel"], ' +
    'input[type="username"], input:not([type])';

  let userField = null;

  // Prefer a candidate within the same form, appearing before the password.
  const form = pwField.form;
  if (form) {
    const inForm = Array.from(form.querySelectorAll(userSelector)).filter(
      isVisible
    );
    const pwIndexEls = Array.from(form.elements);
    const pwPos = pwIndexEls.indexOf(pwField);
    // Walk backwards from the password to find the nearest preceding text input.
    for (let i = inForm.length - 1; i >= 0; i--) {
      const cand = inForm[i];
      if (pwIndexEls.indexOf(cand) < pwPos) {
        userField = cand;
        break;
      }
    }
    if (!userField && inForm.length > 0) {
      userField = inForm[0];
    }
  }

  // Fall back to the first visible text/email input anywhere on the page.
  if (!userField) {
    const anyUser = Array.from(document.querySelectorAll(userSelector)).filter(
      isVisible
    );
    if (anyUser.length > 0) userField = anyUser[0];
  }

  if (userField && typeof username === "string") {
    setNativeValue(userField, username);
  }
  setNativeValue(pwField, password);
  pwField.focus();

  return { filled: true, username: !!userField };
}

async function onFill(itemId) {
  try {
    const reply = await callHost({
      v: 1,
      type: "fill",
      item_id: itemId,
      origin: pageOrigin,
    });

    if (reply.type === "locked") {
      showMessage("Vault locked — unlock LocalPass to autofill.", {
        lead: "Locked",
      });
      return;
    }
    if (reply.type === "error") {
      if (reply.error === "origin_mismatch") {
        showMessage(
          "This saved login is registered for a different site, so LocalPass won't fill it here.",
          { lead: "Origin mismatch", error: true }
        );
      } else {
        showMessage(reply.message || "Couldn't fetch the credential.", {
          error: true,
        });
      }
      return;
    }
    if (reply.type !== "fill") {
      showMessage("Unexpected response from LocalPass.", { error: true });
      return;
    }

    if (activeTabId == null) {
      showMessage("No active tab to fill.", { error: true });
      return;
    }

    let injection;
    try {
      injection = await chrome.scripting.executeScript({
        target: { tabId: activeTabId },
        func: fillCredentials,
        args: [reply.username, reply.password],
      });
    } catch (e) {
      showMessage(
        "Couldn't inject into this page. It may be a restricted page (e.g. chrome:// or the Web Store).",
        { error: true }
      );
      return;
    }

    const result =
      injection && injection[0] ? injection[0].result : { filled: false };

    if (result && result.filled) {
      showMessage("Filled ✓", { lead: "Done" });
      setTimeout(() => window.close(), 700);
    } else {
      showMessage("No login fields found on this page.", { error: true });
    }
  } catch (err) {
    showMessage(friendlyError(err), { error: true });
  }
}

// --- Status / credentials flow ---------------------------------------------

function friendlyError(err) {
  const msg = err && err.message ? err.message : String(err);
  return msg;
}

async function loadForActiveTab() {
  showMessage("Checking LocalPass…");

  // Resolve active tab + origin.
  let tab;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = tabs && tabs[0];
  } catch (e) {
    tab = null;
  }

  if (!tab || !tab.url) {
    activeTabId = null;
    pageOrigin = null;
    pageHost = null;
    originEl.textContent = "—";
    showMessage("No active tab.", { error: true });
    return;
  }

  activeTabId = tab.id;

  try {
    const u = new URL(tab.url);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      pageOrigin = null;
      pageHost = null;
      originEl.textContent = u.protocol.replace(":", "");
      showMessage("LocalPass autofill works on http and https pages only.", {
        lead: "Not a website",
      });
      return;
    }
    pageOrigin = u.origin;
    pageHost = u.host;
    originEl.textContent = u.host;
    originEl.title = u.origin;
  } catch (e) {
    pageOrigin = null;
    pageHost = null;
    originEl.textContent = "—";
    showMessage("Couldn't read this tab's address.", { error: true });
    return;
  }

  // Ask the host for status.
  let status;
  try {
    status = await callHost({ v: 1, type: "status" });
  } catch (err) {
    showMessage(friendlyError(err), {
      lead: "LocalPass unavailable",
      error: true,
    });
    return;
  }

  if (!status || status.type !== "status" || status.available === false) {
    showMessage("LocalPass isn't running. Start the desktop app.", {
      lead: "Not running",
    });
    return;
  }

  if (status.locked) {
    showMessage("Vault locked — unlock LocalPass to autofill.", {
      lead: "Locked",
    });
    return;
  }

  // Unlocked: fetch candidates for this origin.
  await loadCandidates();
}

async function loadCandidates() {
  showMessage("Looking for saved logins…");

  let reply;
  try {
    reply = await callHost({
      v: 1,
      type: "credentials_for",
      origin: pageOrigin,
      kind: "login",
    });
  } catch (err) {
    showMessage(friendlyError(err), { error: true });
    return;
  }

  if (reply.type === "locked") {
    showMessage("Vault locked — unlock LocalPass to autofill.", {
      lead: "Locked",
    });
    return;
  }
  if (reply.type === "error") {
    showMessage(reply.message || "Couldn't load logins.", { error: true });
    return;
  }
  if (reply.type !== "credentials" || !Array.isArray(reply.candidates)) {
    showMessage("Unexpected response from LocalPass.", { error: true });
    return;
  }

  if (reply.candidates.length === 0) {
    showMessage("No saved logins for " + (pageHost || "this site") + ".");
    return;
  }

  renderCandidates(reply.candidates);
}

// --- Wire up ---------------------------------------------------------------

refreshBtn.addEventListener("click", () => loadForActiveTab());

// popup.js loads at the end of <body>, so the DOM is ready; but guard anyway.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", loadForActiveTab, { once: true });
} else {
  loadForActiveTab();
}
