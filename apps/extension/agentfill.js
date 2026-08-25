// SPDX-License-Identifier: MPL-2.0
//
// LocalPass extension — agent-triggered autofill (docs/specs/agent-fill.md).
//
// An AI agent asks the daemon (over MCP) to ARM a single-use fill intent. The
// daemon cannot call into the browser — native messaging is browser-initiated —
// so the extension PULLS: while the arm window is open it polls
// `take_fill_intent` about once a second, and not at all otherwise (§5.1).
//
// Redeeming an intent reuses the ordinary `fill` request, unchanged: the
// credential path still ends only in the extension, and the intent itself
// carries nothing but ids, a tab id and an origin.
//
// # What never crosses back out
//
// The extension decides whether each target field was empty before the fill and
// non-empty after, and reports only `empty` / `filled` (§3). No value, length,
// prefix or hash is reported, logged, or returned — the report type on the Rust
// side has no string field at all, so a body carrying one fails to parse.
//
// # Service-worker lifetime
//
// MV3 kills an idle worker. Two mechanisms, deliberately separate:
//
//   * WHILE ARMED — the once-a-second `take_fill_intent` round trip is port
//     activity, which keeps the worker alive for the whole window. Nothing here
//     relies on the worker surviving idle.
//   * WHILE DISARMED — nothing polls, so the worker dies, and something has to
//     wake it to notice that a window has since opened. That is a
//     `chrome.alarms` heartbeat which wakes the worker, issues ONE `status`, and
//     arms the poller if `agent_fill_secs` says so. Status replies flowing
//     through the popup bridge feed the same path for free, so opening the popup
//     also picks up an open window immediately.
//
// The heartbeat backs off when the daemon is unreachable, so a browser running
// without LocalPass does not relaunch the native host every 30 seconds.

"use strict";

(function () {
  // --- Tunables ------------------------------------------------------------

  /** Intent poll interval while armed (§5.1: "about once a second"). */
  const POLL_MS = 1000;

  /** Re-read `status` every N polls, to notice a window closed early. */
  const STATUS_EVERY_POLLS = 15;

  /** Heartbeat period while disarmed, in minutes (Chrome clamps small values). */
  const HEARTBEAT_MINUTES = 0.5;

  /** Backoff ladder (ms) for the heartbeat when the host/daemon is unreachable. */
  const BACKOFF_LADDER_MS = [0, 60e3, 5 * 60e3, 15 * 60e3];

  /** Consecutive poll failures before we give up and fall back to the heartbeat. */
  const MAX_POLL_FAILURES = 3;

  const ALARM_NAME = "lp-agent-fill-heartbeat";

  /** Host permissions required to inject into a tab we were not clicked on. */
  const FILL_ORIGINS = ["http://*/*", "https://*/*"];

  // --- Injected dependencies ----------------------------------------------

  /** Set by init(): (payload) => Promise<reply>. */
  let hostRequest = null;

  // --- Arm-window state ----------------------------------------------------

  let armed = false;
  let armedUntilMs = 0;
  let pollTimer = null;
  let pollsSinceStatus = 0;
  let pollFailures = 0;
  /** True while a poll or a redemption is in flight (never two at once). */
  let busy = false;
  let backoffStep = 0;
  let backoffUntilMs = 0;

  // --- Small helpers -------------------------------------------------------

  /** The origin of a URL string, or null if it is not an http(s) URL. */
  function originOf(url) {
    if (typeof url !== "string" || url === "") return null;
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      return null;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  }

  function sameOrigin(a, b) {
    const oa = originOf(a);
    const ob = originOf(b);
    return oa !== null && ob !== null && oa === ob;
  }

  // --- The arm window ------------------------------------------------------

  /**
   * Feed a host `status` reply in. The single entry point for learning whether
   * the agent-fill window is open: `agent_fill_secs` is a number of whole
   * seconds while armed, and null/absent when off (§7).
   */
  function noteStatus(reply) {
    if (!reply || reply.type !== "status") return;
    const secs = reply.agent_fill_secs;
    if (typeof secs === "number" && secs > 0 && reply.locked !== true) {
      arm(secs);
    } else {
      disarm("window closed");
    }
  }

  function arm(secs) {
    armedUntilMs = Date.now() + secs * 1000;
    if (armed) return; // already polling; just extended the deadline
    armed = true;
    pollFailures = 0;
    pollsSinceStatus = 0;
    console.info("[LocalPass] agent-fill armed for", secs, "s — polling");
    schedulePoll(0);
  }

  /**
   * Stop polling. Idempotent, and it really stops: the timer is cleared AND
   * `armed` goes false, which every scheduling path re-checks before it runs.
   * Nothing re-enters the poll loop except arm().
   */
  function disarm(why) {
    if (pollTimer !== null) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    if (!armed) return;
    armed = false;
    armedUntilMs = 0;
    console.info("[LocalPass] agent-fill disarmed:", why);
  }

  function schedulePoll(delayMs) {
    if (pollTimer !== null) clearTimeout(pollTimer);
    pollTimer = null;
    if (!armed) return;
    pollTimer = setTimeout(() => {
      pollTimer = null;
      pollOnce();
    }, delayMs);
  }

  async function pollOnce() {
    if (!armed) return;

    // Local deadline: the window lapsed as far as we can tell. Stop polling
    // first, then take exactly one status read, which re-arms if the user
    // extended or re-opened the window.
    if (Date.now() >= armedUntilMs) {
      disarm("window lapsed");
      await refreshStatus();
      return;
    }

    if (busy) {
      schedulePoll(POLL_MS);
      return;
    }
    busy = true;
    try {
      // Periodically re-read status so a window the user closed early stops the
      // poll promptly rather than running to its original deadline.
      if (pollsSinceStatus >= STATUS_EVERY_POLLS) {
        pollsSinceStatus = 0;
        const ok = await refreshStatus();
        if (!ok || !armed) return;
      }
      pollsSinceStatus++;

      let reply;
      try {
        reply = await hostRequest({ v: 1, type: "take_fill_intent" });
        pollFailures = 0;
      } catch (err) {
        pollFailures++;
        if (pollFailures >= MAX_POLL_FAILURES) {
          disarm("host unreachable");
          noteHostFailure();
          return;
        }
        return;
      }

      if (reply && reply.type === "fill_intent") {
        await redeem(reply);
      } else if (reply && reply.type === "locked") {
        // A locked daemon refuses every credential path (§7). Stop; the
        // heartbeat picks the window back up once it is unlocked.
        disarm("daemon locked");
      }
      // `no_fill_intent` — what almost every poll gets — falls through.
    } finally {
      busy = false;
      schedulePoll(POLL_MS);
    }
  }

  // --- Heartbeat while disarmed -------------------------------------------

  /** One `status` request; feeds noteStatus. Returns false if the host failed. */
  async function refreshStatus() {
    let reply;
    try {
      reply = await hostRequest({ v: 1, type: "status" });
    } catch (err) {
      noteHostFailure();
      return false;
    }
    if (reply && reply.type === "status" && reply.available === false) {
      noteHostFailure();
      disarm("daemon unavailable");
      return false;
    }
    backoffStep = 0;
    backoffUntilMs = 0;
    noteStatus(reply);
    return true;
  }

  function noteHostFailure() {
    if (backoffStep < BACKOFF_LADDER_MS.length - 1) backoffStep++;
    backoffUntilMs = Date.now() + BACKOFF_LADDER_MS[backoffStep];
  }

  function onHeartbeat() {
    if (armed) return; // the poll loop already owns the port
    if (Date.now() < backoffUntilMs) return; // host is down; stay quiet
    void refreshStatus();
  }

  // --- Redemption ----------------------------------------------------------

  /**
   * Resolve the intent's target tab (§6).
   *
   * Tab id first — unambiguous when several tabs share an origin, which is
   * exactly when an origin-only rule is loosest. With no tab id, EXACTLY ONE
   * tab must match the origin; several is `ambiguous_tab`, never "pick the
   * first match".
   *
   * Resolves to `{ tabId }` or `{ refusal }`.
   */
  async function resolveTarget(intent) {
    if (typeof intent.tab_id === "number") {
      let tab;
      try {
        tab = await chrome.tabs.get(intent.tab_id);
      } catch (e) {
        return { refusal: "tab_not_found" };
      }
      if (!tab || typeof tab.id !== "number") return { refusal: "tab_not_found" };
      // The tab's CURRENT origin, not the one it had when the intent was armed.
      if (!sameOrigin(tab.url, intent.origin)) return { refusal: "origin_changed" };
      return { tabId: tab.id };
    }

    let tabs;
    try {
      tabs = await chrome.tabs.query({});
    } catch (e) {
      return { refusal: "tab_not_found" };
    }
    const matches = (tabs || []).filter(
      (t) => typeof t.id === "number" && sameOrigin(t.url, intent.origin)
    );
    if (matches.length === 0) return { refusal: "tab_not_found" };
    if (matches.length > 1) return { refusal: "ambiguous_tab" };
    return { tabId: matches[0].id };
  }

  /**
   * Runs in the PAGE (via chrome.scripting.executeScript). Self-contained — it
   * may not reference anything from this scope.
   *
   * Two modes, so the same field-finding heuristic serves both:
   *   * PROBE (password === null): report the fields' `empty`/`filled` state and
   *     change nothing.
   *   * FILL: refuse if a target field is already non-empty and `overwrite` is
   *     not set (§8), otherwise set the values, dispatch input+change, and
   *     report the after state.
   *
   * NEVER submits the form, and NEVER returns a value, a length, a prefix or a
   * hash — `empty` / `filled` is the entire vocabulary (§3, §8).
   *
   * Deliberately duplicates popup.js's field heuristic: an injected function is
   * serialized on its own and cannot share code across the boundary.
   */
  function lpFillInPage(username, password, overwrite) {
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

    // The one place a value is inspected — and only its emptiness, which is all
    // that ever leaves this function.
    function stateOf(el) {
      return el && typeof el.value === "string" && el.value.length > 0
        ? "filled"
        : "empty";
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
      return { ok: false, reason: "no_login_form", before: {}, after: {}, fields: [] };
    }

    const pwField = pwFields[0];

    const userSelector =
      'input[type="text"], input[type="email"], input[type="tel"], ' +
      'input[type="username"], input:not([type])';

    let userField = null;

    const form = pwField.form;
    if (form) {
      const inForm = Array.from(form.querySelectorAll(userSelector)).filter(
        isVisible
      );
      const pwIndexEls = Array.from(form.elements);
      const pwPos = pwIndexEls.indexOf(pwField);
      for (let i = inForm.length - 1; i >= 0; i--) {
        const cand = inForm[i];
        if (pwIndexEls.indexOf(cand) < pwPos) {
          userField = cand;
          break;
        }
      }
      if (!userField && inForm.length > 0) userField = inForm[0];
    }

    if (!userField) {
      const anyUser = Array.from(document.querySelectorAll(userSelector)).filter(
        isVisible
      );
      if (anyUser.length > 0) userField = anyUser[0];
    }

    const willFillUser = !!userField && typeof username === "string";

    const before = { password: stateOf(pwField) };
    if (userField) before.username = stateOf(userField);

    // Probe mode: look, do not touch.
    if (typeof password !== "string") {
      return { ok: true, reason: null, before: before, after: {}, fields: [] };
    }

    // Refuse rather than clobber (§8). Re-checked here, in the page, so a value
    // the user typed after the probe is still protected.
    if (overwrite !== true) {
      if (
        before.password === "filled" ||
        (willFillUser && before.username === "filled")
      ) {
        return {
          ok: false,
          reason: "field_not_empty",
          before: before,
          after: {},
          fields: [],
        };
      }
    }

    const fields = [];
    if (willFillUser) {
      setNativeValue(userField, username);
      fields.push("username");
    }
    setNativeValue(pwField, password);
    fields.push("password");
    pwField.focus();
    // No submit, ever: values set, input+change dispatched, stop.

    const after = { password: stateOf(pwField) };
    if (userField) after.username = stateOf(userField);

    return { ok: true, reason: null, before: before, after: after, fields: fields };
  }

  /** Inject lpFillInPage into `tabId`. Resolves to its result, or null. */
  async function injectFill(tabId, username, password, overwrite) {
    let injection;
    try {
      injection = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: lpFillInPage,
        args: [username, password, overwrite === true],
      });
    } catch (e) {
      return null;
    }
    return injection && injection[0] ? injection[0].result : null;
  }

  /** Whether we may inject into a tab we were never clicked on. */
  async function hasFillPermission() {
    try {
      return await chrome.permissions.contains({ origins: FILL_ORIGINS });
    } catch (e) {
      return false;
    }
  }

  /**
   * Take one intent through to a reported outcome.
   *
   * Order matters: every check that can refuse is made BEFORE the credential is
   * requested, so a refused fill never causes a disclosure. The target origin is
   * then re-verified immediately before injection, because the tab can navigate
   * while the daemon is answering.
   */
  async function redeem(intent) {
    const itemId = typeof intent.item_id === "string" ? intent.item_id : null;
    const origin = originOf(intent.origin);
    if (itemId === null || origin === null) {
      console.warn("[LocalPass] agent-fill: malformed intent; ignoring");
      return;
    }
    const overwrite = intent.overwrite === true;

    // 1. Target checks (§6).
    const target = await resolveTarget(intent);
    if (target.refusal) {
      await finish(itemId, origin, refused(target.refusal, {}));
      return;
    }
    const tabId = target.tabId;

    if (!(await hasFillPermission())) {
      // No §10 code covers this — see the README. Report a plain "did not
      // land" and say why in the notification, which the user does see.
      await finish(
        itemId,
        origin,
        { filled: false, fields: [], before: {}, after: {} },
        "needs page access — enable it from the LocalPass popup"
      );
      return;
    }

    // 2. Probe the page before asking for anything secret.
    const probe = await injectFill(tabId, null, null, overwrite);
    if (!probe) {
      await finish(itemId, origin, refused("no_login_form", {}));
      return;
    }
    if (probe.ok === false) {
      await finish(itemId, origin, refused(probe.reason || "no_login_form", probe.before));
      return;
    }
    if (!overwrite) {
      const b = probe.before || {};
      if (b.password === "filled" || b.username === "filled") {
        await finish(itemId, origin, refused("field_not_empty", b));
        return;
      }
    }

    // 3. The credential. The existing request, unchanged; the daemon re-checks
    //    the item's URL against this origin server-side.
    let fill;
    try {
      fill = await hostRequest({ v: 1, type: "fill", item_id: itemId, origin: origin });
    } catch (err) {
      await finish(itemId, origin, { filled: false, fields: [], before: probe.before, after: {} });
      return;
    }
    if (!fill || fill.type !== "fill") {
      const reason =
        fill && fill.type === "locked"
          ? "locked"
          : fill && fill.type === "error" && fill.error === "origin_mismatch"
            ? "origin_mismatch"
            : null;
      await finish(
        itemId,
        origin,
        reason
          ? refused(reason, probe.before)
          : { filled: false, fields: [], before: probe.before, after: {} }
      );
      return;
    }

    // 4. Re-check the target between fetch and injection: a tab that navigated
    //    while the daemon answered must not receive the credential.
    const recheck = await resolveTarget(intent);
    if (recheck.refusal || recheck.tabId !== tabId) {
      await finish(itemId, origin, refused(recheck.refusal || "origin_changed", probe.before));
      return;
    }

    const result = await injectFill(tabId, fill.username, fill.password, overwrite);
    // `fill` goes out of scope here; nothing retains it, logs it, or reports it.

    if (!result) {
      await finish(itemId, origin, refused("no_login_form", probe.before));
      return;
    }
    if (result.ok === false) {
      await finish(itemId, origin, refused(result.reason || "no_login_form", result.before));
      return;
    }

    await finish(itemId, origin, {
      filled: true,
      fields: Array.isArray(result.fields) ? result.fields : [],
      before: result.before || {},
      after: result.after || {},
    });
  }

  /** A refusal report: closed reason code, closed before-states, nothing else. */
  function refused(reason, before) {
    return {
      filled: false,
      fields: [],
      before: before || {},
      after: {},
      reason: reason,
    };
  }

  // --- Outcome: report + notify -------------------------------------------

  /**
   * Report the outcome to the daemon (§9 audit) and raise the user-visible
   * notification (§9), which is the compensating control for the missing user
   * click and so is never skipped — not even for a refusal.
   */
  async function finish(itemId, origin, report, extraNote) {
    try {
      await hostRequest({
        v: 1,
        type: "fill_outcome",
        item_id: itemId,
        outcome: report,
      });
    } catch (err) {
      console.warn("[LocalPass] agent-fill: could not report the outcome");
    }
    await notify(itemId, origin, report, extraNote);
  }

  /**
   * Best-effort lookup of an item's title for the notification. Non-secret: the
   * same candidate list the popup shows. Falls back to the item id.
   */
  async function titleFor(itemId, origin) {
    try {
      const reply = await hostRequest({
        v: 1,
        type: "credentials_for",
        origin: origin,
        kind: "login",
      });
      if (reply && reply.type === "credentials" && Array.isArray(reply.candidates)) {
        const hit = reply.candidates.find((c) => c && c.item_id === itemId);
        if (hit && hit.title) return hit.title;
      }
    } catch (e) {
      /* fall through */
    }
    return itemId;
  }

  /**
   * Raise the notification. Names the item and the origin — never the value,
   * and never the `empty`/`filled` states either, which the user does not need.
   *
   * If `chrome.notifications` is missing or fails, fall back to the toolbar
   * badge so the fill is still not silent.
   */
  async function notify(itemId, origin, report, extraNote) {
    const title = await titleFor(itemId, origin);
    const headline = report.filled
      ? "LocalPass filled a login"
      : "LocalPass refused an agent fill";
    let message = (report.filled ? "Filled " : "Did not fill ") + title + " on " + origin;
    if (!report.filled) {
      if (report.reason) message += " — " + report.reason;
      if (extraNote) message += " — " + extraNote;
    }
    message += "\nRequested by an agent while agent fill was armed.";

    let raised = false;
    try {
      if (chrome.notifications && chrome.notifications.create) {
        await chrome.notifications.create("", {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
          title: headline,
          message: message,
          priority: 2,
        });
        raised = true;
      }
    } catch (e) {
      raised = false;
    }

    if (!raised) {
      // The notification permission is missing or the API failed. A fill must
      // never be silent, so fall back to something the user can still see.
      try {
        await chrome.action.setBadgeText({ text: report.filled ? "1" : "!" });
        await chrome.action.setBadgeBackgroundColor({
          color: report.filled ? "#0f766e" : "#b91c1c",
        });
        await chrome.action.setTitle({ title: "LocalPass — " + message });
      } catch (e) {
        /* nothing else to try */
      }
    }
  }

  // --- Wiring --------------------------------------------------------------

  function init(deps) {
    hostRequest = deps.hostRequest;

    chrome.alarms.create(ALARM_NAME, { periodInMinutes: HEARTBEAT_MINUTES });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm && alarm.name === ALARM_NAME) onHeartbeat();
    });

    // Wake-ups that cost nothing: worker start, browser start, install.
    if (chrome.runtime.onStartup) {
      chrome.runtime.onStartup.addListener(() => void refreshStatus());
    }
    if (chrome.runtime.onInstalled) {
      chrome.runtime.onInstalled.addListener(() => {
        chrome.alarms.create(ALARM_NAME, { periodInMinutes: HEARTBEAT_MINUTES });
        void refreshStatus();
      });
    }
    void refreshStatus();
  }

  self.lpAgentFill = {
    init: init,
    // Fed every `status` reply that passes through the popup bridge, so opening
    // the popup notices an open window with no extra traffic.
    noteStatus: noteStatus,
    // Exposed for reasoning/debugging only.
    _state: () => ({ armed: armed, armedUntilMs: armedUntilMs }),
  };
})();
