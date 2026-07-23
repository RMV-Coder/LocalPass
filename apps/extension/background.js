// SPDX-License-Identifier: MPL-2.0
//
// LocalPass extension — background service worker.
//
// Owns a single persistent native-messaging port to `com.localpass.host` and
// bridges request/response calls from the popup. The popup sends
//   { cmd: "host", payload: { v: 1, type: "..." } }
// and receives the host's JSON reply through sendResponse.
//
// The native host runs a persistent stdio loop, so we use connectNative (a
// long-lived Port), NOT one-shot sendNativeMessage. Chrome frames messages with
// a u32 length prefix automatically; we post/receive plain JSON objects.

"use strict";

const HOST_NAME = "com.localpass.host";

// The live port, or null when disconnected. Reconnected lazily on next request.
let port = null;

// Monotonic request id -> { resolve, reject, timer }. The host protocol is a
// simple request/response, but the port is async, so we correlate replies to
// pending requests in FIFO order (the host answers one request at a time).
let nextId = 1;
const pending = new Map();

// Queue of pending ids in send order, so an incoming reply (which carries no id)
// maps to the oldest outstanding request.
const inflight = [];

// How long to wait for a host reply before giving up (ms).
const REQUEST_TIMEOUT_MS = 10000;

/**
 * Connect (or reconnect) the native port. Returns the live port, or throws a
 * clean Error if the host cannot be launched (e.g. not registered yet).
 */
function ensurePort() {
  if (port) return port;

  let p;
  try {
    p = chrome.runtime.connectNative(HOST_NAME);
  } catch (e) {
    // connectNative itself rarely throws synchronously, but guard anyway.
    throw new Error(hostUnavailableMessage());
  }

  p.onMessage.addListener((msg) => {
    // Replies arrive in the order requests were sent. Resolve the oldest.
    const id = inflight.shift();
    if (id === undefined) return; // unsolicited message; ignore
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    clearTimeout(entry.timer);
    entry.resolve(msg);
  });

  p.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    // lastError is expected here (e.g. host not found / exited); log for debug.
    console.warn(
      "[LocalPass] native host disconnected:",
      err && err.message ? err.message : "(no error detail)"
    );
    port = null;
    // Fail every outstanding request cleanly; the popup shows a friendly error.
    const message = hostUnavailableMessage();
    for (const id of inflight.splice(0)) {
      const entry = pending.get(id);
      if (entry) {
        pending.delete(id);
        clearTimeout(entry.timer);
        entry.reject(new Error(message));
      }
    }
  });

  port = p;
  return port;
}

function hostUnavailableMessage() {
  return "native host unavailable — is LocalPass installed and registered?";
}

/**
 * Send one request to the host and resolve with its JSON reply.
 * Rejects on disconnect or timeout.
 */
function hostRequest(payload) {
  return new Promise((resolve, reject) => {
    let activePort;
    try {
      activePort = ensurePort();
    } catch (e) {
      reject(e);
      return;
    }

    const id = nextId++;
    const timer = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        const idx = inflight.indexOf(id);
        if (idx !== -1) inflight.splice(idx, 1);
        reject(new Error("native host timed out"));
      }
    }, REQUEST_TIMEOUT_MS);

    pending.set(id, { resolve, reject, timer });
    inflight.push(id);

    try {
      activePort.postMessage(payload);
    } catch (e) {
      // postMessage throws if the port died between ensurePort() and here.
      pending.delete(id);
      const idx = inflight.indexOf(id);
      if (idx !== -1) inflight.splice(idx, 1);
      clearTimeout(timer);
      port = null;
      reject(new Error(hostUnavailableMessage()));
    }
  });
}

// Bridge: popup -> host -> popup. Always call sendResponse exactly once.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.cmd !== "host") {
    sendResponse({ ok: false, error: "bad_request" });
    return false; // synchronous
  }

  const payload = message.payload;
  if (!payload || payload.v !== 1 || typeof payload.type !== "string") {
    sendResponse({ ok: false, error: "bad_request" });
    return false;
  }

  hostRequest(payload)
    .then((reply) => sendResponse({ ok: true, reply }))
    .catch((err) =>
      sendResponse({
        ok: false,
        error: err && err.message ? err.message : "native host error",
      })
    );

  return true; // keep the message channel open for the async sendResponse
});
