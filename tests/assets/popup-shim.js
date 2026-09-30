/*
 * Test-only shim for the popup: answers the messages the popup sends, and records what it asks
 * the tab to do. The popup's own scripts (popup.js, popup.css, popup.html) are unmodified.
 *
 * `svb:tab-fill` and `svb:tab-probe` are the background's job in production (including injecting
 * the content script into a tab that has none); here the tab is simulated, so the shim records the
 * forward exactly as the background would make it.
 */
(function () {
  "use strict";

  window.__sent = [];
  window.__tabMessages = [];

  const STATUS = {
    ok: true,
    port: Number(window.SVB_VAULT_PORT || 8788),
    status: { enabled: true, locked: false, index: { entries: 137, passwords: 131, usernames: 128 } }
  };

  const CANDIDATES = {
    ok: true,
    host: window.location.hostname,
    candidates: [
      {
        path: "/رمزها/آزمون/دمو سایت/demo.md",
        title: "دمو سایت",
        site: "127.0.0.1",
        username: "demo-user@example.com",
        has_password: true,
        has_otp: true
      }
    ],
    entries: 137
  };

  window.browser = {
    runtime: {
      sendMessage(message) {
        window.__sent.push(message);
        if (message.type === "svb:status") return Promise.resolve(STATUS);
        if (message.type === "svb:candidates") return Promise.resolve(CANDIDATES);
        if (message.type === "svb:set-port") {
          return Promise.resolve({ ok: true, port: Number(message.port) });
        }
        if (message.type === "svb:tab-fill") {
          window.browser.tabs.sendMessage(message.tabId, {
            type: "svb:fill-path",
            path: message.path
          });
          return Promise.resolve({ ok: true, filled: "username+password" });
        }
        if (message.type === "svb:tab-probe") {
          return Promise.resolve({ ok: true, host: "127.0.0.1", forms: 1, fillable: true });
        }
        return Promise.resolve({ ok: true });
      }
    },
    tabs: {
      query: () => Promise.resolve([{ id: 7, url: "http://127.0.0.1/demo/login" }]),
      sendMessage: (tabId, message) => {
        window.__tabMessages.push({ tabId: tabId, message: message });
        return Promise.resolve();
      }
    }
  };

  window.__popup = {
    sent: () => window.__sent.map((message) => message.type),
    tabMessages: () => window.__tabMessages,
    ready: false
  };

  window.addEventListener("load", function () {
    // The popup renders in its own async refresh() chain; give it a tick to settle.
    window.setTimeout(function () {
      window.__popup.ready = true;
    }, 250);
  });
})();
