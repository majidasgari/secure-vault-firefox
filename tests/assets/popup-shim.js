/*
 * Test-only shim for the popup: answers the four messages the popup sends, and records what it
 * asks the tab to do. The popup's own scripts (popup.js, popup.css, popup.html) are unmodified.
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
