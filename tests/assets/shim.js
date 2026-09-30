/*
 * Test-only shim for the `browser.*` API surface the add-on uses.
 *
 * The aim is to run the *real* background.js and the *real* content script in a plain page: the
 * shim connects their message ports to each other and lets the client's `fetch` go to the real
 * vault (the harness browser is started with web security off, exactly so a page can talk to the
 * loopback bridge).
 */
(function () {
  "use strict";

  const store = {
    get(defaults) {
      const out = Object.assign({}, defaults || {});
      Object.keys(out).forEach((key) => {
        const raw = window.sessionStorage.getItem("svb:" + key);
        if (raw !== null) out[key] = JSON.parse(raw);
      });
      // The harness points the add-on at the scratch vault (which listens on a random port);
      // nothing is stored, so this is also what the "port" preference looks like on first run.
      if (window.SVB_VAULT_PORT && window.sessionStorage.getItem("svb:port") === null) {
        out.port = Number(window.SVB_VAULT_PORT);
      }
      return Promise.resolve(out);
    },
    set(values) {
      Object.entries(values || {}).forEach((entry) => {
        window.sessionStorage.setItem("svb:" + entry[0], JSON.stringify(entry[1]));
      });
      return Promise.resolve();
    }
  };

  const listeners = [];
  const commands = [];
  const tabListeners = [];
  window.__sent = [];

  function dispatch(message, sender) {
    // A page/content script always has a tab; the background takes the host from `sender.url`.
    const from = sender || {
      id: "secure-vault-browser@maxv.local",
      url: window.location.href,
      tab: { id: 1, url: window.location.href }
    };
    for (const listener of listeners) {
      const result = listener(message, from);
      if (result !== undefined) return Promise.resolve(result);
    }
    return Promise.resolve(undefined);
  }

  window.browser = {
    runtime: {
      id: "secure-vault-browser@maxv.local",
      getURL: (path) => path,
      onMessage: {
        addListener: (listener) => listeners.push(listener)
      },
      sendMessage: (message) => {
        window.__sent.push(JSON.parse(JSON.stringify(message)));
        return dispatch(message);
      }
    },
    storage: { local: store },
    action: {
      setBadgeText: () => Promise.resolve(),
      setBadgeBackgroundColor: () => Promise.resolve(),
      setTitle: () => Promise.resolve()
    },
    commands: {
      onCommand: { addListener: (listener) => commands.push(listener) }
    },
    tabs: {
      query: () => Promise.resolve([{ id: 1, url: window.location.href }]),
      create: (options) => Promise.resolve({ id: 2, url: options && options.url }),
      sendMessage: (tabId, message) => dispatch(message),
      onUpdated: { addListener: (listener) => tabListeners.push(listener) }
    }
  };
})();
