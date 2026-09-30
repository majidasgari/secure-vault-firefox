/*
 * Test-only bridge into the content script.
 *
 * The icon and the dropdown live in a *closed* Shadow DOM on purpose (a page must not be able to
 * click an entry on the user's behalf). The harness therefore patches `attachShadow` first: it
 * keeps the roots it saw, so the driver can ask for real coordinates and dispatch real mouse
 * clicks at them over CDP — the click still arrives the way a user's click would.
 */
(function () {
  "use strict";

  const roots = [];
  const original = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) {
    const root = original.call(this, Object.assign({}, init, { mode: "open" }));
    roots.push(root);
    return root;
  };

  /** The rect of an element in viewport coordinates plus its centre. */
  function box(element) {
    if (!element || !element.isConnected) return null;
    const rect = element.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) return null;
    return {
      x: Math.round(rect.left + rect.width / 2),
      y: Math.round(rect.top + rect.height / 2),
      left: Math.round(rect.left),
      top: Math.round(rect.top),
      width: Math.round(rect.width),
      height: Math.round(rect.height)
    };
  }

  function shadowElements(selector) {
    const found = [];
    roots.forEach((root) => {
      root.querySelectorAll(selector).forEach((element) => found.push(element));
    });
    return found;
  }

  const probe = {
    ready: false,
    roots: roots,
    icons() {
      return shadowElements("button.icon")
        .filter((element) => !element.hidden)
        .map((element) => Object.assign({ title: element.title }, box(element)));
    },
    items() {
      return shadowElements("button.item").map((element) =>
        Object.assign({ text: element.textContent.trim(), path: element.dataset ? element.dataset.path : "" }, box(element))
      );
    },
    panelText() {
      return shadowElements("div.panel")
        .map((element) => element.textContent.trim())
        .join(" | ");
    },
    buttons() {
      return shadowElements("button.ghost").map((element) => Object.assign({ text: element.textContent.trim() }, box(element)));
    },
    values() {
      const read = (id) => {
        const field = document.getElementById(id);
        return field ? field.value : null;
      };
      return { user: read("user"), pass: read("pass"), otp: read("otp") };
    },
    events() {
      return window.__events || null;
    },
    sent() {
      return (window.__sent || []).map((message) => ({ type: message.type, path: message.path || "" }));
    },
    sentRaw() {
      return JSON.stringify(window.__sent || []);
    },
    /** Does this secret appear anywhere outside the input values? */
    leak(secret) {
      const text = String(secret || "");
      if (!text) return "no-secret-given";
      const found = [];
      const html = document.documentElement.outerHTML;
      if (html.indexOf(text) >= 0) found.push("outerHTML");
      if (probe.sentRaw().indexOf(text) >= 0) found.push("messages");
      Array.prototype.forEach.call(document.querySelectorAll("*"), (element) => {
        Array.prototype.forEach.call(element.attributes || [], (attribute) => {
          if (String(attribute.value).indexOf(text) >= 0) found.push(element.tagName + "@" + attribute.name);
        });
      });
      const storage = JSON.stringify(Object.keys(window.sessionStorage).map((key) => window.sessionStorage.getItem(key)));
      if (storage.indexOf(text) >= 0) found.push("storage");
      return found.length ? found.join(",") : "";
    },
    form() {
      const field = document.getElementById("pass");
      const forms = globalThis.SecureVaultContentCore.findLoginForms(document);
      return {
        forms: forms.length,
        username: Boolean(forms[0] && forms[0].username),
        otp: Boolean(forms[0] && forms[0].otp),
        passwordIsField: Boolean(forms[0] && forms[0].password === field)
      };
    }
  };

  window.__probe = probe;

  // The content script initialises on load; sweep once more so the first icon exists before the
  // driver starts asking for coordinates.
  window.addEventListener("load", function () {
    window.setTimeout(function () {
      try {
        globalThis.SecureVaultContentCore.sweep();
      } catch (error) {
        window.__probeError = String(error && error.message);
      }
      probe.ready = true;
    }, 120);
  });
})();
