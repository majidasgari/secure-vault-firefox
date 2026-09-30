/*
 * Content script: find the login form, put a small vault icon in its fields, and — only when the
 * user clicks it — ask the background for the entry and write the username/password in.
 *
 * Rules that matter:
 *  - nothing is filled automatically; every fill starts from a click (or the keyboard shortcut);
 *  - no credential is stored here — it lives in this script's memory for the length of the fill
 *    and is written straight into the input;
 *  - the password never touches an attribute, a data-* field, a console log or storage;
 *  - the icon and the dropdown live in a closed Shadow DOM, so page CSS/JS cannot read or restyle
 *    them (the page can still read the input value after a fill — that is inherent to autofill).
 */
(function () {
  "use strict";

  const HOST_ID = "secure-vault-autofill-root";
  const TEXT = {
    fill: "پر کردن از گاوصندوق امن",
    title: "گاوصندوق امن",
    empty: "برای این سایت ورودی‌ای در گاوصندوق نیست.",
    filled: "نام کاربری و گذرواژه پر شد",
    filledPartial: "ورودی پر شد (این ورودی نام کاربری یا گذرواژه ندارد)",
    otpFilled: "کد یکبارمصرف هم پر شد",
    offline: "ارتباط با افزونه برقرار نشد.",
    unknown: "خطای نامشخص",
    close: "بستن"
  };

  // ------------------------------------------------------------------------- core
  /** Is this element visibly usable (so an icon next to it makes sense)? */
  function isVisible(element) {
    if (!element || element.disabled || element.readOnly) return false;
    const style = window.getComputedStyle(element);
    if (!style || style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
      return false;
    }
    const rect = element.getBoundingClientRect();
    return rect.width > 8 && rect.height > 8;
  }

  /** Every visible password input in the document. */
  function passwordFields(root) {
    const scope = root || document;
    return Array.prototype.slice
      .call(scope.querySelectorAll('input[type="password"]'))
      .filter(isVisible);
  }

  /** Inputs that could hold the user name for a password field. */
  const USERNAME_TYPES = ["text", "email", "tel", "username"];

  /** The most likely user-name input for a password field (nearest one above/in the same form). */
  function usernameFieldFor(password, root) {
    const scope = (password.form && password.form.contains(password) ? password.form : root || document);
    const candidates = Array.prototype.slice
      .call(scope.querySelectorAll("input"))
      .filter(function (element) {
        if (element === password || !isVisible(element)) return false;
        const type = String(element.type || "text").toLowerCase();
        if (USERNAME_TYPES.indexOf(type) < 0) return false;
        if (element.autocomplete === "new-password" || element.autocomplete === "one-time-code") return false;
        return true;
      });
    const before = candidates.filter(function (element) {
      return password.compareDocumentPosition(element) & Node.DOCUMENT_POSITION_PRECEDING;
    });
    if (before.length) return before[before.length - 1];
    return candidates.length ? candidates[0] : null;
  }

  /** A visible input that looks like a one-time-code field (filled only when the entry has one). */
  function otpFieldFor(password, root) {
    const scope = (password && password.form) || root || document;
    const candidates = Array.prototype.slice.call(scope.querySelectorAll("input")).filter(isVisible);
    for (const element of candidates) {
      const hint = [
        element.autocomplete,
        element.name,
        element.id,
        element.getAttribute("aria-label"),
        element.getAttribute("placeholder")
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (/one-time-code|otp|totp|2fa|verification|code|کد/.test(hint)) {
        const max = Number(element.maxLength || 0);
        if (!max || max <= 10) return element;
      }
    }
    return null;
  }

  /** A user-name-only step (some sites ask for the e-mail first, then the password). */
  function usernameOnlyFields(root) {
    const scope = root || document;
    return Array.prototype.slice
      .call(scope.querySelectorAll('input[autocomplete="username"], input[type="email"]'))
      .filter(isVisible);
  }

  /** Group the page into login forms: `{password, username, otp}` per password field. */
  function findLoginForms(root) {
    const passwords = passwordFields(root);
    const forms = passwords.map(function (password) {
      return {
        password: password,
        username: usernameFieldFor(password, root),
        otp: otpFieldFor(password, root)
      };
    });
    if (!forms.length) {
      // No password box: offer the user-name step on its own (fill user name only).
      usernameOnlyFields(root).forEach(function (field) {
        forms.push({ password: null, username: field, otp: null });
      });
    }
    return forms;
  }

  /** Write a value the way a framework expects (native setter + input/change events). */
  function setValue(field, value) {
    if (!field || value === undefined || value === null || value === "") return false;
    const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    const setter = descriptor && descriptor.set;
    if (setter) {
      setter.call(field, String(value));
    } else {
      field.value = String(value);
    }
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  const core = {
    isVisible: isVisible,
    passwordFields: passwordFields,
    usernameFieldFor: usernameFieldFor,
    otpFieldFor: otpFieldFor,
    usernameOnlyFields: usernameOnlyFields,
    findLoginForms: findLoginForms,
    setValue: setValue
  };
  globalThis.SecureVaultContentCore = core;

  // --------------------------------------------------------------------------- UI
  const STYLE = [
    ":host{all:initial}",
    "*{box-sizing:border-box;font-family:Vazirmatn,system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif}",
    ".icon{position:fixed;z-index:2147483646;width:22px;height:22px;padding:0;border:1px solid rgba(0,0,0,.25);",
    "border-radius:6px;background:#111827;color:#f9fafb;cursor:pointer;display:flex;align-items:center;",
    "justify-content:center;line-height:1;box-shadow:0 1px 3px rgba(0,0,0,.35);opacity:.9}",
    ".icon:hover{opacity:1;transform:scale(1.06)}",
    ".icon svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.7}",
    ".panel{position:fixed;z-index:2147483646;min-width:240px;max-width:340px;max-height:320px;overflow:auto;",
    "background:#0f172a;color:#e5e7eb;border:1px solid #334155;border-radius:10px;padding:8px;direction:rtl;",
    "text-align:right;box-shadow:0 8px 24px rgba(0,0,0,.45);font-size:13px}",
    ".panel .head{display:flex;align-items:center;gap:6px;padding:2px 4px 8px;color:#94a3b8;font-size:12px}",
    ".item{display:block;width:100%;text-align:right;background:transparent;border:0;border-radius:8px;",
    "padding:8px;color:inherit;cursor:pointer;font-size:13px}",
    ".item:hover,.item:focus{background:#1e293b;outline:none}",
    ".item .t{font-weight:600}",
    ".item .s{color:#94a3b8;font-size:11px;margin-inline-start:6px}",
    ".item .u{color:#cbd5f5;font-size:12px;direction:ltr;text-align:left;display:block;margin-top:2px}",
    ".msg{padding:6px 4px;color:#fca5a5;font-size:12px;line-height:1.7}",
    ".msg.ok{color:#86efac}",
    ".row{display:flex;gap:6px;align-items:center;padding:6px 4px 2px;border-top:1px solid #1e293b;margin-top:6px}",
    ".ghost{flex:1;background:transparent;border:1px solid #334155;border-radius:8px;color:#cbd5f5;",
    "padding:5px 8px;font-size:12px;cursor:pointer}",
    ".badge{background:#1e293b;border-radius:999px;padding:1px 7px;font-size:11px;color:#cbd5f5}"
  ].join("");

  /** The little shield, built with DOM nodes (nothing is ever parsed as HTML). */
  function buildIcon() {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    const shield = document.createElementNS(NS, "path");
    shield.setAttribute("d", "M12 3l7 3v5.5c0 4.2-2.9 7.6-7 8.5-4.1-.9-7-4.3-7-8.5V6l7-3z");
    const stem = document.createElementNS(NS, "path");
    stem.setAttribute("d", "M12 10.2v3.1");
    const hole = document.createElementNS(NS, "circle");
    hole.setAttribute("cx", "12");
    hole.setAttribute("cy", "13.9");
    hole.setAttribute("r", "1.3");
    svg.appendChild(shield);
    svg.appendChild(stem);
    svg.appendChild(hole);
    return svg;
  }

  const state = {
    host: window.location.hostname,
    forms: [],
    icons: new Map(),
    busy: false
  };

  let host = null;
  let root = null;
  let panelElement = null;
  let sweepTimer = 0;
  let pending = false;

  /** Create (once) the Shadow DOM host that holds every icon and the dropdown. */
  function ensureRoot() {
    if (root && root.isConnected) return root;
    host = document.createElement("div");
    host.id = HOST_ID;
    host.style.cssText = "all:initial";
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    shadow.appendChild(style);
    root = shadow;
    (document.body || document.documentElement).appendChild(host);
    return root;
  }

  /** Position one icon over its field; hide it when the field is gone or off-screen. */
  function placeIcon(icon, field) {
    if (!field || !field.isConnected) {
      icon.hidden = true;
      return false;
    }
    const rect = field.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 8) {
      icon.hidden = true;
      return false;
    }
    const size = 22;
    const top = Math.max(0, Math.min(window.innerHeight - size, rect.top + (rect.height - size) / 2));
    const left = Math.max(0, Math.min(window.innerWidth - size - 2, rect.right - size - 4));
    icon.style.top = top + "px";
    icon.style.left = left + "px";
    icon.hidden = false;
    return true;
  }

  /** Reposition every icon (called on scroll/resize, cheap by design). */
  function reposition() {
    state.icons.forEach(function (icon, field) {
      placeIcon(icon, field);
    });
    if (panelElement && panelElement.anchor && panelElement.anchor.isConnected) {
      positionPanel(panelElement, panelElement.anchor);
    }
  }

  function positionPanel(panel, anchor) {
    const rect = anchor.getBoundingClientRect();
    const width = panel.element.offsetWidth || 260;
    const height = panel.element.offsetHeight || 160;
    let left = Math.min(window.innerWidth - width - 8, Math.max(8, rect.right - width));
    let top = rect.bottom + 6;
    if (top + height > window.innerHeight - 8) {
      top = Math.max(8, rect.top - height - 6);
    }
    panel.element.style.left = left + "px";
    panel.element.style.top = top + "px";
  }

  function closePanel() {
    if (!panelElement) return;
    if (panelElement.element.parentNode) panelElement.element.parentNode.removeChild(panelElement.element);
    panelElement = null;
  }

  /** Build (and show) the dropdown for one field. */
  async function openPanel(field) {
    closePanel();
    const shadow = ensureRoot();
    const element = document.createElement("div");
    element.className = "panel";
    const head = document.createElement("div");
    head.className = "head";
    head.textContent = TEXT.title + " — " + (field.form && field.form.getAttribute("name") ? field.form.getAttribute("name") : state.host);
    element.appendChild(head);
    const list = document.createElement("div");
    element.appendChild(list);
    shadow.appendChild(element);
    panelElement = { element: element, anchor: field, list: list };
    positionPanel(panelElement, field);

    const message = document.createElement("div");
    message.className = "msg";
    message.textContent = "…";
    list.appendChild(message);

    let response = null;
    try {
      response = await browser.runtime.sendMessage({ type: "svb:candidates" });
    } catch (error) {
      response = { ok: false, error: { text: TEXT.offline } };
    }
    list.textContent = "";
    if (!response || !response.ok) {
      const failure = document.createElement("div");
      failure.className = "msg";
      failure.textContent = (response && response.error && response.error.text) || TEXT.unknown;
      list.appendChild(failure);
      addCloseRow(list);
      return;
    }
    const candidates = response.candidates || [];
    if (!candidates.length) {
      const empty = document.createElement("div");
      empty.className = "msg";
      empty.textContent = TEXT.empty;
      list.appendChild(empty);
      addCloseRow(list);
      return;
    }
    head.textContent = TEXT.title + " — " + response.host + " (" + candidates.length + ")";
    candidates.forEach(function (candidate) {
      list.appendChild(candidateRow(candidate, field));
    });
    addCloseRow(list);
    positionPanel(panelElement, field);
  }

  function candidateRow(candidate, field) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "item";
    const title = document.createElement("span");
    title.className = "t";
    title.dir = "auto";
    title.textContent = candidate.title || candidate.site || candidate.path;
    const score = document.createElement("span");
    score.className = "s";
    score.textContent = candidate.has_password ? "" : "(بدون گذرواژه)";
    title.appendChild(score);
    button.appendChild(title);
    if (candidate.username) {
      const username = document.createElement("span");
      username.className = "u";
      username.textContent = candidate.username;
      button.appendChild(username);
    }
    button.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      fillFrom(candidate, field);
    });
    return button;
  }

  function addCloseRow(container) {
    const row = document.createElement("div");
    row.className = "row";
    const close = document.createElement("button");
    close.type = "button";
    close.className = "ghost";
    close.textContent = TEXT.close;
    close.addEventListener("click", function (event) {
      event.stopPropagation();
      closePanel();
    });
    row.appendChild(close);
    container.appendChild(row);
  }

  /** Ask the background for the entry's fields and write them into the page. */
  async function fillFrom(candidate, field) {
    if (state.busy) return;
    state.busy = true;
    let response = null;
    try {
      response = await browser.runtime.sendMessage({ type: "svb:fill", path: candidate.path });
    } catch (error) {
      response = { ok: false, error: { text: TEXT.offline } };
    }
    state.busy = false;
    if (!response || !response.ok) {
      if (panelElement) {
        const failure = document.createElement("div");
        failure.className = "msg";
        failure.textContent = (response && response.error && response.error.text) || TEXT.unknown;
        panelElement.list.appendChild(failure);
      }
      return;
    }
    const form = state.forms.find(function (item) {
      return item.password === field || item.username === field || item.otp === field;
    }) || { password: null, username: null, otp: null };
    const entry = response.entry || {};
    const filledUsername = setValue(form.username || (form.password ? usernameFieldFor(form.password) : null), entry.username);
    const filledPassword = setValue(form.password, entry.password);
    let filledOtp = false;
    if (response.totp && response.totp.code) {
      const otpTarget = form.otp || (form.password ? otpFieldFor(form.password) : null);
      filledOtp = setValue(otpTarget, response.totp.code);
    }
    closePanel();
    showToast(filledUsername || filledPassword ? TEXT.filled : TEXT.filledPartial);
    if (filledOtp) showToast(TEXT.otpFilled, "ok");
  }

  /** A short, self-removing toast inside the shadow root. */
  function showToast(message, kind) {
    const shadow = ensureRoot();
    const toast = document.createElement("div");
    toast.className = "panel";
    toast.style.position = "fixed";
    toast.style.bottom = "16px";
    toast.style.right = "16px";
    toast.style.left = "auto";
    toast.style.top = "auto";
    toast.style.minWidth = "0";
    const line = document.createElement("div");
    line.className = "msg" + (kind === "ok" ? " ok" : "");
    line.style.color = kind === "ok" ? "#86fca5" : "#e5e7eb";
    line.textContent = message;
    toast.appendChild(line);
    shadow.appendChild(toast);
    window.setTimeout(function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 3200);
  }

  // ------------------------------------------------------------------- lifecycle
  /** Re-scan the page and make sure every login form has an icon. */
  function sweep() {
    pending = false;
    if (!document.body) return;
    const forms = findLoginForms(document);
    state.forms = forms;
    const seen = new Set();
    const shadow = forms.length ? ensureRoot() : null;
    forms.forEach(function (form) {
      const anchor = form.username && !form.password ? form.username : form.password || form.username;
      if (!anchor) return;
      seen.add(anchor);
      let icon = state.icons.get(anchor);
      if (!icon) {
        icon = document.createElement("button");
        icon.type = "button";
        icon.className = "icon";
        icon.title = TEXT.fill;
        icon.setAttribute("aria-label", TEXT.fill);
        icon.appendChild(buildIcon());
        icon.addEventListener("click", function (event) {
          event.preventDefault();
          event.stopPropagation();
          openPanel(anchor);
        });
        shadow.appendChild(icon);
        state.icons.set(anchor, icon);
      }
      placeIcon(icon, anchor);
    });
    state.icons.forEach(function (icon, field) {
      if (seen.has(field) && field.isConnected) return;
      if (icon.parentNode) icon.parentNode.removeChild(icon);
      state.icons.delete(field);
    });
  }

  /** Coalesce sweeps: one per frame, with a small trailing timer for slow SPA renders. */
  function scheduleSweep() {
    if (pending) return;
    pending = true;
    window.requestAnimationFrame(function () {
      window.setTimeout(sweep, 60);
    });
  }

  /** The keyboard shortcut path: fill the first candidate into the primary form. */
  async function fillFirst() {
    const form = state.forms.find(function (item) {
      return item.password;
    }) || state.forms[0];
    if (!form) return;
    const anchor = form.password || form.username;
    let response = null;
    try {
      response = await browser.runtime.sendMessage({ type: "svb:candidates" });
    } catch (error) {
      return;
    }
    if (!response || !response.ok || !(response.candidates || []).length) {
      showToast((response && response.error && response.error.text) || TEXT.empty);
      return;
    }
    fillFrom(response.candidates[0], anchor);
  }

  function init() {
    if (!document.body) {
      document.addEventListener("DOMContentLoaded", init);
      return;
    }
    sweep();
    const observer = new MutationObserver(function () {
      scheduleSweep();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    window.addEventListener("scroll", reposition, { passive: true, capture: true });
    window.addEventListener("resize", reposition, { passive: true });
    document.addEventListener("click", function (event) {
      if (panelElement && !event.composedPath().includes(host)) closePanel();
    }, true);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closePanel();
    });
    browser.runtime.onMessage.addListener(function (message) {
      if (!message) return undefined;
      if (message.type === "svb:fill-first") {
        fillFirst();
      } else if (message.type === "svb:fill-path") {
        // From the popup: fill one specific entry into this page's primary form.
        const primary = state.forms.find(function (item) {
          return item.password;
        }) || state.forms[0];
        if (primary) {
          fillFrom({ path: String(message.path || "") }, primary.password || primary.username);
        }
      }
      return undefined;
    });
  }

  core.init = init;
  core.sweep = sweep;
  core.fillFirst = fillFirst;
  core.openPanel = openPanel;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
