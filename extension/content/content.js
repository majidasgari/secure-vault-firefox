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
    // Offer the user-name step on its own as well. A two-step sign-in asks for the e-mail
    // first (no password box in the DOM yet), and some sites keep an invisible password box
    // next to a visible e-mail box; in both cases the visible e-mail box deserves an icon.
    const paired = new Set(
      forms.map(function (form) {
        return form.username;
      })
    );
    usernameOnlyFields(root).forEach(function (field) {
      if (paired.has(field)) return;
      forms.push({ password: null, username: field, otp: null });
    });
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
    ".badge{background:#1e293b;border-radius:999px;padding:1px 7px;font-size:11px;color:#cbd5f5}",
    ".save{position:fixed;z-index:2147483646;top:12px;right:12px;max-width:360px;background:#0f172a;",
    "color:#e5e7eb;border:1px solid #334155;border-radius:10px;padding:10px;direction:rtl;text-align:right;",
    "box-shadow:0 10px 28px rgba(0,0,0,.5);font-size:13px;display:flex;flex-direction:column;gap:8px}",
    ".save .save-head{font-weight:700;font-size:12px;color:#93c5fd}",
    ".save .save-text{line-height:1.9}",
    ".save .save-text.err{color:#fca5a5}",
    ".save .save-meta{color:#94a3b8;font-size:11px;direction:ltr;text-align:left;word-break:break-all}",
    ".save .save-row{display:flex;gap:6px;flex-wrap:wrap}",
    ".save .save-primary{background:#1d4ed8;border:0;border-radius:8px;color:#fff;padding:6px 10px;",
    "font-size:12px;cursor:pointer;font-family:inherit}",
    ".save .save-ghost{background:transparent;border:1px solid #334155;border-radius:8px;color:#cbd5f5;",
    "padding:6px 10px;font-size:12px;cursor:pointer;font-family:inherit}"
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
  let retries = 0;

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
    if (state.busy) return { ok: false, reason: "busy", text: TEXT.unknown };
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
      return {
        ok: false,
        reason: "vault",
        text: (response && response.error && response.error.text) || TEXT.unknown
      };
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
    // Remember what the vault just put in this page, so a submit of exactly these values is not
    // offered back for saving: the vault obviously already holds them.
    lastFill = {
      username: String(entry.username || ""),
      password: String(entry.password || "")
    };
    showToast(filledUsername || filledPassword ? TEXT.filled : TEXT.filledPartial);
    if (filledOtp) showToast(TEXT.otpFilled, "ok");
    const parts = [];
    if (filledUsername) parts.push("username");
    if (filledPassword) parts.push("password");
    if (filledOtp) parts.push("otp");
    return {
      ok: true,
      filled: parts.join("+") || "none",
      reason: parts.length ? "" : "nothing_to_fill",
      text: parts.length ? "" : TEXT.filledPartial
    };
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

  // ----------------------------------------------------------------- saving a password
  /*
   * The user typed a password by hand and the page moved on: that credential is worth offering
   * to the vault. Two rules keep this from becoming noise —
   *
   *  * nothing is offered for a fill the add-on itself made (`lastFill`): the vault obviously
   *    already has that password, and asking would look like it did not;
   *  * nothing is offered unless the page really looks like it is *past* its login form (no
   *    visible password box still holding a value, no failure text on screen).
   *
   * The password itself is handed to the background once, in memory, and never comes back here:
   * this script only ever sends «ذخیره» / «الان نه» / «هرگز» and renders the answer.
   */
  const SAVE_TEXT = {
    title: "گاوصندوق امن",
    save: "ذخیره در گاوصندوق",
    update: "به‌روزرسانی گذرواژه",
    later: "الان نه",
    never: "هرگز برای این سایت",
    fresh: "نام کاربری و گذرواژهٔ این ورود در گاوصندوق ذخیره شود؟",
    changed: "گذرواژهٔ این سایت عوض شده؛ در گاوصندوق به‌روز شود؟",
    saving: "در حال ذخیره…",
    openVault: "باز کردن گاوصندوق",
    saved: "در گاوصندوق ذخیره شد."
  };

  /** Text that means the attempt failed (nothing may be offered then). */
  const FAILURE_TEXT =
    /(رمز عبور|گذرواژه|نام کاربری|ایمیل)[^.\n]{0,30}(اشتباه|نادرست|نامعتبر|منقضی)|incorrect|invalid|wrong (password|username|credentials)|login failed|authentication failed|try again|too many (attempts|tries)/i;

  /** What the add-on itself just filled, so its own credentials are never offered back. */
  let lastFill = null;

  /** The attempt already handed over, so one submit is not reported three times (click + submit). */
  let lastAttempt = null;

  /** How long after a submit the page is re-examined (SPAs never navigate). */
  const OUTCOME_DELAY_MS = 1500;
  let outcomeTimer = 0;
  let outcomeChecks = 0;

  /** The bar currently on screen (one at a time). */
  let saveBar = null;

  /** Does the page look like it is *past* its login form (the only state worth offering in)? */
  function looksSignedIn() {
    const body = document.body;
    const text = body ? String(body.innerText || "").slice(0, 20000) : "";
    if (FAILURE_TEXT.test(text)) return false;
    if (passwordFields(document).some(function (field) { return Boolean(field.value); })) return false;
    return !findLoginForms(document).some(function (form) { return Boolean(form.password); });
  }

  /** Tell the background what the page just did; it decides whether there is anything to offer. */
  async function announceOutcome(phase) {
    let response = null;
    try {
      response = await browser.runtime.sendMessage({
        type: "svb:login-outcome",
        phase: phase,
        title: String(document.title || "").slice(0, 200)
      });
    } catch (error) {
      return null;
    }
    // Only a positive answer draws anything: while a page is loading its own scripts, an error
    // banner about the vault would be noise with no action behind it.
    if (response && response.prompt) showSaveBar(response.prompt);
    return response || null;
  }

  /** Remember the credentials of the form the user just submitted (never when the vault filled). */
  function captureSubmit() {
    const form = findLoginForms(document).filter(function (item) {
      return item.password && item.password.value;
    })[0];
    if (!form) return false;
    const username = form.username && form.username.value ? String(form.username.value) : "";
    const password = String(form.password.value);
    if (!password) return false;
    if (lastFill && lastFill.password === password && lastFill.username === username) return false;
    // One submit fires several events (the click on the button, the form's own submit, Enter in
    // a field): the credential is handed over once, not once per event.
    const now = Date.now();
    if (
      lastAttempt &&
      lastAttempt.username === username &&
      lastAttempt.password === password &&
      now - lastAttempt.at < 5000
    ) {
      return false;
    }
    lastAttempt = { username: username, password: password, at: now };
    browser.runtime
      .sendMessage({
        type: "svb:login-attempt",
        username: username,
        password: password,
        title: String(document.title || "").slice(0, 200)
      })
      .catch(function () {});
    outcomeChecks = 0;
    window.clearTimeout(outcomeTimer);
    outcomeTimer = window.setTimeout(checkAfterSubmit, OUTCOME_DELAY_MS);
    return true;
  }

  /** A submit that does not navigate: watch the form go away by itself, for a while. */
  function checkAfterSubmit() {
    if (looksSignedIn()) {
      announceOutcome("same-document");
      return;
    }
    outcomeChecks += 1;
    if (outcomeChecks < 8) {
      outcomeTimer = window.setTimeout(checkAfterSubmit, 900);
    }
  }

  /** Close the bar (the decision was made, or it timed out). */
  function closeSaveBar() {
    if (saveBar && saveBar.parentNode) saveBar.parentNode.removeChild(saveBar);
    saveBar = null;
  }

  /** A button of the bar (nothing here is ever parsed as HTML). */
  function barButton(label, className, onClick) {
    const element = document.createElement("button");
    element.type = "button";
    element.className = className;
    element.textContent = label;
    element.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      onClick();
    });
    return element;
  }

  /** Show the one bar the user answers (it stays until answered, then goes by itself). */
  function showSaveBar(prompt) {
    closeSaveBar();
    const shadow = ensureRoot();
    const bar = document.createElement("div");
    bar.className = "save";
    const head = document.createElement("div");
    head.className = "save-head";
    head.textContent = SAVE_TEXT.title;
    const message = document.createElement("div");
    message.className = "save-text";
    message.textContent =
      prompt.state === "locked"
        ? prompt.text || "گاوصندوق امن قفل است."
        : prompt.state === "changed"
          ? SAVE_TEXT.changed
          : SAVE_TEXT.fresh;
    const meta = document.createElement("div");
    meta.className = "save-meta";
    meta.textContent = [prompt.username, prompt.title && prompt.title !== prompt.host ? prompt.title : ""]
      .filter(Boolean)
      .join(" · ");
    if (!meta.textContent) meta.hidden = true;
    const row = document.createElement("div");
    row.className = "save-row";
    if (prompt.state === "locked") {
      row.appendChild(
        barButton(SAVE_TEXT.openVault, "save-primary", function () {
          browser.runtime.sendMessage({ type: "svb:open-vault" }).catch(function () {});
          closeSaveBar();
        })
      );
      row.appendChild(barButton(SAVE_TEXT.later, "save-ghost", function () { dismissSave("later"); }));
    } else {
      row.appendChild(
        barButton(prompt.state === "changed" ? SAVE_TEXT.update : SAVE_TEXT.save, "save-primary", function () {
          saveCredential(prompt, row, message);
        })
      );
      row.appendChild(barButton(SAVE_TEXT.later, "save-ghost", function () { dismissSave("later"); }));
      row.appendChild(barButton(SAVE_TEXT.never, "save-ghost", function () { dismissSave("never"); }));
    }
    bar.appendChild(head);
    bar.appendChild(message);
    bar.appendChild(meta);
    bar.appendChild(row);
    shadow.appendChild(bar);
    saveBar = bar;
  }

  /** Ask the background to write the credential the vault is still holding for this tab. */
  async function saveCredential(prompt, row, message) {
    row.textContent = "";
    message.className = "save-text";
    message.textContent = SAVE_TEXT.saving;
    let response = null;
    try {
      response = await browser.runtime.sendMessage({
        type: "svb:save-password",
        path: prompt.state === "changed" ? prompt.path : ""
      });
    } catch (error) {
      response = null;
    }
    if (response && response.ok) {
      message.textContent = response.text || SAVE_TEXT.saved;
      window.setTimeout(closeSaveBar, 3200);
      return;
    }
    const failure = response && response.error ? response.error : null;
    message.className = "save-text err";
    message.textContent = (failure && failure.text) || TEXT.offline;
    row.appendChild(
      barButton(prompt.state === "changed" ? SAVE_TEXT.update : SAVE_TEXT.save, "save-ghost", function () {
        saveCredential(prompt, row, message);
      })
    );
    if (failure && (failure.reason === "vault_locked" || failure.code === "VAULT_LOCKED")) {
      row.appendChild(
        barButton(SAVE_TEXT.openVault, "save-ghost", function () {
          browser.runtime.sendMessage({ type: "svb:open-vault" }).catch(function () {});
          closeSaveBar();
        })
      );
    }
    row.appendChild(barButton(SAVE_TEXT.later, "save-ghost", function () { dismissSave("later"); }));
  }

  /** The user said no: the background drops the credential (for good, on «هرگز»). */
  function dismissSave(mode) {
    browser.runtime.sendMessage({ type: "svb:save-dismiss", mode: mode }).catch(function () {});
    closeSaveBar();
  }

  // ------------------------------------------------------------------- lifecycle
  /** Re-scan the page and make sure every login form has an icon. */
  function sweep() {
    pending = false;
    if (!document.body) return;
    const forms = findLoginForms(document);
    state.forms = forms;
    // A form can arrive in two steps: the field is already in the DOM but invisible (an entrance
    // animation), and only later becomes usable — with no insertion for the observer to see. Keep
    // re-checking for a while instead of leaving the page without an icon forever.
    if (!forms.length && retries < 10) {
      retries += 1;
      window.clearTimeout(sweepTimer);
      sweepTimer = window.setTimeout(sweep, 400);
    } else if (forms.length) {
      retries = 0;
    }
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
    // The popup injects this script into tabs that were already open (so no icon was there):
    // running it twice must not double the icons, the observer or the listeners.
    if (window.__secureVaultBrowserInit) return;
    window.__secureVaultBrowserInit = true;
    sweep();
    const observer = new MutationObserver(function () {
      scheduleSweep();
    });
    // Attributes matter as much as insertions: a class or a style change is how pages reveal a
    // form that was already in the DOM (and how they hide it again).
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden", "type", "autocomplete", "disabled", "readonly"]
    });
    window.addEventListener("scroll", reposition, { passive: true, capture: true });
    window.addEventListener("resize", reposition, { passive: true });
    document.addEventListener("click", function (event) {
      if (panelElement && !event.composedPath().includes(host)) closePanel();
    }, true);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closePanel();
    });
    // The saving flow. `submit` covers the ordinary form; a click on a submit control and Enter
    // in a password box cover the SPAs that never fire one. Nothing leaves the page until a
    // submit actually carried a password (`captureSubmit`), and the background decides the rest.
    document.addEventListener(
      "submit",
      function () {
        captureSubmit();
      },
      true
    );
    document.addEventListener(
      "keydown",
      function (event) {
        if (event.key === "Enter" && event.target && event.target.type === "password") captureSubmit();
      },
      true
    );
    document.addEventListener(
      "click",
      function (event) {
        const path = event.composedPath ? event.composedPath() : [];
        for (let index = 0; index < path.length; index += 1) {
          const node = path[index];
          if (!node || node.nodeType !== 1) continue;
          if (node.tagName === "BUTTON" && String(node.type || "").toLowerCase() === "submit") {
            captureSubmit();
            return;
          }
        }
      },
      true
    );
    // A page that already arrived *past* its login form: the background still holds the
    // credential typed on the previous page, so this is where a navigated login is offered.
    // (It answers from memory in one message — this costs the vault nothing on ordinary pages.)
    window.setTimeout(function () {
      if (looksSignedIn()) announceOutcome("load");
    }, 400);
    browser.runtime.onMessage.addListener(function (message) {
      if (!message) return undefined;
      if (message.type === "svb:ping") {
        // The popup asks this before it offers an entry: it says whether this tab can be filled.
        sweep();
        return Promise.resolve({
          ok: true,
          host: location.host,
          forms: state.forms.length,
          fillable: state.forms.length > 0
        });
      }
      if (message.type === "svb:fill-first") {
        return fillFirst();
      } else if (message.type === "svb:fill-path") {
        // From the popup: fill one specific entry into this page's primary form.
        // Look again before giving up: the form may have appeared since the last sweep.
        if (!state.forms.length) sweep();
        const primary = state.forms.find(function (item) {
          return item.password;
        }) || state.forms[0];
        if (!primary) {
          return Promise.resolve({
            ok: false,
            reason: "no_form",
            text: "فیلد ورودی در این صفحه پیدا نشد."
          });
        }
        return fillFrom({ path: String(message.path || "") }, primary.password || primary.username);
      }
      return undefined;
    });
  }

  core.init = init;
  core.sweep = sweep;
  core.fillFirst = fillFirst;
  core.openPanel = openPanel;
  core.captureSubmit = captureSubmit;
  core.looksSignedIn = looksSignedIn;
  core.announceOutcome = announceOutcome;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
