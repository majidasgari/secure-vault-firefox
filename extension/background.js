/*
 * Background event page: the only place that talks to the vault.
 *
 * The content script and the popup ask for one of seven things and never see the vault's token.
 * The host that a lookup is made for is taken from the *sender's* URL, never from the page, so a
 * script on the page cannot ask for another site's credentials. Filling happens in the frame
 * that asked, and nothing is written to disk but the port and the (revocable) browser token.
 *
 * One of those seven is new and worth naming: ``svb:otp`` returns the *current one-time code* of
 * one entry, so the popup can show it the way the vault's own viewer does. It costs one audited
 * reveal per entry (not per tick — see `otpValues`), and the value it generates from never leaves
 * this page: the popup receives the six digits, never the secret behind them.
 */
"use strict";

const client = new SecureVaultClient();

/** Persian messages for the failure codes the vault can answer with. */
const MESSAGE_TEXT = {
  VAULT_NOT_RUNNING: "گاوصندوق امن در حال اجرا نیست.",
  UNAUTHORIZED: "اتصال به گاوصندوق برقرار نشد.",
  CLAIM_DENIED: "اتصال به گاوصندوق برقرار نشد.",
  CLAIM_FAILED: "اتصال به گاوصندوق برقرار نشد.",
  VAULT_LOCKED: "گاوصندوق امن قفل است؛ قفلش را در برنامه باز کن.",
  BRIDGE_MISSING: "این نسخهٔ گاوصندوق افزونهٔ مرورگر را ندارد؛ برنامه را کامل ببند و دوباره باز کن.",
  PROVIDER_UNAVAILABLE: "پل مرورگر در گاوصندوق فعال نیست.",
  NO_HOST: "این صفحه آدرس معتبری ندارد.",
  NO_ENTRY: "ورودی‌ای برای این سایت در گاوصندوق نیست.",
  NO_OTP: "این ورودی کد یکبارمصرفِ خواندنی ندارد.",
  BAD_REQUEST: "درخواست نامعتبر بود.",
  NOT_FOUND: "این ورودی در گاوصندوق پیدا نشد.",
  VAULT_ERROR: "گاوصندوق خطا داد."
};

/** The vault reports several distinct refusals as PERMISSION_DENIED with a specific message. */
const VAULT_REASON_TEXT = {
  browser_autofill_disabled: "تکمیل خودکار مرورگر در گاوصندوق خاموش است.",
  too_many_reveals: "تعداد درخواست‌ها زیاد شد؛ چند لحظه بعد دوباره تلاش کن.",
  path_outside_credentials: "این ورودی مربوط به این سایت نیست.",
  host_mismatch: "این ورودی مربوط به این سایت نیست.",
  vault_locked: "گاوصندوق امن قفل است؛ قفلش را در برنامه باز کن.",
  missing_host: "این صفحه آدرس معتبری ندارد."
};

/** Turn a failure into the shape both UIs render. */
function failure(error) {
  const code = (error && error.code) || "ERROR";
  const reason = String((error && error.details && error.details.message) || "");
  const text =
    VAULT_REASON_TEXT[reason] ||
    MESSAGE_TEXT[code] ||
    MESSAGE_TEXT.VAULT_ERROR + " (" + code + ")";
  return {
    ok: false,
    error: { code: code, reason: reason, text: text, status: (error && error.status) || 0 }
  };
}

/** The host of a URL ("" when the scheme has no host we could match on). */
function hostOf(url) {
  try {
    const parsed = new URL(String(url || ""));
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.hostname;
  } catch (error) {
    return "";
  }
}

/**
 * The OTP values the popup has asked to read, in this page's memory only.
 *
 * A code changes every thirty seconds, so a popup that showed a live countdown would otherwise
 * make one audited reveal per tick. The *value* is therefore kept here for a few minutes (never in
 * `storage`, never written anywhere) and the code is generated from it on each look, which keeps
 * the audit log at one row per "show me the code" click. Entries are also dropped when the vault
 * is locked or the port changes, and the popup forgets them when it closes.
 */
const OTP_TTL_MS = 5 * 60 * 1000;
const otpValues = new Map();

/** Drop every remembered OTP value (lock, port change, popup closed). */
function forgetOtpValues() {
  otpValues.clear();
}

/** One memoised OTP value, but only for the host it was revealed for. */
function rememberedOtp(path, host) {
  const held = otpValues.get(path);
  if (!held) return null;
  if (held.host !== host || Date.now() - held.at > OTP_TTL_MS) {
    otpValues.delete(path);
    return null;
  }
  return held;
}

/** Accept only a bare ASCII hostname (the popup passes one; a page never can). */
function sanitizeHost(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text || text.indexOf(".") < 0) return "";
  return /^[a-z0-9][a-z0-9._-]*$/.test(text) ? text : "";
}

/** Paint the toolbar badge from a status payload. */
function updateBadge(status) {
  const locked = Boolean(status && status.locked);
  const enabled = Boolean(status && status.enabled);
  const text = !enabled ? "" : locked ? "!" : "";
  const colour = !enabled ? "#6b7280" : locked ? "#b91c1c" : "#15803d";
  browser.action.setBadgeText({ text: text }).catch(() => {});
  browser.action.setBadgeBackgroundColor({ color: colour }).catch(() => {});
  browser.action.setTitle({
    title: !enabled
      ? "گاوصندوق امن — تکمیل خودکار خاموش است"
      : locked
        ? "گاوصندوق امن — قفل است"
        : "گاوصندوق امن — باز است"
  }).catch(() => {});
}

/** Fetch the bridge status and refresh the badge. */
async function fetchStatus() {
  await client.configure();
  const status = await client.status();
  // A locked (or disabled) vault must not keep serving codes from the memo above.
  if (!status || status.locked || !status.enabled) forgetOtpValues();
  updateBadge(status);
  return status;
}

/** Handler: status for the popup/content script. */
async function onStatus() {
  try {
    const status = await fetchStatus();
    return { ok: true, port: client.port, status: status };
  } catch (error) {
    updateBadge(null);
    return Object.assign(failure(error), { port: client.port });
  }
}

/** Handler: candidates for the sender's own host. */
async function onCandidates(message, sender) {
  // A content script always has a tab, and its host comes from the tab's own URL — the page
  // cannot ask for another site. The popup has no tab of its own and passes the active tab's
  // host explicitly; it is validated, and only extension code can send it at all.
  const senderHost = hostOf((sender && sender.url) || (sender && sender.tab && sender.tab.url));
  const host = senderHost || (sender && sender.tab ? "" : sanitizeHost(message && message.host));
  if (!host) return failure({ code: "NO_HOST" });
  try {
    await client.configure();
    const result = await client.match(host, sender && sender.url ? sender.url : "");
    return {
      ok: true,
      host: result.host || host,
      candidates: result.candidates || [],
      entries: (result.index && result.index.entries) || 0
    };
  } catch (error) {
    return failure(error);
  }
}

/** Handler: the fields of one entry for the sender's own host (the audited reveal). */
async function onFill(message, sender) {
  const host = hostOf((sender && sender.url) || (sender && sender.tab && sender.tab.url));
  if (!host) return failure({ code: "NO_HOST" });
  const path = String((message && message.path) || "");
  if (!path) return failure({ code: "NO_ENTRY" });
  try {
    await client.configure();
    const entry = await client.reveal(path, host);
    let totp = null;
    if (entry.has_otp && entry.otp) {
      // Only a code generated from a secret is worth typing. A stored *static* code (a pasted
      // six-digit value) is a backup code: filling it into the page would look successful and
      // then fail, so it is left alone.
      const generated = await SecureVaultTotp.valueToCode(entry.otp).catch(() => null);
      if (generated && generated.live) totp = generated;
    }
    return { ok: true, host: host, entry: entry, totp: totp };
  } catch (error) {
    return failure(error);
  }
}

/** Handler: the live one-time code of one entry (the popup's reading surface, never a fill). */
async function onOtp(message, sender) {
  const senderHost = hostOf((sender && sender.url) || (sender && sender.tab && sender.tab.url));
  const host = senderHost || (sender && sender.tab ? "" : sanitizeHost(message && message.host));
  if (!host) return failure({ code: "NO_HOST" });
  const path = String((message && message.path) || "");
  if (!path) return failure({ code: "NO_ENTRY" });
  try {
    await client.configure();
    let held = rememberedOtp(path, host);
    if (!held) {
      // One audited reveal per entry, exactly like a fill — the code is credential material even
      // when it is only being looked at. The value stays in memory (see `otpValues`).
      const entry = await client.reveal(path, host);
      if (!entry.has_otp || !entry.otp) return failure({ code: "NO_OTP" });
      held = { host: host, value: entry.otp, at: Date.now() };
      otpValues.set(path, held);
    }
    const generated = await SecureVaultTotp.valueToCode(held.value).catch(() => null);
    if (!generated) return failure({ code: "NO_OTP" });
    return {
      ok: true,
      has_otp: true,
      code: generated.code,
      display: generated.display,
      remaining: generated.remaining,
      period: generated.period,
      live: generated.live
    };
  } catch (error) {
    otpValues.delete(path);
    return failure(error);
  }
}

/** Handler: the popup closed — forget every remembered OTP value. */
async function onOtpForget() {
  forgetOtpValues();
  return { ok: true };
}

/** Handler: the port the user typed in the popup. */
async function onSetPort(message) {
  await client.configure();
  const port = await client.setPort(message && message.port);
  forgetOtpValues();
  try {
    const status = await fetchStatus();
    return { ok: true, port: port, status: status };
  } catch (error) {
    return Object.assign(failure(error), { port: port });
  }
}

/** Handler: open the vault's own web UI in a tab. */
async function onOpenVault() {
  await client.configure();
  const url = `${client.baseUrl()}/`;
  await browser.tabs.create({ url: url });
  return { ok: true, url: url };
}

/**
 * Make sure the content script is answering in this tab.
 *
 * A tab that was already open when the add-on was installed has no content script in it, and a
 * click in the popup would then do nothing at all. Inject it on demand instead — and say so
 * plainly when even that is refused (about:, the add-on store, a PDF viewer).
 */
async function ensureContent(tabId) {
  try {
    return await browser.tabs.sendMessage(tabId, { type: "svb:ping" });
  } catch (error) {
    // No receiver in that tab: fall through and inject the content script.
  }
  try {
    await browser.scripting.executeScript({
      target: { tabId: tabId, allFrames: true },
      files: ["content/content.js"]
    });
  } catch (error) {
    return { ok: false, code: "NO_CONTENT", text: "این صفحه اجازهٔ فعال‌شدن افزونه را نمی‌دهد." };
  }
  try {
    return await browser.tabs.sendMessage(tabId, { type: "svb:ping" });
  } catch (error) {
    return { ok: false, code: "NO_CONTENT", text: "افزونه در این تب فعال نشد؛ صفحه را دوباره بارگذاری کن (F5)." };
  }
}

/** Handler: what the add-on sees in one tab right now (the popup's per-tab line). */
async function onTabProbe(message) {
  const tabId = Number(message && message.tabId);
  if (!tabId) return failure({ code: "BAD_REQUEST" });
  const probe = await ensureContent(tabId);
  if (probe && probe.ok) return probe;
  return {
    ok: false,
    code: (probe && probe.code) || "NO_CONTENT",
    text: (probe && probe.text) || "این تب در دسترس افزونه نیست."
  };
}

/** Handler: fill one entry in one tab (the popup path; the content script owns the form). */
async function onTabFill(message) {
  const tabId = Number(message && message.tabId);
  const path = String((message && message.path) || "");
  if (!tabId || !path) return failure({ code: "BAD_REQUEST" });
  const probe = await ensureContent(tabId);
  if (!probe || !probe.ok) {
    return {
      ok: false,
      code: (probe && probe.code) || "NO_CONTENT",
      text: (probe && probe.text) || "این تب در دسترس افزونه نیست."
    };
  }
  const answer = await browser.tabs.sendMessage(tabId, { type: "svb:fill-path", path: path });
  return answer || { ok: false, code: "NO_ANSWER", text: "پاسخی از صفحه نیامد." };
}

browser.runtime.onMessage.addListener((message, sender) => {
  const type = (message && message.type) || "";
  if (type === "svb:status") return onStatus();
  if (type === "svb:candidates") return onCandidates(message, sender);
  if (type === "svb:fill") return onFill(message, sender);
  if (type === "svb:otp") return onOtp(message, sender);
  if (type === "svb:otp-forget") return onOtpForget();
  if (type === "svb:set-port") return onSetPort(message);
  if (type === "svb:open-vault") return onOpenVault();
  if (type === "svb:tab-probe") return onTabProbe(message);
  if (type === "svb:tab-fill") return onTabFill(message);
  return undefined;
});

/** The keyboard shortcut fills the top candidate in the active tab. */
browser.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs && tabs[0];
  if (!tab || !tab.id) return;
  const probe = await ensureContent(tab.id);
  if (probe && probe.ok) {
    await browser.tabs.sendMessage(tab.id, { type: "svb:fill-first" }).catch(() => {});
  }
});

// Deliberately no `tabs.onUpdated` badge refresh: every bridge call lands in the vault's access
// log, and a status call per page load would fill that log with rows the user never caused. The
// badge refreshes when the popup is opened, which is the only moment it is looked at.

