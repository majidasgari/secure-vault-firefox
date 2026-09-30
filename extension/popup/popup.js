/*
 * The popup: status, the entry list for the current tab, and the port setting.
 *
 * It never talks to the vault itself — every call goes through the background page, so the
 * browser token stays in one place. Clicking an entry asks the page's content script to fill it
 * (the content script owns the form, and the background derives the host from *that* frame).
 */
"use strict";

const ui = {
  dot: document.getElementById("dot"),
  state: document.getElementById("state"),
  host: document.getElementById("host"),
  list: document.getElementById("list"),
  port: document.getElementById("port"),
  save: document.getElementById("save"),
  open: document.getElementById("open")
};

/** Host of a URL, or "" for anything that is not http(s). */
function hostOf(url) {
  try {
    const parsed = new URL(String(url || ""));
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.hostname;
  } catch (error) {
    return "";
  }
}

function setState(text, kind) {
  ui.state.textContent = text;
  ui.dot.className = "dot" + (kind ? " " + kind : "");
}

/** Ask the background for the candidate list of the tab the user is looking at. */
async function loadCandidates(tab) {
  const host = tab ? hostOf(tab.url) : "";
  ui.host.textContent = host || "";
  if (!host) {
    ui.list.textContent = "";
    const note = document.createElement("div");
    note.className = "empty";
    note.textContent = "این صفحه آدرس معتبری ندارد.";
    ui.list.appendChild(note);
    return;
  }
  let response = null;
  try {
    response = await browser.runtime.sendMessage({ type: "svb:candidates", host: host });
  } catch (error) {
    response = { ok: false, error: { text: "ارتباط با افزونه برقرار نشد." } };
  }
  renderCandidates(response, tab);
}

function renderCandidates(response, tab) {
  ui.list.textContent = "";
  if (!response || !response.ok) {
    const failure = document.createElement("div");
    failure.className = "error";
    failure.textContent = (response && response.error && response.error.text) || "خطای نامشخص";
    ui.list.appendChild(failure);
    return;
  }
  const candidates = response.candidates || [];
  if (!candidates.length) {
    const note = document.createElement("div");
    note.className = "empty";
    note.textContent = "برای این سایت ورودی‌ای در گاوصندوق نیست.";
    ui.list.appendChild(note);
    return;
  }
  candidates.forEach(function (candidate) {
    const entry = document.createElement("button");
    entry.type = "button";
    entry.className = "entry";
    const title = document.createElement("span");
    title.className = "title";
    title.dir = "auto";
    title.textContent = candidate.title || candidate.site || candidate.path;
    entry.appendChild(title);
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.dir = "auto";
    meta.textContent = [candidate.site, candidate.has_password ? "" : "بدون گذرواژه"]
      .filter(Boolean)
      .join(" · ");
    entry.appendChild(meta);
    if (candidate.username) {
      const username = document.createElement("span");
      username.className = "username";
      username.textContent = candidate.username;
      entry.appendChild(username);
    }
    entry.addEventListener("click", function () {
      fillInTab(tab, candidate);
    });
    ui.list.appendChild(entry);
  });
  renderTabLine(tab);
}

/** One short line: what the add-on can see in this tab at this moment. */
async function renderTabLine(tab) {
  if (!tab || !tab.id) return;
  let probe = null;
  try {
    probe = await browser.runtime.sendMessage({ type: "svb:tab-probe", tabId: tab.id });
  } catch (error) {
    probe = null;
  }
  const line = document.createElement("div");
  line.className = "note";
  if (probe && probe.ok) {
    line.textContent = probe.forms
      ? "در این تب " + probe.forms + " فیلد ورود شناسایی شد — آیکن کوچک داخل فیلد را بزن."
      : "فیلد ورودی در این صفحه پیدا نشد.";
  } else {
    line.textContent =
      (probe && (probe.text || (probe.error && probe.error.text))) ||
      "این تب در دسترس افزونه نیست؛ صفحه را دوباره بارگذاری کن.";
  }
  ui.list.insertBefore(line, ui.list.firstChild);
  line.scrollIntoView({ block: "nearest" });
}

/** A result line above the list (the fill is never silent). */
function showResult(text, kind) {
  const line = document.createElement("div");
  line.className = kind === "ok" ? "note" : "error";
  line.textContent = text;
  ui.list.insertBefore(line, ui.list.firstChild);
  line.scrollIntoView({ block: "nearest" });
}

/** Ask the content script of that tab to fill one entry (it owns the form). */
async function fillInTab(tab, candidate) {
  if (!tab || !tab.id) return;
  ui.list.classList.add("busy");
  let answer = null;
  try {
    answer = await browser.runtime.sendMessage({
      type: "svb:tab-fill",
      tabId: tab.id,
      path: candidate.path
    });
  } catch (error) {
    answer = null;
  }
  ui.list.classList.remove("busy");
  if (answer && answer.ok && answer.filled && answer.filled !== "none") {
    window.close();
    return;
  }
  if (answer && answer.ok) {
    showResult("این ورودی چیزی برای پر کردن نداشت.", "error");
    return;
  }
  showResult(
    (answer && (answer.text || (answer.error && answer.error.text))) ||
      "ارتباط با این تب برقرار نشد؛ صفحه را دوباره بارگذاری کن (F5).",
    "error"
  );
}

/** Refresh status + list + port field. */
async function refresh() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs && tabs[0];
  let status = null;
  try {
    status = await browser.runtime.sendMessage({ type: "svb:status" });
  } catch (error) {
    status = null;
  }
  if (status && status.ok) {
    if (Number(status.port) !== Number(ui.port.value)) ui.port.value = String(status.port);
    else ui.port.value = ui.port.value || String(status.port);
    const info = status.status || {};
    const entries = (info.index && info.index.entries) || 0;
    if (!info.enabled) {
      setState("تکمیل خودکار در گاوصندوق خاموش است.", "off");
    } else if (info.locked) {
      setState("گاوصندوق قفل است؛ در برنامه بازش کن.", "locked");
    } else {
      setState("گاوصندوق باز است — " + entries + " ورودی رمز.", "ok");
    }
  } else {
    ui.port.value = ui.port.value || String((status && status.port) || 8788);
    setState((status && status.error && status.error.text) || "گاوصندوق امن در حال اجرا نیست.", "off");
  }
  loadCandidates(tab);
}

ui.save.addEventListener("click", async function () {
  const port = Number(ui.port.value);
  ui.save.disabled = true;
  const response = await browser.runtime.sendMessage({ type: "svb:set-port", port: port }).catch(() => null);
  ui.save.disabled = false;
  if (response && response.ok) {
    ui.port.value = String(response.port);
    refresh();
  } else {
    setState((response && response.error && response.error.text) || "گاوصندوق امن در این پورت پاسخ نداد.", "off");
  }
});

ui.open.addEventListener("click", function () {
  browser.runtime.sendMessage({ type: "svb:open-vault" }).catch(() => {});
  window.close();
});

refresh();
