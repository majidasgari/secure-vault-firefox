#!/usr/bin/env python3
"""Probe: the *Chrome build*, loaded as a real extension in a real Chrome, against a real vault.

Where ``probe.py`` loads the add-on's own scripts into a page (a plain page is not an extension
host, so it has to), this one loads ``dist/chrome/`` the way Chrome does — ``--load-extension``,
MV3 service worker and all — and then drives it as a user would:

* the vault — a scratch vault (never the user's) with one credential in it;
* the extension — built by ``tools/build-chrome.py``, loaded by Chrome itself, so the manifest, the
  service worker, the content script, the popup and Chrome's own message plumbing are all real;
* the clicks — real ``Input.dispatchMouseEvent`` events at coordinates taken from the live DOM. The
  add-on's icon and dropdown live in a *closed* shadow root (a page must not be able to click an
  entry for the user), so the coordinates come from ``DOM.getDocument(pierce=true)``, which is how
  DevTools reaches inside a closed shadow tree — nothing in the add-on is patched for the test.

The probe points the extension at the scratch vault *before* it can make a single bridge call, so
a vault of the user's that happens to be running on the default port is never contacted.

Which Chrome: the newest Chrome for Testing found in ``~/.cache/puppeteer`` (or ``--chrome PATH``,
or ``$SVB_CHROME``). Branded Google Chrome ignores ``--load-extension`` — it cannot load an
extension from the command line at all — so the probe says so and stops rather than reporting a
green run against an extension that never loaded.

Run:  cd /data/Codes/secure-vault && ./.venv/bin/python \\
        /data/Codes/secure-vault-browser/tests/probe_chrome.py
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEMO = REPO_ROOT / "demo"

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from probe import (  # noqa: E402  (the Firefox probe owns the fixtures and the primitives)
    CREDENTIAL_PATH,
    PASSWORD,
    USERNAME,
    Checks,
    Cdp,
    free_port,
    seed_scratch_vault,
    totp_now,
)

SW_ENTRY = "background.sw.js"
OTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
HOST_ID = "secure-vault-autofill-root"


class FastCdp(Cdp):
    """probe.py's DevTools client with a short socket timeout.

    A MV3 service worker is started and stopped by Chrome on its own, so a connection to one can be
    left hanging when the worker goes away mid-call; failing in ten seconds (and retrying) is worth
    far more than blocking for thirty.
    """

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        from wsclient import WebSocket

        self.ws = WebSocket(url, timeout=timeout)
        self._next = 1


class QuietDemoHandler(http.server.SimpleHTTPRequestHandler):
    """The demo pages, from the repo, without a line of request noise in the probe's output."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, directory=str(DEMO), **kwargs)

    def log_message(self, *args, **kwargs) -> None:
        return


# ------------------------------------------------------------------------------- finding chrome
def chrome_candidates() -> list[Path]:
    """Every Chrome this probe could drive, newest build first."""
    found: list[tuple[tuple[int, ...], Path]] = []
    cache = Path.home() / ".cache" / "puppeteer" / "chrome"
    for directory in sorted(cache.glob("linux-*")) if cache.is_dir() else []:
        binary = directory / "chrome-linux64" / "chrome"
        if binary.is_file():
            match = re.search(r"linux-(\d+(?:\.\d+)*)", directory.name)
            version = tuple(int(part) for part in match.group(1).split(".")) if match else (0,)
            found.append((version, binary))
    # Branded Google Chrome last: it cannot load an extension from the command line, so it is only
    # useful for proving that fact.
    for path, version in ((Path("/usr/bin/chromium"), (0,)), (Path("/usr/bin/google-chrome-stable"), (-1,))):
        if path.is_file():
            found.append((version, path))
    return [binary for _, binary in sorted(found, key=lambda item: item[0], reverse=True)]


def pick_chrome(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    from_env = os.environ.get("SVB_CHROME")
    if from_env:
        return Path(from_env).expanduser().resolve()
    candidates = chrome_candidates()
    if not candidates:
        raise SystemExit("no Chrome found; pass --chrome PATH (Chrome for Testing or Chromium)")
    return candidates[0]


def unpacked_id(path: Path) -> str:
    """Chrome's id for an unpacked extension: sha256 of the absolute path, digits mapped a-p."""
    import hashlib

    digest = hashlib.sha256(str(path).encode()).hexdigest()[:32]
    return "".join(chr(ord("a") + int(char, 16)) for char in digest)


# ----------------------------------------------------------------------------------- CDP extras
def targets(port: int) -> list[dict]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as response:
        return json.load(response)


def wait_for_target(port: int, predicate, timeout: float = 25.0) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for target in targets(port):
            if predicate(target):
                return target
        time.sleep(0.25)
    return None


def iter_nodes(node: dict):
    """Every node under this one, including closed shadow trees (``pierce=true`` gives them)."""
    yield node
    for key in ("children", "shadowRoots", "pseudoElements"):
        for child in node.get(key) or []:
            yield from iter_nodes(child)
    content = node.get("contentDocument")
    if isinstance(content, dict):
        yield from iter_nodes(content)


def node_attrs(node: dict) -> dict:
    attrs = node.get("attributes") or []
    return {attrs[index]: attrs[index + 1] for index in range(0, len(attrs) - 1, 2)}


def find_node(root: dict, *, tag: str | None = None, cls: str | None = None, node_id: str | None = None):
    for node in iter_nodes(root):
        if tag and node.get("localName") != tag:
            continue
        if cls and cls not in (node_attrs(node).get("class") or "").split():
            continue
        if node_id and node_attrs(node).get("id") != node_id:
            continue
        return node
    return None


def find_nodes(root: dict, **kwargs) -> list[dict]:
    out = []
    for node in iter_nodes(root):
        if kwargs.get("tag") and node.get("localName") != kwargs["tag"]:
            continue
        if kwargs.get("cls") and kwargs["cls"] not in (node_attrs(node).get("class") or "").split():
            continue
        if kwargs.get("node_id") and node_attrs(node).get("id") != kwargs["node_id"]:
            continue
        out.append(node)
    return out


def node_text(node: dict) -> str:
    return " ".join(part.get("nodeValue", "") for part in iter_nodes(node) if part.get("nodeType") == 3)


def as_json(value: object, default: Any = None) -> Any:
    """An answer that was JSON.stringify()ed inside the page (or a fallback when there was none)."""
    if not isinstance(value, str):
        return default if default is not None else {}
    try:
        return json.loads(value)
    except ValueError:
        return default if default is not None else {}


class Page:
    """One Chrome tab, driven over its own CDP connection."""

    def __init__(self, cdp: Cdp) -> None:
        self.cdp = cdp
        self.cdp.send("Page.enable")
        self.cdp.send("Runtime.enable")

    def navigate(self, url: str) -> None:
        self.cdp.send("Page.navigate", {"url": url})

    def js(self, expression: str) -> Any:
        return self.cdp.evaluate(expression)

    def json(self, expression: str) -> Any:
        raw = self.cdp.evaluate(f"JSON.stringify({expression})")
        return json.loads(raw) if raw else None

    def wait(self, expression: str, timeout: float = 15.0) -> bool:
        return self.cdp.wait_for(expression, timeout=timeout)

    def dom(self) -> dict:
        return self.cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})["root"]

    def wait_for_node(self, timeout: float = 15.0, **kwargs):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            node = find_node(self.dom(), **kwargs)
            if node:
                return node
            time.sleep(0.2)
        return None

    def click(self, *, cls: str | None = None, tag: str | None = None, node_id: str | None = None,
              timeout: float = 10.0) -> bool:
        """Find a node and click it in one go.

        Resolving the node in the same snapshot matters: a fresh ``DOM.getDocument`` invalidates the
        node ids of the previous one, so a node found earlier cannot be clicked later.
        """
        node = self.wait_for_node(cls=cls, tag=tag, node_id=node_id, timeout=timeout)
        if not node:
            return False
        model = self.cdp.send("DOM.getBoxModel", {"nodeId": node["nodeId"]})["model"]
        quad = model.get("content") or model["border"]
        xs, ys = quad[0::2], quad[1::2]
        self.cdp.click(round(sum(xs) / 4), round(sum(ys) / 4))
        return True

    def box(self, *, cls: str | None = None, tag: str | None = None) -> dict | None:
        """The border box of a node, in one snapshot with the lookup."""
        node = self.wait_for_node(cls=cls, tag=tag)
        if not node:
            return None
        model = self.cdp.send("DOM.getBoxModel", {"nodeId": node["nodeId"]})["model"]
        quad = model.get("content") or model["border"]
        return {
            "left": round(min(quad[0::2])),
            "top": round(min(quad[1::2])),
            "right": round(max(quad[0::2])),
            "bottom": round(max(quad[1::2])),
        }

    def message(self, payload: dict) -> dict:
        """Ask the background the way the popup does, and get its answer."""
        raw = self.cdp.evaluate(
            "(async () => JSON.stringify(await (globalThis.browser || globalThis.chrome).runtime.sendMessage("
            + json.dumps(payload, ensure_ascii=False)
            + ")))()"
        )
        return as_json(raw)

    def message_from_content_world(self, tab_id: int, payload: dict) -> dict:
        """Send one message the way a *content script* does: from a page's isolated world, so the
        sender is that tab (which is the shape the background's host rule is written around)."""
        return content_world_message(self.cdp, tab_id, payload)

    def close(self) -> None:
        self.cdp.close()


def content_world_message(connection: Cdp, tab_id: int, payload: dict) -> dict:
    """One message sent from a tab's isolated world, so the sender has that tab.

    `chrome.scripting.executeScript` runs the snippet inside the page but *as the extension*, which
    is exactly what a content script is: the background then derives the host from the tab's URL.
    """
    script = (
        "(async () => { const [out] = await (globalThis.browser || globalThis.chrome).scripting.executeScript({"
        " target: { tabId: %d }, world: 'ISOLATED',"
        " func: async (payload) => await (globalThis.browser || globalThis.chrome).runtime.sendMessage(payload),"
        " args: [%s] }); return JSON.stringify(out && out.result); })()"
        % (tab_id, json.dumps(payload, ensure_ascii=False))
    )
    return as_json(connection.evaluate(script))


# ------------------------------------------------------------------------------------- scenario
def run_scenario(chrome_port: int, checks: Checks, vault_port: int, base: str, session, baseline: int,
                 extension: Path) -> None:
    extension_id = unpacked_id(extension)
    cdp_port = chrome_port

    worker_target = wait_for_target(
        cdp_port, lambda item: item.get("type") == "service_worker" and extension_id in item.get("url", "")
    )
    checks.check(
        "Chrome loaded the extension and started its service worker",
        bool(worker_target) and str(worker_target.get("url", "")).endswith("/" + SW_ENTRY),
        worker_target and worker_target.get("url"),
    )
    if not worker_target:
        return
    checks.equal("the manifest's background key is the service worker", worker_target["url"].rsplit("/", 1)[-1], SW_ENTRY)

    browser_target = wait_for_target(cdp_port, lambda item: item.get("type") == "page" and item.get("webSocketDebuggerUrl"))
    if not browser_target:
        checks.check("a page target exists to drive", False)
        return
    with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/version", timeout=5) as response:
        browser_ws = json.load(response)["webSocketDebuggerUrl"]
    browser = Cdp(browser_ws)

    # Point the add-on at the scratch vault before it can make a bridge call of its own: the stored
    # port is what every later call reads, and `configure()` is what caches it in the worker.
    def worker_call(callback, attempts: int = 4):
        """Run one call against the service worker, re-attaching and retrying each time.

        Chrome starts and stops a MV3 service worker whenever it likes: the target id changes when it
        restarts, and a worker that is still starting up answers nothing at all. So the target is
        resolved afresh per call, with a short socket timeout and a few retries, instead of holding
        one connection open for the whole scenario.
        """
        last_error = "no answer"
        for _ in range(attempts):
            target = wait_for_target(
                cdp_port,
                lambda item: item.get("type") == "service_worker" and extension_id in item.get("url", ""),
                timeout=8,
            )
            if not target:
                last_error = "no service worker target"
                time.sleep(1.0)
                continue
            connection = FastCdp(target["webSocketDebuggerUrl"])
            try:
                return callback(connection)
            except (TimeoutError, OSError, RuntimeError) as error:
                last_error = error
                time.sleep(1.0)
            finally:
                connection.close()
        raise SystemExit(f"the extension's service worker did not answer: {last_error!r}")

    def worker_eval(expression: str):
        return worker_call(lambda connection: connection.evaluate(expression))

    def worker_result(expression: str):
        """The same, for an expression that answers with JSON (a worker that never answers ends the
        run with a clear message instead of a traceback)."""
        try:
            return as_json(worker_eval(expression))
        except SystemExit as error:
            checks.check("the extension's service worker answers", False, str(error))
            return None

    def worker_message(tab_id: int, payload: dict) -> dict:
        return worker_call(lambda connection: content_world_message(connection, tab_id, payload))

    state = worker_result(
        "(async () => { await browser.storage.local.set({ port: %d, token: '', tokenPort: 0 });"
        " await client.configure(); client.token = '';"
        " return JSON.stringify({ port: client.port, namespaces: { browser: typeof browser,"
        " chrome: typeof chrome, aliased: browser === chrome },"
        " listenerBridge: String(chrome.runtime.onMessage.addListener).indexOf('sendResponse') > 0,"
        " serviceWorker: typeof importScripts === 'function' && typeof window === 'undefined' }); })()"
        % vault_port
    )
    if state is None:
        return
    checks.equal("the worker was pointed at the scratch vault", state.get("port"), vault_port)
    checks.check("the worker is a service worker, not a background page", state.get("serviceWorker") is True, state)
    checks.check(
        "the `browser` namespace exists in the worker (aliased on builds that lack it)",
        state.get("namespaces", {}).get("browser") == "object",
        state.get("namespaces"),
    )
    checks.check(
        "promise-returning message listeners are bridged onto sendResponse on Chrome",
        state.get("listenerBridge") is True,
        state,
    )

    demo = Page(Cdp(browser_target["webSocketDebuggerUrl"]))
    demo.navigate(f"{base}/login.html")
    loaded = demo.wait("document.readyState === 'complete' && document.getElementById('pass') !== null")
    checks.check("the demo login page loaded", loaded)
    if not loaded:
        return
    checks.check(
        "the content script was injected by Chrome itself",
        demo.wait(f"document.getElementById({json.dumps(HOST_ID)}) !== null"),
    )

    # 1. Nothing is filled before a click, and the icon is in the password field.
    checks.equal(
        "no field is filled on load",
        demo.json("{user: document.getElementById('user').value, pass: document.getElementById('pass').value,"
                  " otp: document.getElementById('otp').value}"),
        {"user": "", "pass": "", "otp": ""},
    )
    icon = demo.wait_for_node(cls="icon")
    checks.check("the vault icon is drawn (from inside a closed shadow root)", bool(icon))
    field = demo.json(
        "(() => { const r = document.getElementById('pass').getBoundingClientRect();"
        " return {left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width), height: Math.round(r.height)}; })()"
    )
    if icon and field:
        box = demo.box(cls="icon")
        inside = bool(box) and (
            box["left"] >= field["left"] - 2
            and box["right"] <= field["left"] + field["width"] + 2
            and box["top"] >= field["top"] - 2
            and box["bottom"] <= field["top"] + field["height"] + 2
        )
        checks.check("the icon sits inside the password field", inside, {"icon": box, "field": field})

    # 2. Clicking the icon lists the entry (metadata only), and clicking the entry fills the form.
    if icon:
        demo.click(cls="icon")
        row = demo.wait_for_node(cls="item")
        checks.check("clicking the icon opens the entry list", bool(row))
        if row:
            panel_text = " ".join(
                node_text(node) for node in find_nodes(demo.dom(), cls="panel")
            )
            checks.check("the panel names the entry", "دمو سایت" in panel_text, panel_text)
            checks.check("the panel shows the stored user name", USERNAME in panel_text, panel_text)
            checks.check(
                "the metadata lookup handed the page no password",
                PASSWORD not in panel_text and OTP_SECRET not in panel_text,
                panel_text,
            )
            checks.check("the entry row was clicked", demo.click(cls="item"))
            filled = demo.wait("document.getElementById('pass').value !== ''")
            checks.check("clicking the entry fills the form", filled)
            values = demo.json(
                "{user: document.getElementById('user').value, pass: document.getElementById('pass').value,"
                " otp: document.getElementById('otp').value}"
            )
            checks.equal("the user name was filled", values.get("user"), USERNAME)
            checks.equal("the password was filled", values.get("pass"), PASSWORD)
            expected = {totp_now(OTP_SECRET), totp_now(OTP_SECRET, at=time.time() - 30)}
            checks.check("a live one-time code was filled", values.get("otp") in expected, values)
            checks.check(
                "the fill fired input+change events (frameworks see a user edit)",
                (demo.json("window.__events") or {}).get("change", 0) >= 2,
                demo.json("window.__events"),
            )
            leak = demo.js(
                "(() => { const value = document.documentElement.outerHTML;"
                " const stores = [localStorage, sessionStorage].map((s) => JSON.stringify(s)).join('');"
                " const inDom = value.indexOf(%s) >= 0; const inStores = stores.indexOf(%s) >= 0;"
                " return inDom ? 'html' : inStores ? 'storage' : ''; })()"
                % (json.dumps(PASSWORD), json.dumps(PASSWORD))
            )
            checks.equal("the password is nowhere but the input value", leak, "")

    # 3. The real popup, opened the way the toolbar opens it. `chrome.action.openPopup()` gives the
    # popup an extension context with *no tab of its own* — which is the shape the background's host
    # rule is written around, and the only way to exercise it without weakening that rule. On a
    # Chrome build where `openPopup` is refused, the popup is opened as a tab instead and the two
    # host-dependent checks are reported as skipped rather than passed.
    demo_tab = int(
        worker_eval(
            "(async () => { const tabs = await chrome.tabs.query({});"
            " const tab = tabs.find((item) => String(item.url).endsWith('/login.html'));"
            " if (!tab) return 0; await chrome.tabs.update(tab.id, { active: true }); return tab.id; })()"
        )
        or 0
    )
    checks.check("the demo tab can be made the active tab", bool(demo_tab), demo_tab)
    opened = worker_eval(
        "chrome.action.openPopup().then(() => 'ok', (error) => 'refused: ' + (error && error.message))"
    )
    popup_meta = wait_for_target(
        cdp_port, lambda item: "/popup/popup.html" in item.get("url", "") and item.get("webSocketDebuggerUrl"), timeout=8
    )
    real_popup = bool(popup_meta)
    if not popup_meta:
        print(f"  note: chrome.action.openPopup() answered {opened!r}: opening the popup as a tab instead")
        browser.send("Target.createTarget", {"url": f"chrome-extension://{extension_id}/popup/popup.html"})
        popup_meta = wait_for_target(
            cdp_port, lambda item: "/popup/popup.html" in item.get("url", "") and item.get("webSocketDebuggerUrl")
        )
    if not popup_meta:
        checks.check("the popup opened", False, opened)
        return
    popup = Page(Cdp(popup_meta["webSocketDebuggerUrl"]))
    checks.check("the popup opened", popup.wait("document.getElementById('state') !== null"))
    checks.check("the popup was opened as a real action popup, with no tab of its own", real_popup, opened)
    popup.js("(async () => { await refresh(); })()")
    popup.wait("document.querySelectorAll('#list .entry').length > 0")
    state_text = popup.js("document.getElementById('state').textContent") or ""
    checks.check("the popup reports the vault is open, with its entry count", "باز است" in state_text, state_text)
    checks.equal("the popup shows the port it was configured with", popup.js("document.getElementById('port').value"), str(vault_port))
    entries = popup.json(
        "Array.prototype.map.call(document.querySelectorAll('#list .entry'), (element) => element.textContent.trim())"
    ) or []
    checks.equal("the popup lists the entry for the page's own host", len(entries), 1)
    checks.check(
        "the entry row names the site and the user",
        bool(entries) and "دمو سایت" in entries[0] and USERNAME in entries[0],
        entries,
    )
    note = popup.js("(document.querySelector('#list .note') || {}).textContent || ''") or ""
    checks.check(
        "the popup asked the tab what it can fill (the real ping path)",
        "فیلد ورود" in note,
        note or ("skipped: no real action popup on this build" if not real_popup else note),
    )
    # With no tab of its own, the popup *is* allowed to name the host — that is how it looks up the
    # active tab — and a host with no entry must simply come back empty.
    popup_other = popup.message({"type": "svb:candidates", "host": "example.com"}) if real_popup else {}
    checks.check(
        "the popup may name a host, and gets nothing for one with no entry",
        popup_other.get("ok") is True and len(popup_other.get("candidates") or []) == 0,
        popup_other or "skipped: no real action popup on this build",
    )

    # The second fill path: the popup hands the job to the background, which reaches or injects the
    # content script. Clear the fields first so the click has to do the work again.
    demo.js("['user', 'pass', 'otp'].forEach((id) => { document.getElementById(id).value = ''; })")
    if popup.wait_for_node(cls="entry"):
        checks.check("the popup's entry row was clicked", popup.click(cls="entry"))
        refilled = demo.wait("document.getElementById('pass').value !== ''")
        checks.check("clicking the popup's entry fills the page through the background", refilled)
        values = demo.json("{user: document.getElementById('user').value, pass: document.getElementById('pass').value}")
        checks.equal("the popup path filled the same values", values.get("pass"), PASSWORD)
        checks.equal("the popup path filled the user name too", values.get("user"), USERNAME)

    # 4. The one-time code reading surface: digits to the caller, never the secret, and one audited
    # reveal per "show me the code" — a second look is served from the worker's memory.
    read_payload = {"type": "svb:otp", "path": CREDENTIAL_PATH}
    read = worker_message(demo_tab, read_payload)
    checks.check("the background reads a live one-time code", read.get("ok") is True and read.get("live") is True, read)
    expected_codes = {totp_now(OTP_SECRET), totp_now(OTP_SECRET, at=time.time() - 30)}
    checks.check("the code matches an independent RFC 6238 calculation", read.get("code") in expected_codes, read)
    checks.check("no secret is handed to the caller", OTP_SECRET not in json.dumps(read), read)
    before = len(list(session.access_log(limit=400)))
    second = worker_message(demo_tab, read_payload)
    checks.check("a second look answers with a code too", second.get("ok") is True and bool(second.get("code")), second)
    checks.equal(
        "the second look needed no second reveal (the value was remembered in the worker)",
        len(list(session.access_log(limit=400))) - before,
        0,
    )
    # Forgetting is what closing the popup does; afterwards the next look reveals again.
    worker_eval("onOtpForget().then((answer) => JSON.stringify(answer))")
    forgotten_at = len(list(session.access_log(limit=400)))
    third = worker_message(demo_tab, read_payload)
    checks.check("after forgetting, a code is still readable", third.get("ok") is True, third)
    checks.check(
        "after forgetting, the vault is asked again (one more audited reveal)",
        len(list(session.access_log(limit=400))) - forgotten_at >= 1,
    )

    # 5. The sender's own tab decides the host: the same call made with a *different* host in the
    # message must still be answered for the tab it came from, or a page-facing surface could ask
    # for another site's credentials.
    spoofed = worker_message(demo_tab, {"type": "svb:candidates", "host": "example.com"})
    checks.check("a content script's lookup is answered", spoofed.get("ok") is True, spoofed)
    checks.equal("the host comes from the sender's tab, not from the message", spoofed.get("host"), "127.0.0.1")
    checks.equal("the entry for the tab's own host is offered", len(spoofed.get("candidates") or []), 1)

    # 6. Another host really does get nothing: the same page served as `localhost` in a second tab,
    # where the panel has to say so and no entry may be offered.
    other_target_id = browser.send(
        "Target.createTarget", {"url": f"{base.replace('127.0.0.1', 'localhost')}/login.html"}
    )["targetId"]
    other_meta = wait_for_target(
        cdp_port, lambda item: item.get("id") == other_target_id and item.get("webSocketDebuggerUrl")
    )
    if other_meta:
        other = Page(Cdp(other_meta["webSocketDebuggerUrl"]))
        checks.check("the other-host page loaded", other.wait("document.getElementById('pass') !== null"))
        other_tab = int(
            worker_eval(
                "(async () => { const tabs = await chrome.tabs.query({});"
                " const tab = tabs.find((item) => String(item.url).indexOf('localhost') > -1"
                " && String(item.url).endsWith('/login.html'));"
                " return tab ? tab.id : 0; })()"
            )
            or 0
        )
        checks.check("the second tab is a tab of its own", bool(other_tab), other_tab)
        lookup = worker_message(other_tab, {"type": "svb:candidates"})
        checks.check("the other host's lookup is answered", lookup.get("ok") is True, lookup)
        checks.equal("the other host is offered no entry", len(lookup.get("candidates") or []), 0)
        stolen = worker_message(other_tab, {"type": "svb:otp", "path": CREDENTIAL_PATH})
        checks.check(
            "the other host cannot read that entry's code",
            stolen.get("ok") is False and "این سایت" in (stolen.get("error") or {}).get("text", ""),
            stolen,
        )
        other_icon = other.wait_for_node(cls="icon")
        checks.check("the other host still gets the icon (it is a login page)", bool(other_icon))
        if other_icon:
            other.click(cls="icon")
            deadline = time.monotonic() + 12
            message_text = ""
            while time.monotonic() < deadline:
                panel = find_node(other.dom(), cls="msg")
                if panel:
                    message_text = node_text(panel)
                    if message_text and "…" not in message_text:
                        break
                time.sleep(0.25)
            checks.check("the other host's panel answered", bool(message_text) and "…" not in message_text, message_text)
            checks.check("the other host is told there is no entry", "نیست" in message_text, message_text)
            checks.check("the other host is not passed off as a broken bridge", "ببند" not in message_text, message_text)
            checks.equal("no candidate is offered to the other host", len(find_nodes(other.dom(), cls="item")), 0)
        other.close()

    popup.close()

    # 7. The vault's own record: what the add-on did, and what it never did.
    all_rows = list(session.access_log(limit=400))
    tools = [
        (row.get("tool"), row.get("source"), row.get("outcome"), row.get("target_path"))
        for row in all_rows[: max(0, len(all_rows) - baseline)]
    ]
    reveals = [row for row in tools if row[0] == "vault.browser_reveal"]
    allowed = [row for row in reveals if row[2] == "allow"]
    denied = [row for row in reveals if row[2] != "allow"]
    checks.check(
        "the vault audited the fills and the code reads (four allowed reveals)",
        len(allowed) >= 4,
        [row[0] for row in tools],
    )
    checks.check(
        "every reveal names the browser as its source and the entry's path",
        bool(reveals) and all(row[1] == "browser" and row[3] == CREDENTIAL_PATH for row in reveals),
        reveals,
    )
    checks.check(
        "the attempt made from the other host was refused, and audited as denied",
        len(denied) >= 1,
        reveals,
    )
    checks.check(
        "the metadata lookups were logged",
        sum(1 for row in tools if row[0] == "vault.browser_match") >= 2,
        [row[0] for row in tools],
    )
    checks.check(
        "the browser token was claimed",
        any(row[0] == "session.claim" and row[1] == "browser" for row in tools),
        [row for row in tools if row[0] == "session.claim"],
    )
    checks.check(
        "the add-on wrote nothing in the vault",
        not any(row[0] in ("write_file", "mkdir", "file_ops") for row in tools),
        [row for row in tools if row[0] in ("write_file", "mkdir", "file_ops")],
    )
    browser.close()


# --------------------------------------------------------------------------------------- driver
def start_chrome(binary: Path, profile: Path, port: int, extension: Path, log: Path) -> subprocess.Popen:
    handle = open(log, "wb")
    process = subprocess.Popen(
        [
            str(binary),
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--hide-scrollbars",
            "--window-size=1000,1100",
            "--enable-logging=stderr",
            f"--disable-extensions-except={extension}",
            f"--load-extension={extension}",
            "about:blank",
        ],
        stdout=handle,
        stderr=handle,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"chrome exited immediately; see {log}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1):
                return process
        except Exception:
            time.sleep(0.2)
    process.terminate()
    raise SystemExit(f"chrome did not open its debugging port; see {log}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", help="path to an extension-capable Chrome (Chrome for Testing or Chromium)")
    parser.add_argument("--ext", help="reuse an existing build instead of building one")
    parser.add_argument("--keep", action="store_true", help="keep the scratch dir and the Chrome profile")
    args = parser.parse_args()

    checks = Checks()
    binary = pick_chrome(args.chrome)
    print(f"chrome: {binary}")
    scratch = Path(tempfile.mkdtemp(prefix="svb-chrome-"))
    print(f"scratch: {scratch}")

    extension = Path(args.ext).resolve() if args.ext else scratch / "chrome-ext"
    if not args.ext:
        build = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "build-chrome.py"), "--out", str(extension)],
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            print(build.stdout + build.stderr)
            return 1
        print(build.stdout.strip())
    checks.check("the Chrome build has a manifest and a service worker entry point",
                 (extension / "manifest.json").is_file() and (extension / SW_ENTRY).is_file())
    manifest = json.loads((extension / "manifest.json").read_text(encoding="utf-8"))
    checks.equal("the build carries no gecko-only key", "browser_specific_settings" in manifest, False)
    checks.equal("the build asks Chrome for a service worker", manifest["background"].get("service_worker"), SW_ENTRY)

    session = seed_scratch_vault(scratch)
    web = None
    from vault.api.service import Service  # noqa: E402
    from vault.web.server import WebServer  # noqa: E402

    service = Service(session)
    web = WebServer(service, host="127.0.0.1", port=0, runtime_dir=session._runtime, keepalive=1.0)
    web.start()
    print(f"vault listener: http://127.0.0.1:{web.port}/  (bridge token: {'yes' if web.browser.token else 'no'})")
    checks.check("the scratch vault's bridge has its own token", bool(web.browser.token))
    baseline = len(list(session.access_log(limit=400)))

    handler_port = free_port()
    server = socketserver.ThreadingTCPServer(("127.0.0.1", handler_port), QuietDemoHandler)
    server.daemon_threads = True
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{handler_port}"
    print(f"demo pages: {base}/login.html")

    cdp_port = free_port()
    log = scratch / "chrome.log"
    chrome = start_chrome(binary, scratch / "profile", cdp_port, extension, log)
    try:
        run_scenario(cdp_port, checks, web.port, base, session, baseline, extension)
        if checks.failures:
            print("--- chrome log (tail) ---")
            print(log.read_text(errors="replace")[-3000:])
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=10)
        except subprocess.TimeoutExpired:
            chrome.kill()
        server.shutdown()
        if web is not None:
            web.stop()
        if not args.keep:
            shutil.rmtree(scratch, ignore_errors=True)

    print("")
    print(f"{checks.total - checks.failures}/{checks.total} checks passed")
    return 1 if checks.failures else 0


if __name__ == "__main__":
    sys.exit(main())
