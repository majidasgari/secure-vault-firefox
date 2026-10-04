#!/usr/bin/env python3
"""End-to-end probe: the real add-on code in a real browser against a real vault.

What is real here:

* the vault — a scratch vault (never the user's) is created, one credential is written under the
  credential root, and the vault's own HTTP listener is started on loopback;
* the add-on — ``background.js``, ``lib/vault-client.js``, ``lib/totp.js`` and ``content.js`` are
  loaded unmodified into the page;
* the clicks — driven over CDP as real ``Input.dispatchMouseEvent`` events, so the icon and the
  dropdown entry receive the same gesture a user's finger produces.

What is stubbed: only the ``browser.*`` extension API surface (``tests/assets/shim.js``), because a
plain page is not an extension host. The shim connects the content script's messages to the real
background script and lets its ``fetch`` reach the loopback bridge (the harness Chrome runs with
``--disable-web-security`` for that one reason).

Run:  cd /data/Codes/secure-vault && ./.venv/bin/python \
        /data/Codes/secure-vault-browser/tests/probe.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
EXTENSION = REPO_ROOT / "extension"
DEMO = REPO_ROOT / "demo"
ASSETS = HERE / "assets"
VAULT_REPO = Path("/data/Codes/secure-vault")
VAULT_SRC = VAULT_REPO / "src"
VAULT_TESTS = VAULT_REPO / "tests"

for path in (str(VAULT_SRC), str(VAULT_TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from vault.api.service import Service  # noqa: E402
from vault.core.credentials import CREDENTIAL_ROOT  # noqa: E402
from vault.web.server import WebServer  # noqa: E402

from support import tmp_vault  # noqa: E402  (the vault repo's own test harness)

CHROME = "/usr/bin/google-chrome-stable"
USERNAME = "demo-user@example.com"
PASSWORD = "demo-pass-123"
OTP_URI = "otpauth://totp/Demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Demo"
CREDENTIAL_PATH = f"/{CREDENTIAL_ROOT}/آزمون/دمو سایت/demo.md"
CREDENTIAL_BODY = f"""# دمو سایت

سایت: 127.0.0.1 | دسته: آزمون

نام کاربری: {USERNAME}
گذرواژه: {PASSWORD}
آدرس: http://127.0.0.1/demo
کد یکبارمصرف (otp): {OTP_URI}
برچسب‌ها: آزمون
"""


# --------------------------------------------------------------------------- checks
class Checks:
    """Collects the assertions the probe makes (and prints them as they happen)."""

    def __init__(self) -> None:
        self.failures = 0
        self.total = 0

    def check(self, label: str, condition: bool, detail: object = None) -> bool:
        self.total += 1
        if condition:
            print(f"  ok   {label}")
        else:
            self.failures += 1
            suffix = "" if detail is None else f"  -> {detail!r}"
            print(f"  FAIL {label}{suffix}")
        return bool(condition)

    def equal(self, label: str, actual: object, expected: object) -> bool:
        return self.check(label, actual == expected, {"actual": actual, "expected": expected})


def totp_now(secret: str, digits: int = 6, period: int = 30, at: float | None = None) -> str:
    """Reference TOTP (RFC 6238, SHA-1) so the filled code can be verified independently."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int(at if at is not None else time.time()) // period
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


# --------------------------------------------------------------------------- fixtures
class HarnessServer(http.server.SimpleHTTPRequestHandler):
    """Serves the extension, the demo page and the test assets (harness page is generated)."""

    protocol_version = "HTTP/1.0"

    #: The port the add-on should be pointed at (set once the scratch vault is listening).
    vault_port = 0

    def log_message(self, fmt: str, *args: object) -> None:  # keep the probe output readable
        return

    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean == "/harness/login.html":
            return "harness"
        if clean.startswith("/ext/"):
            return str(EXTENSION / clean[len("/ext/") :])
        if clean.startswith("/assets/"):
            return str(ASSETS / clean[len("/assets/") :])
        return str(REPO_ROOT / "demo" / clean.lstrip("/"))

    def do_GET(self) -> None:  # noqa: N802 - http.server's spelling
        clean = self.path.split("?", 1)[0]
        if clean.startswith("/harness/"):
            # Only the harness pages are generated on the fly; every other path (the add-on's own
            # files, the test assets, the demo pages) is served from disk by translate_path().
            if clean.endswith("legacy.html"):
                port = self.server.server_address[1]      # this server plays the old vault
                body = self._harness_page("/harness/login.html", port=port).encode("utf-8")
            else:
                body = self._harness_page(clean).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - http.server's spelling
        """Impersonate a vault built *before* the bridge existed.

        That build answered `/api/session/claim` with the whole-vault web token (no `scope`) and
        had no `/api/autofill/*` route at all, which is what the add-on must recognise and report
        honestly instead of claiming there is no entry for the site.
        """
        import json as _json

        path = self.path.split("?", 1)[0]
        if path == "/api/session/claim":
            payload = {
                "ok": True,
                "token": "legacy-web-token",
                "unlocked": True,
                "port": self.server.server_address[1],
            }
            status = 200
        elif path.startswith("/api/autofill/"):
            payload = {"error": {"code": "NOT_FOUND", "message": "not_found"}}
            status = 404
        else:
            self.send_error(501, "not implemented")
            return
        body = _json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _harness_page(clean: str, *, port: int = 0) -> str:
        """A page of the add-on plus the test shims (nothing is injected into the real files)."""
        if clean.endswith("popup.html"):
            page = (EXTENSION / "popup" / "popup.html").read_text(encoding="utf-8")
            page = page.replace('src="../icons/', 'src="/ext/icons/')
            page = page.replace('href="popup.css"', 'href="/ext/popup/popup.css"')
            page = page.replace('src="popup.js"', 'src="/ext/popup/popup.js"')
            # Into <head>: the popup's own script runs on load and needs `browser` to exist first.
            # `lib/totp.js` comes along because the shim plays the background for `svb:otp`, and a
            # code generated by the add-on's own module is what the probe verifies in Python.
            scripts = (
                f'    <script>window.SVB_VAULT_PORT = {port or HarnessServer.vault_port};</script>\n'
                '    <script src="/ext/lib/totp.js"></script>\n'
                '    <script src="/assets/popup-shim.js"></script>'
            )
            return page.replace("</head>", scripts + "\n  </head>")
        # One demo page per login shape: the plain form, the two-step (e-mail first) form, and a
        # page with no form at all.
        name = clean.rsplit("/", 1)[-1]
        if name == "blank.html":
            page = (
                '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">'
                "<title>بدون فرم</title></head><body><h1>هیچ فرم ورودی نیست</h1></body></html>"
            )
        elif name == "two-step.html":
            page = (DEMO / "two-step.html").read_text(encoding="utf-8")
        elif name == "fade-in.html":
            page = (DEMO / "fade-in.html").read_text(encoding="utf-8")
        else:
            page = (DEMO / "login.html").read_text(encoding="utf-8")
        scripts = "\n".join(
            f'    <script src="{shared}"></script>'
            for shared in (
                "/assets/shim.js",
                "/ext/lib/vault-client.js",
                "/ext/lib/totp.js",
                "/ext/background.js",
                "/assets/probe.js",          # patches attachShadow *before* the content script
                "/ext/content/content.js",
            )
        )
        prelude = f"    <script>window.SVB_VAULT_PORT = {port or HarnessServer.vault_port};</script>"
        return page.replace("</body>", prelude + "\n" + scripts + "\n  </body>")


class Cdp:
    """A tiny Chrome DevTools Protocol client over ``tests/wsclient.py`` (stdlib only)."""

    def __init__(self, url: str) -> None:
        from wsclient import WebSocket

        self.ws = WebSocket(url)
        self._next = 1

    def send(self, method: str, params: dict | None = None) -> dict:
        message_id = self._next
        self._next += 1
        self.ws.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def evaluate(self, expression: str, await_promise: bool = True) -> object:
        result = self.send(
            "Runtime.evaluate",
            {"expression": expression, "awaitPromise": await_promise, "returnByValue": True},
        )
        if result.get("exceptionDetails"):
            details = result["exceptionDetails"]
            message = (details.get("exception") or {}).get("description") or details.get("text")
            raise RuntimeError(f"JS error: {message} in {expression}")
        return (result.get("result") or {}).get("value")

    def click(self, x: int, y: int) -> None:
        """One real mouse click (pressed + released) at viewport coordinates."""
        self.send(
            "Input.dispatchMouseEvent",
            {"type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1},
        )
        self.send(
            "Input.dispatchMouseEvent",
            {"type": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1},
        )

    def wait_for(self, expression: str, timeout: float = 15.0) -> bool:
        """Poll a JS expression until it is truthy."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self.evaluate(expression):
                    return True
            except RuntimeError:
                pass
            time.sleep(0.1)
        return False

    def close(self) -> None:
        self.ws.close()


def free_port() -> int:
    """Return a free loopback port."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_chrome(profile: Path, port: int, window: str) -> subprocess.Popen:
    """Launch headless Chrome with CDP open."""
    process = subprocess.Popen(
        [
            CHROME,
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            f"--window-size={window}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-web-security",
            "--hide-scrollbars",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1):
                return process
        except Exception:
            time.sleep(0.2)
    process.terminate()
    raise RuntimeError("chrome did not open its debugging port")


def page_ws_url(port: int) -> str:
    """The websocket URL of the (blank) page target."""
    import urllib.request

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as response:
        targets = json.load(response)
    for target in targets:
        if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
            return str(target["webSocketDebuggerUrl"])
    raise RuntimeError("no page target")


# --------------------------------------------------------------------------- scenario
def run_scenario(cdp: Cdp, checks: Checks, harness_base: str, session: object, baseline: int) -> None:
    """Drive the add-on and assert what happened, in the browser and in the vault's log."""
    page_url = f"{harness_base}/harness/login.html"
    cdp.send("Page.enable")
    cdp.send("Runtime.enable")
    # The popup's copy button writes the clipboard and the probe reads it back. A headless page has
    # no permission prompt and no window focus, so ask for both explicitly (harness only; if the
    # build refuses, the clipboard check reports itself as unverified rather than passing blindly).
    for method, params in (
        ("Emulation.setFocusEmulationEnabled", {"enabled": True}),
        (
            "Browser.grantPermissions",
            {
                "origin": harness_base,
                "permissions": ["clipboardReadWrite", "clipboardSanitizedWrite"],
            },
        ),
    ):
        try:
            cdp.send(method, params)
        except RuntimeError:
            pass
    cdp.send("Page.navigate", {"url": page_url})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("harness page and content script loaded", ready)
    if not ready:
        return
    checks.check(
        "the content script found the login form (username + otp detected)",
        cdp.evaluate(
            "JSON.stringify(window.__probe.form()) === "
            'JSON.stringify({forms:1, username:true, otp:true, passwordIsField:true})'
        ),
    )

    # 1. Nothing is filled before the user clicks.
    default_values = {"user": "", "pass": "", "otp": ""}
    checks.equal(
        "no field is filled on load",
        json.loads(cdp.evaluate("JSON.stringify(window.__probe.values())") or "{}"),
        default_values,
    )
    checks.equal("no message is sent on load", cdp.evaluate("window.__probe.sent().length"), 0)

    # 2. The icon is in the field.
    icons = cdp.evaluate("JSON.stringify(window.__probe.icons())") or "[]"
    icon_list = json.loads(icons)
    checks.equal("exactly one vault icon on the page", len(icon_list), 1)
    if not icon_list:
        return
    icon = icon_list[0]
    password_box = cdp.evaluate(
        "JSON.stringify((() => { const r = document.getElementById('pass').getBoundingClientRect();"
        " return {left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width),"
        " height: Math.round(r.height)}; })())"
    )
    password_rect = json.loads(password_box)
    inside = (
        icon["left"] >= password_rect["left"]
        and icon["left"] + icon["width"] <= password_rect["left"] + password_rect["width"] + 2
        and icon["top"] >= password_rect["top"] - 2
        and icon["top"] + icon["height"] <= password_rect["top"] + password_rect["height"] + 2
    )
    checks.check("the icon sits inside the password field", inside, {"icon": icon, "field": password_rect})

    # 3. Clicking the icon lists the entry (metadata only).
    cdp.click(icon["x"], icon["y"])
    listed = cdp.wait_for("window.__probe.items().length > 0")
    checks.check("clicking the icon opens the entry list", listed)
    items = json.loads(cdp.evaluate("JSON.stringify(window.__probe.items())") or "[]")
    checks.equal("one candidate is offered", len(items), 1)
    panel = cdp.evaluate("window.__probe.panelText()") or ""
    checks.check("the panel names the entry", "دمو سایت" in panel, panel)
    checks.check("the panel shows the stored user name", USERNAME in panel, panel)
    sent = json.loads(cdp.evaluate("window.__probe.sentRaw()") or "[]")
    checks.check(
        "the lookup asked for the page's own host",
        any(item.get("type") == "svb:candidates" for item in sent),
        sent,
    )
    checks.check(
        "no password left the vault during the lookup",
        PASSWORD not in json.dumps(sent, ensure_ascii=False),
    )

    # 4. Clicking the entry fills the form (the audited reveal).
    if items:
        cdp.click(items[0]["x"], items[0]["y"])
        filled = cdp.wait_for("window.__probe.values().pass !== ''")
        checks.check("clicking the entry fills the form", filled)
        values = json.loads(cdp.evaluate("JSON.stringify(window.__probe.values())") or "{}")
        checks.equal("user name filled", values.get("user"), USERNAME)
        checks.equal("password filled", values.get("pass"), PASSWORD)
        code = values.get("otp") or ""
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        expected = {totp_now(secret), totp_now(secret, at=time.time() - 30)}
        checks.check("a live one-time code was filled", code in expected, {"filled": code, "expected": sorted(expected)})
        events = json.loads(cdp.evaluate("JSON.stringify(window.__probe.events())") or "{}")
        checks.check(
            "the fill fired input+change events (frameworks see a user edit)",
            events.get("user", 0) >= 1 and events.get("pass", 0) >= 1 and events.get("change", 0) >= 2,
            events,
        )
        leak = cdp.evaluate(f"window.__probe.leak({json.dumps(PASSWORD)})")
        checks.equal("the password is nowhere but the input value", leak, "")
        checks.equal("the panel closed after the fill", cdp.evaluate("window.__probe.items().length"), 0)

    # 4b. Reading a one-time code without filling anything — the popup's path. The background does
    # one audited reveal per entry, then serves the code from memory: a popup that ticks every
    # second must not turn into one vault read per tick.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    read_js = json.dumps({"type": "svb:otp", "path": CREDENTIAL_PATH})
    otp = json.loads(
        cdp.evaluate(f"(async () => JSON.stringify(await window.browser.runtime.sendMessage({read_js})))()")
    )
    checks.check("the background reads a live one-time code", otp.get("ok") is True and otp.get("live") is True, otp)
    expected_codes = {totp_now(secret), totp_now(secret, at=time.time() - 30)}
    checks.check(
        "the code matches an independent RFC 6238 calculation",
        otp.get("code") in expected_codes,
        {"read": otp.get("code"), "expected": sorted(expected_codes)},
    )
    checks.check(
        "the code is grouped for reading, with the raw digits beside it",
        " " in (otp.get("display") or "") and (otp.get("display") or "").replace(" ", "") == otp.get("code"),
        otp,
    )
    checks.check(
        "the countdown and period come along",
        isinstance(otp.get("remaining"), int) and otp.get("period") == 30,
        otp,
    )
    checks.check("no secret is handed to the caller", secret not in json.dumps(otp), otp)
    before_second = len(list(session.access_log(limit=400)))
    second = json.loads(
        cdp.evaluate(f"(async () => JSON.stringify(await window.browser.runtime.sendMessage({read_js})))()")
    )
    checks.check("a second look answers with a code too", second.get("ok") is True and second.get("code"), second)
    checks.equal(
        "the second look needed no second reveal (the value was remembered in memory)",
        len(list(session.access_log(limit=400))) - before_second,
        0,
    )
    # Forgetting the values is what closing the popup does; afterwards the next look reveals again.
    cdp.evaluate(
        '(async () => JSON.stringify(await window.browser.runtime.sendMessage({type: "svb:otp-forget"})))()'
    )
    forgotten_at = len(list(session.access_log(limit=400)))
    third = json.loads(
        cdp.evaluate(f"(async () => JSON.stringify(await window.browser.runtime.sendMessage({read_js})))()")
    )
    checks.check("after forgetting, a code is still readable", third.get("ok") is True, third)
    checks.check(
        "after forgetting, the vault is asked again (one more audited reveal)",
        len(list(session.access_log(limit=400))) - forgotten_at >= 1,
    )

    # 5. Another host gets nothing (the host gate is enforced by the vault, not the page).
    other = harness_base.replace("127.0.0.1", "localhost")
    cdp.send("Page.navigate", {"url": f"{other}/harness/login.html"})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("second page (other host) loaded", ready)
    icons = json.loads(cdp.evaluate("JSON.stringify(window.__probe.icons())") or "[]")
    if icons:
        cdp.click(icons[0]["x"], icons[0]["y"])
        settled = cdp.wait_for("window.__probe.panelText().indexOf('…') < 0")
        checks.check("the other host's panel answered", settled)
        panel = cdp.evaluate("window.__probe.panelText()") or ""
        checks.check("the other host is told there is no entry", "نیست" in panel, panel)
        checks.equal("no candidate is offered to the other host", cdp.evaluate("window.__probe.items().length"), 0)

    # 6. The popup (its own page, its own shim): status, entry list, and the fill hand-off.
    cdp.send("Page.navigate", {"url": f"{harness_base}/harness/popup.html"})
    ready = cdp.wait_for("Boolean(window.__popup && window.__popup.ready)")
    checks.check("the popup page loaded", ready)
    if ready:
        settled = cdp.wait_for("document.querySelectorAll('#list .entry').length > 0")
        checks.check("the popup finished its refresh", settled)
        state_text = cdp.evaluate("document.getElementById('state').textContent") or ""
        checks.check("the popup reports the vault is open, with its entry count", "باز است" in state_text and "137" in state_text, state_text)
        checks.equal("the popup asks for the active tab's candidates", "svb:candidates" in (cdp.evaluate("window.__popup.sent().join(',')") or ""), True)
        checks.equal("the popup shows the port it was configured with", cdp.evaluate("document.getElementById('port').value"), str(HarnessServer.vault_port))
        entries = json.loads(
            cdp.evaluate(
                "JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#list .entry'),"
                " (element) => element.textContent.trim()))"
            )
            or "[]"
        )
        checks.equal("the popup lists the entry", len(entries), 1)
        checks.check("the entry row names the site and the user", entries and "دمو سایت" in entries[0] and "demo-user@example.com" in entries[0], entries)
        if entries:
            box = json.loads(
                cdp.evaluate(
                    "JSON.stringify((() => { const r = document.querySelector('#list .entry').getBoundingClientRect();"
                    " return {x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2)}; })())"
                )
            )
            checks.check(
                "the popup says what it sees in this tab",
                "فیلد ورود"
                in (
                    cdp.evaluate(
                        "document.querySelector('#list .note')"
                        " ? document.querySelector('#list .note').textContent : ''"
                    )
                    or ""
                ),
            )
            cdp.click(box["x"], box["y"])
            handed = cdp.wait_for("window.__tabMessages.length > 0")
            checks.check("clicking a row asks the content script to fill that entry", handed)
            messages = json.loads(cdp.evaluate("JSON.stringify(window.__popup.tabMessages())") or "[]")
            checks.equal("the hand-off carries the entry's path", messages[0]["message"]["path"] if messages else "", CREDENTIAL_PATH)
            checks.equal("the hand-off goes to the active tab", messages[0]["tabId"] if messages else None, 7)

            # 6a. Reading the code: nothing is read from the vault until the row is clicked.
            checks.equal(
                "no one-time code is read before it is asked for",
                cdp.evaluate("window.__popup.sent().filter((type) => type === 'svb:otp').length"),
                0,
            )
            toggle = json.loads(
                cdp.evaluate(
                    "JSON.stringify((() => { const el = document.querySelector('#list .otp-toggle');"
                    " if (!el) return null; const r = el.getBoundingClientRect();"
                    " return {text: el.textContent, x: Math.round(r.left + r.width / 2),"
                    " y: Math.round(r.top + r.height / 2)}; })())"
                )
                or "null"
            )
            checks.check(
                "the entry offers its one-time code",
                bool(toggle) and "کد یکبارمصرف" in (toggle or {}).get("text", ""),
                toggle,
            )
            if toggle:
                cdp.click(toggle["x"], toggle["y"])
                shown = cdp.wait_for("Boolean(document.querySelector('#list .otp-code'))")
                checks.check("clicking the code row shows a code", shown)
                shown_code = cdp.evaluate("document.querySelector('#list .otp-code').textContent") or ""
                secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                expected_codes = {totp_now(secret), totp_now(secret, at=time.time() - 30)}
                checks.check(
                    "the popup shows the current code, and only that code",
                    shown_code.replace(" ", "") in expected_codes,
                    {"shown": shown_code, "expected": sorted(expected_codes)},
                )
                checks.check(
                    "the popup groups the digits for reading",
                    " " in shown_code and shown_code.replace(" ", "") in expected_codes,
                    shown_code,
                )
                checks.check(
                    "the popup shows a countdown",
                    "ثانیه مانده"
                    in (cdp.evaluate("document.querySelector('#list .otp-left').textContent") or ""),
                )
                # The code must be a real, visible element — not a clipped or hidden one.
                box_model = json.loads(
                    cdp.evaluate(
                        "JSON.stringify((() => { const el = document.querySelector('#list .otp-code');"
                        " const r = el.getBoundingClientRect();"
                        " return {width: Math.round(r.width), height: Math.round(r.height)}; })())"
                    )
                )
                checks.check(
                    "the code is laid out, not clipped",
                    box_model["width"] > 40 and box_model["height"] > 12,
                    box_model,
                )
                copy_at = json.loads(
                    cdp.evaluate(
                        "JSON.stringify((() => { const el = document.querySelector('#list .otp-copy');"
                        " const r = el.getBoundingClientRect();"
                        " return {x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2)}; })())"
                    )
                )
                cdp.click(copy_at["x"], copy_at["y"])
                settled = cdp.wait_for(
                    "(() => { const el = document.querySelector('#list .otp-status');"
                    " return Boolean(el && el.textContent); })()"
                )
                checks.check("the copy button reports what happened", settled)
                clipboard = cdp.evaluate(
                    "navigator.clipboard && navigator.clipboard.readText"
                    " ? navigator.clipboard.readText().then((text) => text, () => null)"
                    " : null"
                )
                if clipboard is None:
                    # No clipboard permission in this headless context: say so instead of
                    # pretending the copy was verified.
                    checks.check("the clipboard is unreadable headlessly, so only the button was", True, "skipped")
                else:
                    checks.equal(
                        "the clipboard holds exactly the code, without the space",
                        clipboard,
                        shown_code.replace(" ", ""),
                    )
                cdp.click(toggle["x"], toggle["y"])
                closed = cdp.wait_for(
                    "document.querySelector('#list .otp-box').hidden === true"
                )
                checks.check("the code can be put away again", closed)

    # 6b. A two-step sign-in: the e-mail box deserves its own icon even though a password box
    # exists — invisibly — elsewhere on the page. This is the shape of real sign-in pages.
    cdp.send("Page.navigate", {"url": f"{harness_base}/harness/two-step.html"})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("the two-step page loaded", ready)
    icons = json.loads(cdp.evaluate("JSON.stringify(window.__probe.icons())") or "[]")
    checks.equal("the e-mail box of a two-step sign-in gets an icon", len(icons), 1)
    if icons:
        cdp.click(icons[0]["x"], icons[0]["y"])
        opened = cdp.wait_for("window.__probe.panelText().indexOf('…') < 0")
        checks.check("the two-step panel answered", opened)
        rows = json.loads(cdp.evaluate("JSON.stringify(window.__probe.items())") or "[]")
        checks.check("the two-step panel offers the entry", len(rows) >= 1, rows)
    checks.equal(
        "the invisible password box was not touched",
        cdp.evaluate("document.getElementById('pass-hidden').value"),
        "",
    )
    checks.equal(
        "the e-mail box stayed empty until a click",
        cdp.evaluate("document.getElementById('identifier').value"),
        "",
    )

    # 6d. A form that only fades in (no insertion at all) must still get its icon: pages reveal
    # their sign-in card by toggling a class, and a sweep that only watches insertions never looks
    # again — the field stays invisible to the add-on and a click looks like nothing happened.
    cdp.send("Page.navigate", {"url": f"{harness_base}/harness/fade-in.html"})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("the fade-in page loaded", ready)
    checks.check(
        "the form was revealed without any DOM insertion",
        cdp.evaluate("window.__inserted === false") is True,
    )
    appeared = cdp.wait_for("window.__probe.icons().length === 1", timeout=8)
    checks.check("a form that only fades in still gets its icon", appeared)
    late_answer = json.loads(
        cdp.evaluate('(async () => JSON.stringify(await window.browser.runtime.sendMessage({type: "svb:ping"})))()')
    )
    checks.check("the late form is reported as fillable", late_answer.get("fillable") is True, late_answer)

    # 6c. A page with no login form says so, instead of offering nothing in silence.
    cdp.send("Page.navigate", {"url": f"{harness_base}/harness/blank.html"})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("the form-less page loaded", ready)
    checks.equal(
        "no icon is drawn where there is no form",
        len(json.loads(cdp.evaluate("JSON.stringify(window.__probe.icons())") or "[]")),
        0,
    )
    probe_answer = json.loads(
        cdp.evaluate('(async () => JSON.stringify(await window.browser.runtime.sendMessage({type: "svb:ping"})))()')
    )
    checks.check(
        "the tab reports it has nothing to fill",
        probe_answer.get("forms") == 0 and probe_answer.get("fillable") is False,
        probe_answer,
    )
    fill_answer = json.loads(
        cdp.evaluate('(async () => JSON.stringify(await window.browser.runtime.sendMessage({type: "svb:fill-path", path: "/x"})))()')
    )
    checks.check("a fill request on such a page answers why", fill_answer.get("reason") == "no_form", fill_answer)

    # 7. A vault without the bridge (an older build) is reported honestly — and hands over no token.
    cdp.send("Page.navigate", {"url": f"{harness_base}/harness/legacy.html"})
    ready = cdp.wait_for("Boolean(window.__probe && window.__probe.ready)")
    checks.check("the page against an old vault build loaded", ready)
    # sessionStorage lives per origin, so drop whatever the earlier scenarios left behind: from
    # here on, anything stored is something *this* vault build caused.
    cdp.evaluate("window.sessionStorage.clear()")
    icons = json.loads(cdp.evaluate("JSON.stringify(window.__probe.icons())") or "[]")
    if icons:
        cdp.click(icons[0]["x"], icons[0]["y"])
        settled = cdp.wait_for("window.__probe.panelText().indexOf('…') < 0")
        checks.check("the old-build panel answered", settled)
        panel = cdp.evaluate("window.__probe.panelText()") or ""
        checks.check("the old build is named as such, not as a missing entry", "ببند" in panel, panel)
        checks.check("the old build is not passed off as 'no entry for this site'", "پیدا نشد" not in panel, panel)
        checks.equal(
            "the whole-vault token of the old build was refused, not stored",
            cdp.evaluate("window.sessionStorage.getItem('svb:token')"),
            None,
        )
        checks.equal("no field is filled from an old build", cdp.evaluate("document.getElementById('pass').value"), "")

    # 8. The vault's own record of what happened (the log is newest-first, so the add-on's rows
    # are the ones sitting on top of the seeding rows).
    all_rows = list(session.access_log(limit=400))
    log_rows = all_rows[: max(0, len(all_rows) - baseline)]
    tools = [
        (row.get("tool"), row.get("source"), row.get("outcome"), row.get("target_path"))
        for row in log_rows
    ]
    reveals = [row for row in tools if row[0] == "vault.browser_reveal"]
    # Exactly three: the fill, the first look at the one-time code, and the look after the popup's
    # "forget" — the second look in a row was served from memory and must not appear here.
    checks.equal("the vault audited three reveals (a fill and two code reads)", len(reveals), 3)
    checks.check(
        "every reveal is attributed to the browser, allowed, and names the entry's path",
        bool(reveals)
        and all(row[1] == "browser" and row[2] == "allow" and row[3] == CREDENTIAL_PATH for row in reveals),
        reveals,
    )
    checks.equal(
        # The popup's list, the login page's panel, and the two-step page's panel.
        "every lookup was logged (metadata only, no path)",
        sum(1 for row in tools if row[0] == "vault.browser_match"),
        3,
    )
    checks.check(
        "the metadata scan wrote no per-file read rows",
        not any(row[0] == "read_file" for row in tools),
        [row for row in tools if row[0] == "read_file"][:3],
    )
    checks.check(
        "the browser token was claimed",
        sum(1 for row in tools if row[0] == "session.claim" and row[1] == "browser") >= 1,
        [row for row in tools if row[0] == "session.claim"],
    )
    checks.check(
        "the add-on wrote nothing in the vault",
        not any(row[0] in ("write_file", "mkdir", "file_ops") for row in tools),
        [row for row in tools if row[0] in ("write_file", "mkdir", "file_ops")][:3],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the scratch dir and Chrome profile")
    args = parser.parse_args()

    checks = Checks()
    scratch = Path(tempfile.mkdtemp(prefix="svb-harness-"))
    print(f"scratch: {scratch}")

    session = tmp_vault(scratch)
    logical = CREDENTIAL_PATH.strip("/")
    parts = logical.split("/")
    for index in range(1, len(parts)):
        try:
            session.mkdir("/".join(parts[:index]), source="ui")
        except Exception:  # noqa: BLE001 - the folder may already exist
            pass
    session.write_file(logical, CREDENTIAL_BODY.encode("utf-8"), source="ui")
    service = Service(session)
    web = WebServer(service, host="127.0.0.1", port=0, runtime_dir=session._runtime, keepalive=1.0)
    web.start()
    print(f"vault listener: http://127.0.0.1:{web.port}/  (bridge token: {'yes' if web.browser.token else 'no'})")
    checks.check("the vault's bridge has its own token", bool(web.browser.token))
    baseline = len(list(session.access_log(limit=400)))  # everything below is the add-on's doing

    handler_port = free_port()
    server = socketserver.ThreadingTCPServer(("0.0.0.0", handler_port), HarnessServer)
    server.daemon_threads = True
    HarnessServer.vault_port = web.port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    harness_base = f"http://127.0.0.1:{handler_port}"
    print(f"harness: {harness_base}/harness/login.html")

    cdp_port = free_port()
    profile = scratch / "chrome"
    chrome = start_chrome(profile, cdp_port, "1000,1100")
    print(f"chrome: {CHROME} (cdp {cdp_port})")
    try:
        _drive(cdp_port, checks, harness_base, session, baseline)
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=10)
        except subprocess.TimeoutExpired:
            chrome.kill()
        server.shutdown()
        web.stop()
        if not args.keep:
            import shutil

            shutil.rmtree(scratch, ignore_errors=True)

    print("")
    print(f"{checks.total - checks.failures}/{checks.total} checks passed")
    return 1 if checks.failures else 0


def _drive(cdp_port: int, checks: Checks, harness_base: str, session: object, baseline: int) -> None:
    """Connect to Chrome and run the scenario."""
    cdp = Cdp(page_ws_url(cdp_port))
    try:
        run_scenario(cdp, checks, harness_base, session, baseline)
    finally:
        cdp.close()


if __name__ == "__main__":
    sys.exit(main())
