# Secure Vault — log-in autofill for Firefox

Other language: [فارسی](README.fa.md).

**Firefox add-on for [Secure Vault](https://github.com/majidasgari/secure-vault)** — while the vault app is
running on this machine, it fills the user name and password stored in the vault's credential folder into
website login forms.

How it thinks: **nothing is filled automatically.** The add-on puts a small icon inside the fields; only when
you click it does it show the entries for that site, and picking one fills the fields. Every time a password
leaves the vault, one row is written to the vault's access log.

## The family — three repositories

This add-on is one of three clients that work on **one** vault:

| repository | what it is |
| --- | --- |
| [secure-vault](https://github.com/majidasgari/secure-vault) | The vault itself: the storage format and crypto, the Qt desktop app, the web UI, the MCP bridge, two-way S3 sync and the importers. The browser bridge and the access log live on that side too (`docs/BROWSER-AUTOFILL.md`). |
| [secure-vault-android](https://github.com/majidasgari/secure-vault-android) | The read-only Android client (Ganjineh): pulls the vault from the S3 bucket and offers browsing, search and one-time codes on the phone; it never writes. |
| **[secure-vault-firefox](https://github.com/majidasgari/secure-vault-firefox)** — this repository | The add-on documented in this file: on your click it fills the entries of the vault's credential folder into web forms. |

All three speak one on-disk format and one shared security model: the add-on is given only a narrow token
(`/api/autofill/*` and nothing else) and can neither read nor write anything else in the vault.

## What it does

- Detects login forms on any page (user name, password and, where present, the one-time-code field).
- Shows the entries for that site from the vault's credential folder (title, address, user name — **no
  password**).
- Fills the fields on click (never automatically), together with `input`/`change` events so web frameworks
  (React/Vue/…) see the change.
- Generates a live one-time code (TOTP) from an `otpauth://` value or from a seed stored in the entry.
- **Reading a one-time code in the popup:** under every entry that has a code a "show one-time code" button
  appears; clicking it shows the six-digit code (grouped in threes, like `287 082`) with a seconds countdown,
  a progress bar and a "copy" button, refreshing itself every 30 seconds. Until you click, no code is read,
  and every look writes one row to the vault's access log.
- Keyboard shortcut `Alt+Shift+L` on the active page fills the first suggested entry.
- **Two-step sign-in support:** on a page that only asks for the e-mail/user name (no password box, or one
  that is present but hidden) the e-mail field gets the icon as well.
- **Automatic activation:** if a tab was already open before the add-on was installed, the add-on injects
  itself into that tab; no page reload is needed.
- **No click goes silent:** if the page has no login form, both the in-field list and the popup say why.

## Requirements

- Firefox 142 or newer.
- The Secure Vault app running on this machine and **unlocked**. If the vault is locked, the popup says you
  must unlock it in the app and no password is fetched.
- The vault's built-in web service switched on (default `127.0.0.1:8788`). If you configured another port,
  enter it in the popup.

## Installing

**1) Temporary (for testing):** in Firefox open `about:debugging#/runtime/this-firefox` → "Load Temporary
Add-on…" → pick `extension/manifest.json`.

**2) Permanent:** install the signed `.xpi` (the output of `tools/build.sh` and `tools/amo-sign.py`) from
`about:addons` → gear → "Install Add-on From File…".

After installing, open the add-on's popup: if you see "Secure Vault is not running", start the app first, and
if needed enter and save the port in that same popup.

## How it works

```
[web page]  --(message)-->  [add-on background]  --(HTTP on 127.0.0.1)-->  [vault]
fields + icon              host taken from the tab URL      credential folder, access log
```

1. **The add-on connects to the vault** — the vault has an HTTP listener on the loopback (`127.0.0.1`). The
   add-on calls `POST /api/session/claim` with `{"scope": "browser"}` and receives a **browser-scoped token**;
   that token is valid only for the three calls `/api/autofill/status|match|reveal`, and with it nothing else
   in the vault can be read or written.
2. **The entry list (metadata only)** — when you click the icon, the add-on sends the page's host (taken from
   the tab's own URL, not from page content) and the vault returns the entries for that host: title, address,
   user name. **No password is sent at this stage.**
3. **Revealing a password (the only sensitive step)** — picking an entry makes the add-on call `reveal` for
   that path and that host; the vault checks that the entry is under the credential folder and belongs to that
   host, returns its fields and writes **one row to the access log** with `source=browser`.
4. **Filling** — the values are written into the fields with the native setter and `input`/`change` events. No
   other copy of the password lands anywhere on the page: not in HTML attributes, not in browser storage.

## Security model (summary)

- **Minimal reach on the vault side:** the add-on's token reaches only the credential folder and is valid only
  for those three calls. No other read/write route opens with it.
- **Host lock:** an entry that does not belong to the page's host is never handed over; another site cannot
  ask for your entries.
- **No automatic filling:** filling happens only on a user click. The icon and the list are built inside a
  closed Shadow DOM, so page scripts cannot click the options themselves.
- **Full audit:** every reveal writes one row to the vault's access log (host, entry path, time). Listing and
  index scans do not fill the log — only a password actually leaving the vault is logged.
- **Rate cap:** reveals per minute are capped on the vault side; beyond that they are temporarily refused.
- **One-time codes and the popup:** the code is still generated in the add-on's background page and the popup
  receives only the six digits — the seed (the `otpauth://` value) never reaches the popup page. Every "show
  code" is an audited reveal, just like filling; but so that the countdown does not become one vault read per
  second, the seed is kept after the first look **only in the memory of that background page**, for at most
  five minutes (cleared when the popup closes, when the vault locks and when the port changes). "Copy" puts
  only the six unformatted digits on the clipboard, not the grouped form shown on screen.
- **Off switch:** in the vault app → Settings → Web UI → "browser autofill" can be turned off; from that
  moment no browser call is answered.
- **What the add-on stores:** only the port number and that one revocable token. No password is written to the
  add-on's memory or the browser's storage.

## Tests

```bash
# 1) one-time-code logic (the standard RFC 6238 vectors) — no dependencies:
node tests/totp_test.js

# 2) end-to-end test in a real browser: a scratch vault is built, the add-on's code is loaded
#    into headless Chrome and the clicks are performed with real mouse events.
cd ../secure-vault && ./.venv/bin/python ../secure-vault-browser/tests/probe.py
```

The second test (80 checks) verifies: no field is filled before a click; the icon sits inside the field; the
entry list shows the right entries; after the click the user name/password/one-time code are written into the
fields; the password is found nowhere on the page except as the field value; another host gets no entry at
all; a **two-step** page (e-mail + hidden password box) gets the icon on the e-mail and leaves the hidden box
untouched; a **formless** page says explicitly that it has no field; an old (pre-bridge) vault is detected
correctly, is given the right message, and its whole-vault token is not stored; and exactly three reveal rows
with `source=browser` are recorded in the vault's log.

Since version 1.1.0 these are checked as well: no code is read before a click; the code that was read matches
an independent RFC 6238 computation in Python exactly; the grouped form on screen matches the six unformatted
digits on the clipboard; the seconds countdown and the progress bar appear; a second look within the same
minute is answered **without** re-reading the vault; and after "forget" (closing the popup) the vault is read
again.

## Building and signing

```bash
tools/build.sh          # the .xpi package in dist/
tools/amo-sign.py       # sign with a Mozilla account (keys in .amo-keys) → dist/signed/
```

## Repository layout

```
extension/
  manifest.json          version 3, Firefox 142+
  background.js          the only place that talks to the vault; message routing and the status badge
  lib/vault-client.js    the browser-bridge client: claim, status, match, reveal (+ port discovery)
  lib/totp.js            one-time code (RFC 6238) from otpauth:// or a base32 seed
  content/content.js     form detection, the in-field icon, the list, filling
  popup/                 status, the current tab's entries, one-time code, port setting
  icons/                 icons (generated by tools/make_icons.py)
tools/                   icon generation, packaging, signing
tests/                   TOTP unit test + real-browser end-to-end test
demo/login.html          sample login page for manual testing
demo/two-step.html       sample two-step page (e-mail + hidden password box)
```

## Troubleshooting

| symptom | cause and fix |
| --- | --- |
| popup: "Secure Vault is not running" | the app is not running, or its web service is off; start the app. |
| popup: "Secure Vault is locked" | unlock it in the app. |
| popup: "browser autofill is turned off in the vault" | the off switch in the vault's settings is on. |
| the icon does not appear in the field | open the popup: one row says "N login fields detected in this tab" or "no login field found on this page". If it says "not found", the add-on sees no form on that page (some pages build the field late or put it in an iframe); reload the page once. |
| I click the popup's entries and nothing happens | the popup writes what happened underneath the list (e.g. "no login field found on this page"). If it says "this tab is not available to the add-on", the page is restricted (`about:` or Firefox's own pages) and the add-on is not allowed to run there. |
| the icon does not appear on the e-mail field but the form is two-step | since version 1.0.2 the e-mail/user-name field gets the icon even when a password box is on the page too; if it still does not, reload the page. |
| "this entry does not belong to this site" | the entry belongs to another host; fix its "site" or "address" field in the vault. |
| there is no "show one-time code" button | that entry has no one-time-code field; put the `otpauth://…` value or a base32 seed in the entry's "one-time code" field in the vault. |
| the one-time code appears but the site rejects it | the computer's clock differs from the server's; sync the system clock (the code is generated from this machine's clock). |
| "this entry has no readable one-time code" | that field's value is neither `otpauth://`, nor a base32 seed, nor a numeric code; remove the unrecognisable text from the "one-time code" field. |
| "too many requests" | the per-minute reveal cap is full; wait a moment. |
| I changed the vault's port | enter the new number in the popup and save it. |

