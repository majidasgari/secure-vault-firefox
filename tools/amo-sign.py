#!/usr/bin/env python3
"""
amo-sign.py — sign this extension with Mozilla's addons.mozilla.org API v5.

Why not `web-ext sign`: this box cannot reach the npm registry (registry.npmjs.org
times out), so the whole flow is done here over plain HTTPS with the stdlib.

Credentials (never printed, never sent anywhere but addons.mozilla.org):
    line 1 = JWT issuer      (looks like `user:12345678:90`)
    line 2 = JWT secret      (the long base64-ish string AMO shows once)
  default path: <repo>/.amo-keys   (override with --keys PATH)

Usage:
    tools/amo-sign.py                 # upload → validate → sign → download
    tools/amo-sign.py --lint-only     # upload + validate, do not create a version

The signed .xpi lands in dist/signed/ and is what you install permanently via
about:addons → gear → "Install Add-on From File…".
"""
import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = 'https://addons.mozilla.org/api/v5'
REPO = Path(__file__).resolve().parent.parent


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def make_jwt(issuer: str, secret: str, ttl: int = 300) -> str:
    now = int(time.time())
    header = b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    payload = b64url(json.dumps(
        {'iss': issuer, 'jti': secrets.token_hex(8), 'iat': now, 'exp': now + ttl},
        separators=(',', ':')
    ).encode())
    signing_input = f'{header}.{payload}'.encode()
    signature = b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f'{header}.{payload}.{signature}'


def read_keys(path: Path) -> tuple[str, str]:
    if not path.is_file():
        sys.exit(f'missing credentials file: {path}\n'
                 f'  create it with the two lines AMO shows on\n'
                 f'  https://addons.mozilla.org/developers/addon/api/key/')
    lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    if len(lines) < 2:
        sys.exit(f'{path} must hold two non-empty lines: issuer, then secret')
    return lines[0], lines[1]


def request(token: str, method: str, url: str, *, data=None, body=None, headers=None):
    head = {'Authorization': f'JWT {token}'}
    head.update(headers or {})
    req = urllib.request.Request(url, data=data or body, method=method, headers=head)
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            return response.status, json.loads(response.read().decode() or '{}')
    except urllib.error.HTTPError as error:
        payload = error.read().decode(errors='replace')
        try:
            payload = json.dumps(json.loads(payload), indent=2)
        except Exception:
            pass
        return error.code, payload


def multipart(field: str, filename: str, content: bytes, extra: dict) -> tuple[bytes, str]:
    boundary = f'----hermes{secrets.token_hex(12)}'
    parts = []
    for key, value in extra.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
        )
    ctype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f'Content-Type: {ctype}\r\n\r\n'.encode()
    )
    parts.append(content)
    parts.append(f'\r\n--{boundary}--\r\n'.encode())
    return b''.join(parts), f'multipart/form-data; boundary={boundary}'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--keys', default=str(REPO / '.amo-keys'))
    parser.add_argument('--file', default=None, help='xpi to sign (default: newest dist/*.xpi)')
    parser.add_argument('--channel', default='unlisted', choices=['unlisted', 'listed'])
    parser.add_argument('--lint-only', action='store_true')
    parser.add_argument('--fetch-only', action='store_true',
                        help='do not upload: just download the signed file of the '
                             'manifest version already on AMO')
    args = parser.parse_args()

    issuer, secret = read_keys(Path(args.keys))
    token = make_jwt(issuer, secret)

    manifest = json.loads((REPO / 'extension/manifest.json').read_text())
    addon_id = manifest['browser_specific_settings']['gecko']['id']
    version = manifest['version']

    xpi = Path(args.file) if args.file else max(
        (REPO / 'dist').glob('*.xpi'), key=lambda p: p.stat().st_mtime, default=None
    )
    if not xpi or not xpi.is_file():
        sys.exit('no .xpi found — run tools/build.sh first')
    print(f'>> add-on  : {addon_id} {version}')
    print(f'>> upload  : {xpi} ({xpi.stat().st_size} bytes)')

    uuid = None
    if not args.fetch_only:
        body, ctype = multipart('upload', xpi.name, xpi.read_bytes(), {'channel': args.channel})
        status, result = request(token, 'POST', f'{API}/addons/upload/', data=body,
                                 headers={'Content-Type': ctype})
        if status not in (200, 201, 202):
            sys.exit(f'upload failed ({status}):\n{result}')
        uuid = result.get('uuid')
        print(f'>> upload ok, uuid={uuid}')

        detail = {}
        for attempt in range(60):
            status, detail = request(token, 'GET', f'{API}/addons/upload/{uuid}/')
            if status != 200:
                sys.exit(f'validation poll failed ({status}):\n{detail}')
            if detail.get('processed'):
                break
            time.sleep(3)
        else:
            sys.exit('validation did not finish in time')

        validation = detail.get('validation') or {}
        errors = validation.get('errors', 0)
        warnings = validation.get('warnings', 0)
        print(f'>> validation: valid={detail.get("valid")} errors={errors} warnings={warnings}')
        for message in (validation.get('messages') or [])[:20]:
            print(f'   [{message.get("type")}] {message.get("message")}'
                  + (f' ({message.get("description")})' if message.get('description') else ''))
        if not detail.get('valid'):
            sys.exit('the add-on did not validate — fix the messages above and re-upload')
        if args.lint_only:
            print('>> lint-only: stopping before signing')
            return 0

    payload = json.dumps({'upload': uuid or ''}).encode()
    created = {}
    if not args.fetch_only:
        status, created = request(
            token, 'POST',
            f'{API}/addons/addon/{urllib.parse.quote(addon_id, safe="")}/versions/',
            body=payload, headers={'Content-Type': 'application/json'}
        )
        if status == 404:
            print('>> add-on does not exist on AMO yet — creating it')
            payload = json.dumps({
                'slug': 'vault-autofill',
                'name': {'en-US': 'Vault Autofill'},
                'version': {'upload': uuid}
            }).encode()
            status, created = request(token, 'POST', f'{API}/addons/addon/', body=payload,
                                      headers={'Content-Type': 'application/json'})
        if status not in (200, 201, 202):
            sys.exit(f'version creation failed ({status}):\n{created}')

    file_info = {}
    for candidate in (
        created.get('file'),
        (created.get('latest_unlisted_version') or {}).get('file'),
        (created.get('current_version') or {}).get('file'),
    ):
        if isinstance(candidate, dict) and candidate.get('url'):
            file_info = candidate
            break

    if not file_info.get('url'):
        print('>> response had no file URL — asking for the version list')
        status, listed = request(
            token, 'GET',
            f'{API}/addons/addon/{urllib.parse.quote(addon_id, safe="")}/versions/'
            f'?filter=all_with_unlisted'
        )
        if status != 200 or not isinstance(listed, dict):
            sys.exit(f'could not list versions ({status}): {str(listed)[:800]}')
        for item in listed.get('results', []):
            if str(item.get('version')) == str(version):
                file_info = item.get('file') or {}

    print(f'>> submitted: version={version} file={file_info.get("id")} status={file_info.get("status")}')

    # AMO signs unlisted versions ASYNCHRONOUSLY: right after submission the
    # file still points at the unsigned upload (…-1.0.0.zip, status
    # `unreviewed`). It flips to `public` and a `.xpi` URL once Mozilla's
    # signing service is done, which is the artifact Firefox will accept.
    detail = {}
    url = None
    for attempt in range(60):
        status, detail = request(
            token, 'GET',
            f'{API}/addons/addon/{urllib.parse.quote(addon_id, safe="")}'
            f'/versions/{urllib.parse.quote(str(version), safe="")}/'
        )
        if not isinstance(detail, dict):
            # request() hands back the raw text when AMO answers with an error (the version can
            # still be propagating right after creation, or a transient 5xx): keep polling.
            print(f'   … version lookup answered {status}: {str(detail)[:120]}')
            time.sleep(10)
            continue
        candidate = (detail or {}).get('file') or {}
        if candidate.get('url', '').endswith('.xpi') and candidate.get('status') != 'disabled':
            url = candidate['url']
            file_info = candidate
            break
        print(f'   … waiting for the signature ({candidate.get("status")}, '
              f'{candidate.get("url", "").rsplit("/", 1)[-1]})')
        time.sleep(10)
    if not url:
        sys.exit('AMO never produced a signed file for this version — '
                 'check the version on addons.mozilla.org')
    print(f'>> signed: status={file_info.get("status")} size={file_info.get("size")} url={url}')

    out_dir = REPO / 'dist/signed'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f'{addon_id.split("@")[0]}-{version}-signed.xpi'
    try:
        req = urllib.request.Request(url, headers={'Authorization': f'JWT {token}'})
        with urllib.request.urlopen(req, timeout=180) as response:
            out_path.write_bytes(response.read())
    except urllib.error.HTTPError:
        with urllib.request.urlopen(url, timeout=180) as response:
            out_path.write_bytes(response.read())

    print(f'>> downloaded: {out_path} ({out_path.stat().st_size} bytes)')

    import zipfile
    with zipfile.ZipFile(out_path) as archive:
        entries = archive.namelist()
    signature = [n for n in entries if n.startswith('META-INF/'
                 ) and n.rsplit('/', 1)[-1].lower() in ('mozilla.rsa', 'cose.sig')]
    if not signature:
        sys.exit(f'{out_path.name} carries no Mozilla signature — Firefox will refuse it')
    print(f'>> verified: Mozilla signature present ({", ".join(signature)})')
    print(f'>> install it: about:addons → gear → "Install Add-on From File…" → {out_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
