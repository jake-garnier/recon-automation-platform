#!/usr/bin/env python3
"""
capture_session.py — capture an authenticated session from your local Chrome
via the Chrome DevTools Protocol, emit Playwright `storage_state.json`,
optionally upload to the Kali credential store via SSH.

Why CDP and not Playwright codegen / a browser extension:
  - You log in normally on your Mac (1Password autofill, U2F, MFA all work)
  - HttpOnly cookies are captured (extensions can't read them from JS)
  - Works on Chromium-derivatives (Brave, Edge, Arc) that share the CDP API
  - Single Python file, no extension install, no Playwright dep on the Mac

Workflow:
  1. Quit Chrome (or use a separate user-data-dir).
  2. Start Chrome with remote-debugging enabled:
       open -na "Google Chrome" --args \\
         --remote-debugging-port=9222 \\
         --user-data-dir=/tmp/chrome-recon
  3. Log into the target program normally. Make sure the tab is on the
     authenticated origin (e.g. app.hubspot.com after login).
  4. Run this script:
       python3 capture_session.py <program-handle> --origin https://app.hubspot.com
     (origin defaults to the first matching tab)
  5. Optionally push to Kali:
       --upload kali@<KALI_TS_IP>
     Calls `python3 credential_store.py store` over SSH.

Output: <program>.json on the local filesystem (Playwright storage_state schema).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

# WebSocket dep — websocket-client is small + ubiquitous
try:
    import websocket  # pip install websocket-client
except ImportError:
    sys.stderr.write(
        "FATAL: pip install websocket-client\n"
        "  (this script runs on your Mac, not on Kali)\n"
    )
    sys.exit(2)


DEBUG_PORT = 9222


def _list_tabs(port: int) -> list[dict]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=3) as r:
        return json.loads(r.read())


def _find_tab(tabs: list[dict], origin: str | None) -> dict | None:
    """Pick the best tab. If origin given, match URL prefix. Else first 'page'."""
    pages = [t for t in tabs if t.get("type") == "page"]
    if origin:
        for t in pages:
            url = t.get("url", "")
            if url.startswith(origin):
                return t
        # No exact match — print available and exit
        sys.stderr.write(f"no tab matching {origin}. Open tabs:\n")
        for t in pages:
            sys.stderr.write(f"  - {t.get('url', '<no-url>')}\n")
        return None
    return pages[0] if pages else None


_msg_id = 0


def _cdp_call(ws, method: str, params: dict | None = None) -> dict:
    """Send a CDP command, wait for response, return result."""
    global _msg_id
    _msg_id += 1
    mid = _msg_id
    ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
    # CDP can interleave events with our response — drain until we see our id
    while True:
        raw = ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == mid:
            if "error" in msg:
                raise RuntimeError(f"CDP {method} error: {msg['error']}")
            return msg.get("result", {})


def _to_playwright_cookies(cdp_cookies: list[dict]) -> list[dict]:
    """Convert CDP Network.Cookie to Playwright storage_state cookie."""
    out = []
    for c in cdp_cookies:
        pw = {
            "name": c["name"],
            "value": c["value"],
            "domain": c["domain"],
            "path": c.get("path", "/"),
            # CDP expires is unix seconds float; -1 / 0 means session
            "expires": int(c["expires"]) if c.get("expires", 0) > 0 else -1,
            "httpOnly": bool(c.get("httpOnly", False)),
            "secure": bool(c.get("secure", False)),
        }
        # sameSite: CDP says "Strict"/"Lax"/"None"/"" or sometimes absent
        ss = c.get("sameSite", "")
        if ss in ("Strict", "Lax", "None"):
            pw["sameSite"] = ss
        out.append(pw)
    return out


def _get_localstorage(ws, origin: str) -> list[dict]:
    """Evaluate localStorage in the current page context.
    We can only read localStorage for the page's current origin; for
    cross-origin storage you'd need to navigate first.
    """
    res = _cdp_call(ws, "Runtime.evaluate", {
        "expression":
            "JSON.stringify(Object.keys(localStorage).map(k => "
            "({name: k, value: localStorage.getItem(k)})))",
        "returnByValue": True,
    })
    try:
        return json.loads(res["result"]["value"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return []


def capture(port: int, origin: str | None) -> dict:
    tabs = _list_tabs(port)
    if not tabs:
        raise RuntimeError(
            f"no Chrome tabs visible on port {port}. Is Chrome started with "
            f"--remote-debugging-port={port} --user-data-dir=...?"
        )
    tab = _find_tab(tabs, origin)
    if not tab:
        raise RuntimeError("no matching tab")
    ws_url = tab["webSocketDebuggerUrl"]
    page_origin = urllib.parse.urlsplit(tab["url"])
    page_origin = f"{page_origin.scheme}://{page_origin.netloc}"
    sys.stderr.write(f"capturing from tab: {tab['url']}\n")

    ws = websocket.create_connection(ws_url, timeout=10)
    try:
        # All cookies for ALL origins the browser knows about, including HttpOnly
        cookies = _cdp_call(ws, "Network.getAllCookies")["cookies"]
        localstorage = _get_localstorage(ws, page_origin)
    finally:
        ws.close()

    state = {
        "cookies": _to_playwright_cookies(cookies),
        "origins": [
            {
                "origin": page_origin,
                "localStorage": localstorage,
            }
        ] if localstorage else [],
    }
    sys.stderr.write(
        f"captured {len(state['cookies'])} cookies, "
        f"{len(localstorage)} localStorage entries from {page_origin}\n"
    )
    return state


def upload_to_kali(state: dict, ssh_target: str, handle: str,
                    auth_type: str = "storage_state",
                    notes: str = "", account_email: str = "",
                    probe_url: str = "", expected_status: int | None = None) -> None:
    """SSH to Kali and call credential_store.py to store the captured state."""
    payload = json.dumps(state)
    # We use base64 to avoid SSH-arg-list quoting nightmares
    import base64
    b64 = base64.b64encode(payload.encode()).decode()
    # Python heredoc on the remote side
    remote = f"""
cd /home/kali/apps/hackerOne
python3 - <<'PYEOF'
import base64, sys
sys.path.insert(0, '.')
import credential_store
state = base64.b64decode({b64!r}).decode()
import json
parsed = json.loads(state)
rid = credential_store.store(
    program_handle={handle!r},
    auth_type={auth_type!r},
    value=parsed,
    notes={notes!r},
    account_email={account_email!r},
    probe_url={probe_url!r},
    expected_status={expected_status!r},
)
print(f"stored credential id={{rid}} for {handle}")
PYEOF
"""
    subprocess.run(["ssh", ssh_target, remote], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("handle", help="Program handle (e.g. hubspot, algolia)")
    ap.add_argument("--port", type=int, default=DEBUG_PORT,
                    help=f"CDP port (default {DEBUG_PORT})")
    ap.add_argument("--origin", default=None,
                    help="Match tab by URL prefix (e.g. https://app.hubspot.com)")
    ap.add_argument("--out", default=None,
                    help="Local output JSON path (default: <handle>.json)")
    ap.add_argument("--upload", default=None,
                    help="SSH target to upload to (e.g. kali@<KALI_TS_IP>)")
    ap.add_argument("--notes", default="",
                    help="Free-text notes (tier, capture context, etc.)")
    ap.add_argument("--email", default="",
                    help="Account email (for dashboard display)")
    ap.add_argument("--probe-url", default="",
                    help="URL to probe for liveness (e.g. https://app.target.com/api/v1/me)")
    ap.add_argument("--expected-status", type=int, default=None,
                    help="Expected HTTP status from probe-url (e.g. 200)")
    args = ap.parse_args()

    state = capture(args.port, args.origin)

    out_path = Path(args.out or f"{args.handle}.json")
    out_path.write_text(json.dumps(state, indent=2))
    out_path.chmod(0o600)
    print(f"wrote {out_path} (cookies={len(state['cookies'])}, "
          f"origins={len(state['origins'])})")

    if args.upload:
        upload_to_kali(
            state, args.upload, args.handle,
            notes=args.notes, account_email=args.email,
            probe_url=args.probe_url, expected_status=args.expected_status,
        )
        print(f"uploaded to {args.upload}")


if __name__ == "__main__":
    main()
