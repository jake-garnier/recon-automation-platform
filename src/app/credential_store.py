"""
credential_store.py — encrypted per-program credential storage.

Plaintext credentials never touch disk except encrypted via age. Decryption
happens in-process when a tool fetches a credential. The age identity lives
at AGE_KEY_PATH (default /home/kali/.age/key.txt, mode 0600).

Threat model: single-user Kali VM, recon-agent runs as systemd User=kali.
Anyone with `kali` shell can decrypt. Acceptable for this deployment.
Upgrade path: age-plugin-tpm once VM 103 has a vTPM attached.

Public API:
    store(handle, auth_type, value, **kwargs)       → id
    get(handle, auth_type=None)                     → dict | None  (most-recent active row)
    list_all(status=None)                           → list[dict]
    mark_validated(cred_id, ok: bool, error="")     → None
    delete(cred_id)                                 → None
    write_storage_state_file(handle, path: Path)    → Path  (writes plaintext to tmp)

Imports gracefully no-op if pyrage isn't installed (callers can fall back
to "no auth available" without crashing the daemon).
"""
from __future__ import annotations

import json
import os
import stat
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from app.db import get_connection

AGE_KEY_PATH = Path(os.environ.get(
    "AGE_KEY_PATH", "/home/kali/.age/key.txt"
))

# Lazy-loaded singletons
_IDENT = None
_RECIP = None
_PYRAGE_AVAILABLE = None


def _ensure_pyrage():
    """Return True if pyrage is importable and an age identity is loaded.

    On first call, loads the identity from AGE_KEY_PATH. Subsequent calls
    are cached. Caller can check this to decide whether to skip credential
    features (e.g. for environments where pyrage isn't installed yet)."""
    global _IDENT, _RECIP, _PYRAGE_AVAILABLE
    if _PYRAGE_AVAILABLE is not None:
        return _PYRAGE_AVAILABLE
    try:
        import pyrage  # noqa: F401
    except ImportError:
        _PYRAGE_AVAILABLE = False
        return False
    if not AGE_KEY_PATH.exists():
        sys.stderr.write(
            f"[credential_store] AGE_KEY_PATH {AGE_KEY_PATH} missing — "
            "run bootstrap_age_identity() or `age-keygen -o {AGE_KEY_PATH}`\n"
        )
        _PYRAGE_AVAILABLE = False
        return False
    # Check mode is 0600 (paranoid; refuse to load a world-readable key)
    mode = AGE_KEY_PATH.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.stderr.write(
            f"[credential_store] AGE_KEY_PATH {AGE_KEY_PATH} has unsafe mode "
            f"{oct(mode)} — must be 0600 (run `chmod 600 {AGE_KEY_PATH}`)\n"
        )
        _PYRAGE_AVAILABLE = False
        return False
    import pyrage
    # age-keygen output format: 3 lines (created-at comment, public-key
    # comment, "AGE-SECRET-KEY-..."). The last non-empty non-comment line
    # is the identity.
    secret_lines = [
        ln.strip() for ln in AGE_KEY_PATH.read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not secret_lines:
        sys.stderr.write(
            f"[credential_store] no AGE-SECRET-KEY line in {AGE_KEY_PATH}\n"
        )
        _PYRAGE_AVAILABLE = False
        return False
    try:
        _IDENT = pyrage.x25519.Identity.from_str(secret_lines[-1])
        _RECIP = _IDENT.to_public()
    except Exception as e:
        sys.stderr.write(f"[credential_store] failed to load identity: {e}\n")
        _PYRAGE_AVAILABLE = False
        return False
    _PYRAGE_AVAILABLE = True
    return True


def bootstrap_age_identity():
    """Create AGE_KEY_PATH (mode 0600) if it doesn't exist. Returns the path.

    Uses pyrage's keygen if available; falls back to subprocess `age-keygen`.
    """
    if AGE_KEY_PATH.exists():
        return AGE_KEY_PATH
    AGE_KEY_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        import pyrage
        ident = pyrage.x25519.Identity.generate()
        AGE_KEY_PATH.write_text(
            "# created: " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n"
            "# public key: " + str(ident.to_public()) + "\n"
            + str(ident) + "\n"
        )
    except ImportError:
        import subprocess
        subprocess.check_call(["age-keygen", "-o", str(AGE_KEY_PATH)])
    AGE_KEY_PATH.chmod(0o600)
    return AGE_KEY_PATH


def encrypt(plaintext: bytes) -> bytes:
    if not _ensure_pyrage():
        raise RuntimeError(
            "credential_store: pyrage not available (run "
            "`pip install pyrage>=1.3.0` and bootstrap_age_identity())"
        )
    import pyrage
    return pyrage.encrypt(plaintext, [_RECIP])


def decrypt(ciphertext: bytes) -> bytes:
    if not _ensure_pyrage():
        raise RuntimeError(
            "credential_store: pyrage not available — cannot decrypt"
        )
    import pyrage
    return pyrage.decrypt(ciphertext, [_IDENT])


# ----- DB CRUD -----

def store(
    program_handle: str,
    auth_type: str,
    value: str | bytes | dict,
    notes: str = "",
    account_email: str = "",
    tier: str = "",
    probe_url: str = "",
    probe_method: str = "GET",
    expected_status: int | None = None,
    expected_body_contains: str = "",
    expires_at: str | None = None,
) -> int:
    """Encrypt + store a credential. Returns the new row id.

    `value` may be a JSON-serializable dict (for storage_state), a string
    (API key, cookie jar), or raw bytes. Always stored as encrypted JSON.
    """
    if isinstance(value, dict):
        plaintext = json.dumps(value).encode("utf-8")
    elif isinstance(value, str):
        plaintext = value.encode("utf-8")
    elif isinstance(value, bytes):
        plaintext = value
    else:
        raise TypeError(f"unsupported value type: {type(value)}")
    ct = encrypt(plaintext)
    conn = get_connection()
    try:
        cur = conn.execute(
            """
            INSERT INTO program_credentials
                (program_handle, auth_type, value_ct, notes, account_email,
                 tier, probe_url, probe_method, expected_status,
                 expected_body_contains, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (program_handle, auth_type, ct, notes, account_email, tier,
             probe_url, probe_method, expected_status,
             expected_body_contains, expires_at),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get(program_handle: str, auth_type: str | None = None) -> dict | None:
    """Return the most-recent active credential for a program, decrypted.

    Returns dict with all metadata fields PLUS a `value` key containing the
    decrypted plaintext (parsed as JSON if possible, else returned as str).
    Returns None if no active credential exists.
    """
    conn = get_connection()
    try:
        query = """
            SELECT * FROM program_credentials
            WHERE program_handle = ? AND status = 'active'
        """
        params: list[Any] = [program_handle]
        if auth_type:
            query += " AND auth_type = ?"
            params.append(auth_type)
        query += " ORDER BY captured_at DESC LIMIT 1"
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            pt = decrypt(d["value_ct"])
            try:
                d["value"] = json.loads(pt.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                d["value"] = pt.decode("utf-8", errors="replace")
        except Exception as e:
            d["value"] = None
            d["decrypt_error"] = str(e)
        # Don't return the ciphertext to callers
        del d["value_ct"]
        # Touch last_used_at
        conn.execute(
            "UPDATE program_credentials SET last_used_at = datetime('now') WHERE id = ?",
            (d["id"],),
        )
        conn.commit()
        return d
    finally:
        conn.close()


def list_all(status: str | None = None) -> list[dict]:
    """List credentials WITHOUT decrypting (for dashboard display).

    Returns metadata only — no plaintext values.
    """
    conn = get_connection()
    try:
        query = """
            SELECT id, program_handle, auth_type, notes, account_email, tier,
                   probe_url, status, captured_at, last_validated_at,
                   last_used_at, expires_at
            FROM program_credentials
        """
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY program_handle, captured_at DESC"
        return [dict(r) for r in conn.execute(query, params).fetchall()]
    finally:
        conn.close()


def mark_validated(cred_id: int, ok: bool, error: str = "") -> None:
    """Update last_validated_at + status based on a liveness probe outcome."""
    conn = get_connection()
    try:
        if ok:
            conn.execute(
                """
                UPDATE program_credentials
                SET last_validated_at = datetime('now'), status = 'active'
                WHERE id = ?
                """,
                (cred_id,),
            )
        else:
            note_suffix = f"\n[probe failed {time.strftime('%Y-%m-%d')}: {error[:200]}]"
            conn.execute(
                """
                UPDATE program_credentials
                SET last_validated_at = datetime('now'),
                    status = 'expired',
                    notes = COALESCE(notes,'') || ?
                WHERE id = ?
                """,
                (note_suffix, cred_id),
            )
        conn.commit()
    finally:
        conn.close()


def delete(cred_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM program_credentials WHERE id = ?", (cred_id,))
        conn.commit()
    finally:
        conn.close()


# ----- Liveness probe -----

def probe(cred: dict, timeout: int = 10) -> tuple[bool, str]:
    """Run a liveness probe against the configured probe_url. Returns
    (ok, error_msg). If no probe_url, returns (True, '') — caller decides
    whether unverified-but-not-expired is acceptable."""
    if not cred.get("probe_url"):
        return True, ""
    probe_url = cred["probe_url"]
    method = (cred.get("probe_method") or "GET").upper()
    expected_status = cred.get("expected_status")
    expected_body = (cred.get("expected_body_contains") or "")

    headers = {"User-Agent": "credential-probe/1.0"}
    cookies = []
    value = cred.get("value")
    if isinstance(value, dict):
        # storage_state cookies → Cookie header
        for c in value.get("cookies", []):
            host = c.get("domain", "")
            # Strip leading dot for comparison (per RFC 6265)
            target_host = urllib.request.Request(probe_url).host
            if host.lstrip(".") in target_host or target_host.endswith(host.lstrip(".")):
                cookies.append(f"{c['name']}={c['value']}")
    elif isinstance(value, str) and cred.get("auth_type") == "api_key":
        # Default to Bearer; programs that need X-API-Key can override via notes
        headers["Authorization"] = f"Bearer {value}"
    if cookies:
        headers["Cookie"] = "; ".join(cookies)

    req = urllib.request.Request(probe_url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body_snippet = resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body_snippet = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body_snippet = ""
    except Exception as e:
        return False, f"probe-error: {type(e).__name__}: {e}"

    if expected_status and status != expected_status:
        return False, f"status {status} (expected {expected_status})"
    if expected_body and expected_body not in body_snippet:
        return False, f"body did not contain {expected_body!r}"
    # Generic auth-failure heuristics if no specific expectation set
    if not expected_status:
        if status in (401, 403):
            return False, f"status {status} (auth-rejected)"
        if status in (301, 302) and any(
            kw in body_snippet.lower() for kw in ("login", "sign in", "signin")
        ):
            return False, "redirected to login"
    return True, ""


def write_storage_state_file(program_handle: str, dest: Path) -> Path | None:
    """Decrypt a storage_state credential and write it to a tmp file so
    Playwright / other tools can read it. Returns the path written, or
    None if no storage_state credential exists."""
    cred = get(program_handle, auth_type="storage_state")
    if not cred or not isinstance(cred.get("value"), dict):
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(cred["value"]))
    dest.chmod(0o600)
    return dest


if __name__ == "__main__":
    # Quick CLI: `python3 credential_store.py status` lists creds
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "status":
        for c in list_all():
            print(f"  [{c['status']:7}] {c['program_handle']:20} {c['auth_type']:15} "
                  f"captured={c['captured_at'][:10]} validated={c['last_validated_at'] or 'never'}")
    elif cmd == "bootstrap":
        path = bootstrap_age_identity()
        print(f"age identity at {path}")
    elif cmd == "probe":
        if len(sys.argv) < 3:
            print("usage: credential_store.py probe <handle>")
            sys.exit(1)
        cred = get(sys.argv[2])
        if not cred:
            print(f"no credential for {sys.argv[2]}")
            sys.exit(1)
        ok, err = probe(cred)
        mark_validated(cred["id"], ok, err)
        print(f"probe {'OK' if ok else 'FAIL'}: {err or 'live'}")
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)
