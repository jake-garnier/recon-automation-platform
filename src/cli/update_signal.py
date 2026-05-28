"""Fetch signal requirement settings for all programs via HackerOne GraphQL API.

Queries the public (unauthenticated) GraphQL endpoint to get each program's
signal_requirements_setting.target_signal value and updates the local DB.

Stdlib-only so it can run on the Kali host alongside recon_agent.py.

Usage:
    python3 update_signal.py              # update all programs in DB
    python3 update_signal.py --dry-run    # show what would change without writing
"""

import json
import os
import sys
import time
from urllib.request import urlopen, Request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.environ.get("DB_PATH", os.path.join(_REPO_ROOT, "bounties.db"))
GRAPHQL_URL = "https://hackerone.com/graphql"
BATCH_SIZE = 15  # programs per GraphQL request


def graphql_query(query):
    body = json.dumps({"query": query}).encode()
    req = Request(GRAPHQL_URL, data=body, headers={"Content-Type": "application/json"})
    resp = urlopen(req, timeout=15)
    return json.loads(resp.read().decode())


def alias(handle):
    """GraphQL aliases can't have hyphens/dots."""
    return "p_" + handle.replace("-", "_").replace(".", "_")


def fetch_signal_requirements(handles):
    """Batch-fetch signal requirements for a list of handles. Returns {handle: target_signal}."""
    results = {}
    for i in range(0, len(handles), BATCH_SIZE):
        batch = handles[i:i + BATCH_SIZE]
        parts = []
        for h in batch:
            a = alias(h)
            parts.append(
                f'{a}: team(handle: "{h}") {{ handle signal_requirements_setting {{ target_signal }} }}'
            )
        query = "query { " + " ".join(parts) + " }"

        try:
            data = graphql_query(query)
            if "data" in data:
                for info in data["data"].values():
                    if info:
                        handle = info["handle"]
                        sig = info.get("signal_requirements_setting") or {}
                        results[handle] = sig.get("target_signal")
            if "errors" in data:
                for err in data["errors"]:
                    print(f"  GraphQL error: {err.get('message', '?')}", file=sys.stderr)
        except Exception as e:
            print(f"  Batch {i} error: {e}", file=sys.stderr)

        if i + BATCH_SIZE < len(handles):
            time.sleep(0.5)  # rate limit courtesy

    return results


def main():
    dry_run = "--dry-run" in sys.argv

    # Import sqlite3 directly (stdlib-only)
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Ensure column exists
    cols = {row[1] for row in conn.execute("PRAGMA table_info(programs)").fetchall()}
    if "signal_required" not in cols:
        conn.execute("ALTER TABLE programs ADD COLUMN signal_required INTEGER")
        conn.commit()

    # Get all program handles
    rows = conn.execute("SELECT handle FROM programs WHERE offers_bounties = 1").fetchall()
    handles = [r["handle"] for r in rows]
    print(f"Fetching signal requirements for {len(handles)} programs...")

    signal_data = fetch_signal_requirements(handles)
    print(f"Got data for {len(signal_data)}/{len(handles)} programs")

    # Classify: target_signal >= 0.0 = signal required (even 0 gates trial reporters)
    # -1.0, -10.0 = permissive (no signal gate), None = signal OFF
    updated = 0
    for handle, target_signal in signal_data.items():
        signal_required = 1 if (target_signal is not None and target_signal >= 0.0) else 0
        if dry_run:
            current = conn.execute(
                "SELECT signal_required FROM programs WHERE handle = ?", (handle,)
            ).fetchone()
            cur_val = current["signal_required"] if current else None
            if cur_val != signal_required:
                label = "STRICT" if signal_required else ("OFF" if target_signal is None else f">={target_signal}")
                print(f"  {handle}: {cur_val} -> {signal_required} ({label})")
                updated += 1
        else:
            conn.execute(
                "UPDATE programs SET signal_required = ? WHERE handle = ?",
                (signal_required, handle),
            )
            updated += 1

    if not dry_run:
        conn.commit()

    sig1 = conn.execute("SELECT COUNT(*) FROM programs WHERE signal_required = 1").fetchone()[0]
    sig0 = conn.execute("SELECT COUNT(*) FROM programs WHERE signal_required = 0").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM programs WHERE signal_required IS NULL").fetchone()[0]
    conn.close()

    action = "Would update" if dry_run else "Updated"
    print(f"\n{action} {updated} programs")
    print(f"Summary: {sig0} no-signal, {sig1} signal-required, {unknown} unknown")


if __name__ == "__main__":
    main()
