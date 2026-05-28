#!/usr/bin/env python3
"""Backfill new tools into all completed pipelines.

Iterates through completed pipeline runs and injects new tools that haven't
been run yet. Uses the Flask API (not direct DB access) so all the dependency
resolution, input file detection, and pipeline state management work correctly.

Usage:
    python3 backfill_new_tools.py                  # dry-run (show what would be injected)
    python3 backfill_new_tools.py --run             # actually inject
    python3 backfill_new_tools.py --run --pipeline 11  # inject into specific pipeline only
"""

import json
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError

FLASK_URL = "http://127.0.0.1:5000"

NEW_TOOLS = [
    "crt-sh", "gitleaks",                 # Phase 1 (lightweight — amass deferred, too slow for bulk)
    "gospider",                            # Phase 3
    "git-dumper",                          # Phase 4
    "joomscan", "sqlmap", "commix", "hydra",  # Phase 5
]

# Heavy tools excluded from bulk backfill (run individually per-pipeline):
# "amass" — very slow passive enum, 30+ min per target
# "eyewitness" — launches headless Chrome, high RAM usage


def api(method, path, data=None):
    url = FLASK_URL + path
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, method=method)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        resp = urlopen(req, timeout=30)
        return json.loads(resp.read()), resp.getcode()
    except URLError as e:
        code = getattr(e, "code", 502)
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"error": str(e)}
        return body, code


def get_completed_pipelines():
    """Get all completed pipeline IDs and their targets."""
    # Use the autopilot dashboard's DB query via a targets listing
    # We'll query each pipeline individually
    pipelines = []
    for pid in range(1, 100):
        resp, code = api("GET", f"/api/recon/pipeline/{pid}/status")
        if code == 404:
            continue
        if code != 200:
            break
        if resp.get("phase_status") == "completed":
            pipelines.append({
                "id": pid,
                "target": resp.get("program_handle", resp.get("target_name", "unknown")),
                "phase": resp.get("current_phase"),
            })
    return pipelines


def get_injectable(pipeline_id):
    """Get list of tools that can be injected into a pipeline."""
    resp, code = api("GET", f"/api/recon/pipeline/{pipeline_id}/injectable")
    if code != 200:
        return []
    return [t for t in resp.get("injectable", []) if t.get("can_run")]


def inject_tools(pipeline_id, tools):
    """Inject tools into a pipeline. Returns launched tools and errors."""
    resp, code = api("POST", f"/api/recon/pipeline/{pipeline_id}/inject",
                     {"tools": tools})
    return resp, code


def main():
    dry_run = "--run" not in sys.argv
    target_pipeline = None
    if "--pipeline" in sys.argv:
        idx = sys.argv.index("--pipeline")
        target_pipeline = int(sys.argv[idx + 1])

    if dry_run:
        print("DRY RUN — pass --run to actually inject tools\n")

    # Get completed pipelines
    print("Scanning for completed pipelines...")
    pipelines = get_completed_pipelines()
    if target_pipeline:
        pipelines = [p for p in pipelines if p["id"] == target_pipeline]

    if not pipelines:
        print("No completed pipelines found.")
        return

    print(f"Found {len(pipelines)} completed pipelines\n")

    total_launched = 0
    total_errors = 0

    for p in pipelines:
        pid = p["id"]
        print(f"{'='*60}")
        print(f"Pipeline {pid}: {p['target']}")

        injectable = get_injectable(pid)
        # Filter to only new tools
        new_injectable = [t for t in injectable if t["tool"] in NEW_TOOLS]

        if not new_injectable:
            print(f"  No new tools to inject (all already run or deps missing)")
            continue

        tool_names = [t["tool"] for t in new_injectable]
        print(f"  Injectable: {', '.join(tool_names)}")

        if dry_run:
            for t in new_injectable:
                print(f"    [dry-run] would inject {t['tool']} (phase {t['phase']})")
            continue

        # Inject tools, retrying 429s after waiting for current scans to finish
        remaining = list(tool_names)
        all_launched_pids = []

        while remaining:
            resp, code = inject_tools(pid, remaining)
            launched = resp.get("launched", [])
            errors = resp.get("errors", [])

            for l in launched:
                print(f"    Started {l['tool']} (pid={l['pid']})")
                total_launched += 1
                all_launched_pids.append(l["pid"])
            retry = []
            for e in errors:
                if "concurrent scans" in e or "429" in str(e):
                    # Extract tool name from error "toolname: too many concurrent scans..."
                    tool = e.split(":")[0].strip()
                    retry.append(tool)
                else:
                    print(f"    Error: {e}")
                    total_errors += 1

            if retry and launched:
                print(f"  Concurrency limit hit, waiting for current scans...")
                _wait_for_scans(pid, all_launched_pids)
                remaining = retry
            elif retry and not launched:
                # Nothing launched but still have retries — wait for external scans
                print(f"  Waiting for scan slots to free up...")
                time.sleep(30)
                remaining = retry
            else:
                remaining = []

        # Wait for all scans in this pipeline to finish before next pipeline
        if all_launched_pids:
            print(f"  Waiting for {len(all_launched_pids)} scans to finish...")
            _wait_for_scans(pid, all_launched_pids)

    print(f"\n{'='*60}")
    if dry_run:
        print("DRY RUN complete. Pass --run to execute.")
    else:
        print(f"Done: {total_launched} tools launched, {total_errors} errors")


AGENT_URL = "http://127.0.0.1:5001"


def _wait_for_scans(pipeline_id, pids, timeout=900):
    """Wait for scans to complete (up to timeout seconds)."""
    start = time.time()
    while time.time() - start < timeout:
        all_done = True
        for pid in pids:
            try:
                url = f"{AGENT_URL}/scan/{pid}/status"
                resp = urlopen(Request(url), timeout=10)
                data = json.loads(resp.read())
                if data.get("status") == "running":
                    all_done = False
                    break
            except Exception:
                pass  # scan may have been evicted, treat as done
        if all_done:
            elapsed = int(time.time() - start)
            print(f"    All scans done ({elapsed}s)")
            return
        time.sleep(15)
    print(f"    Timeout waiting for scans after {timeout}s")


if __name__ == "__main__":
    main()
