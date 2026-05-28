"""Oracle Autopilot — continuously runs ORACLE recon pipelines against random
bounty programs.

Mirrors autopilot.py but targets pipeline_type='oracle' via /api/oracle-pipeline.
The oracle pipeline auto-advances through all 5 phases on its own (no manual
approval gates), so this loop is much simpler than the web autopilot:

  1. Pick a program (3-phase weighted random selection, same as web autopilot,
     but de-duplicates against existing ORACLE pipelines instead of all targets).
  2. POST /api/oracle-pipeline/start with the program handle.
  3. Poll /api/oracle-pipeline/<id> until phase_status == "completed".
  4. Sleep BETWEEN_RUNS_DELAY then loop.

Stdlib-only so it can run on the Kali host alongside recon_agent.py.
Talks to the Flask API at http://127.0.0.1:5000.

Usage:
    python3 oracle_autopilot.py              # continuous mode (default)
    python3 oracle_autopilot.py --once       # run a single pipeline then exit
    python3 oracle_autopilot.py <handle>     # run pipeline for a specific program
    python3 oracle_autopilot.py --status     # show status of latest run
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

API_BASE = os.environ.get("AUTOPILOT_API_URL", "http://127.0.0.1:5000")
STATE_FILE = Path.home() / "recon" / ".oracle_autopilot_state.json"
LOG_FILE = Path.home() / "recon" / ".oracle_autopilot.log"
POLL_INTERVAL = 20            # seconds between status checks
BETWEEN_RUNS_DELAY = 10       # seconds before starting next pipeline
EXIT_NODE_RECHECK_S = 120     # see autopilot.py wait_for_exit_node()
MAX_BACKOFF = 1800            # max backoff on consecutive failures (30 min)
PIPELINE_TIMEOUT_HOURS = 6    # abandon a pipeline if it runs longer than this
RESCAN_DAYS = 30              # rescan oracle programs older than this many days
MAX_CONCURRENT_PIPELINES = 3  # run up to N oracle pipelines simultaneously


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print(line)
    LOG_FILE.parent.mkdir(exist_ok=True, parents=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def api_get(path):
    try:
        resp = urlopen("%s%s" % (API_BASE, path), timeout=15)
        return json.loads(resp.read().decode()), resp.status
    except URLError as e:
        return {"error": str(e)}, getattr(e, "code", 0)
    except Exception as e:
        return {"error": str(e)}, 0


def wait_for_exit_node():
    """Block until the recon agent reports exit_node.online == True.
    Mirrors autopilot.py wait_for_exit_node() — see that for full notes."""
    while True:
        resp, status = api_get("/api/recon/agent/health")
        if status != 200:
            log("Agent unreachable (status=%d); waiting %ds..." % (
                status, EXIT_NODE_RECHECK_S))
            time.sleep(EXIT_NODE_RECHECK_S)
            continue
        exit_node = resp.get("exit_node", {})
        if not exit_node.get("guard_enabled", False):
            return
        if exit_node.get("online", True):
            return
        log("Exit node DOWN — current=%s expected=%s (failures=%d). "
            "Pausing %ds." % (
                exit_node.get("current_egress_ip"),
                exit_node.get("expected_egress_ip"),
                exit_node.get("consecutive_failures", 0),
                EXIT_NODE_RECHECK_S))
        time.sleep(EXIT_NODE_RECHECK_S)


def api_post(path, data=None):
    body = json.dumps(data or {}).encode()
    req = Request("%s%s" % (API_BASE, path), data=body,
                  headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=15)
        return json.loads(resp.read().decode()), resp.status
    except URLError as e:
        if hasattr(e, "read"):
            try:
                return json.loads(e.read().decode()), e.code
            except Exception:
                pass
        return {"error": str(e)}, getattr(e, "code", 0)
    except Exception as e:
        return {"error": str(e)}, 0


def save_state(state):
    STATE_FILE.parent.mkdir(exist_ok=True, parents=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def _docker_query(sql_python):
    """Run a python snippet inside the web container to query the DB.

    The snippet should print exactly the result we want on stdout. Returns
    stdout stripped, or empty string on failure.
    """
    import subprocess
    result = subprocess.run([
        "docker", "compose", "exec", "-T", "web", "python3", "-c", sql_python
    ], capture_output=True, text=True,
       cwd=str(Path.home() / "apps" / "hackerOne"))
    return result.stdout.strip()


def pick_random_program():
    """Pick a bounty-eligible program for an ORACLE scan.

    4-phase priority selection, optimized to pick programs that can skip
    Phase 1 (reuse existing httpx results from web pipeline) first:

      1. FAST PATH: programs with existing web-pipeline httpx results but
         no oracle pipeline yet. These skip Phase 1 entirely (~3hr saving).
         Weighted by httpx result count (more hosts = more oracle surface).
      2. Unscanned no-signal programs without web-pipeline data (full run)
      3. Programs whose latest oracle pipeline is >RESCAN_DAYS old
      4. Unscanned signal-required programs (fallback)
    """
    # Phase 1 (PRIORITY): programs with web-pipeline httpx data, no oracle scan yet
    handle = _docker_query(
        "import db, random; conn = db.get_connection(); "
        "oracle_scanned = set(r['program_handle'] for r in conn.execute("
        "'SELECT DISTINCT t.program_handle FROM recon_targets t "
        "JOIN pipeline_runs p ON p.target_id = t.id "
        "WHERE p.pipeline_type = \"oracle\"').fetchall()); "
        "rows = conn.execute('"
        "SELECT DISTINCT t.program_handle, MAX(s.result_count) as httpx_results "
        "FROM recon_scans s "
        "JOIN recon_targets t ON t.id = s.target_id "
        "JOIN programs pr ON pr.handle = t.program_handle "
        "WHERE s.tool = \"httpx-toolkit\" AND s.status = \"completed\" AND s.result_count > 0 "
        "AND (pr.signal_required = 0 OR pr.signal_required IS NULL) "
        "GROUP BY t.program_handle"
        "').fetchall(); "
        "candidates = [(r[0], r[1]) for r in rows if r[0] not in oracle_scanned]; "
        "weights = [w for _, w in candidates]; "
        "chosen = random.choices([h for h, _ in candidates], weights=weights, k=1)[0] if candidates else ''; "
        "print(chosen)"
    )
    if handle:
        log("Selected program '%s' (FAST: has web httpx data, skip Phase 1)" % handle)
        return handle
    log("No fast-path programs (all web-scanned programs already have oracle runs)")

    # Phase 2: unscanned no-signal programs without web data (full Phase 1 needed)
    handle = _docker_query(
        "import db, random; conn = db.get_connection(); "
        "scanned = set(r['program_handle'] for r in conn.execute("
        "'SELECT DISTINCT t.program_handle FROM recon_targets t "
        "JOIN pipeline_runs p ON p.target_id = t.id "
        "WHERE p.pipeline_type = \"oracle\"').fetchall()); "
        "rows = conn.execute('"
        "SELECT p.handle, "
        "SUM(CASE WHEN s.asset_type = \"WILDCARD\" THEN 2 ELSE 1 END) as scope_weight "
        "FROM programs p "
        "JOIN scopes s ON s.program_id = p.id "
        "WHERE s.eligible_for_bounty = 1 AND s.asset_type IN (\"URL\", \"WILDCARD\") "
        "AND (p.signal_required = 0 OR p.signal_required IS NULL) "
        "GROUP BY p.handle "
        "HAVING COUNT(s.id) BETWEEN 1 AND 50"
        "').fetchall(); "
        "candidates = [(r[0], r[1]) for r in rows if r[0] not in scanned]; "
        "weights = [w for _, w in candidates]; "
        "chosen = random.choices([h for h, _ in candidates], weights=weights, k=1)[0] if candidates else ''; "
        "print(chosen)"
    )
    if handle:
        log("Selected program '%s' (pool: unscanned no-signal, weighted)" % handle)
        return handle
    log("No unscanned no-signal programs for oracle pipeline")

    # Phase 3: rescan programs whose latest oracle pipeline is >RESCAN_DAYS old
    handle = _docker_query(
        "import db, random; conn = db.get_connection(); "
        "rows = conn.execute('"
        "SELECT t.program_handle, MAX(p.created_at) as last_oracle "
        "FROM recon_targets t "
        "JOIN pipeline_runs p ON p.target_id = t.id "
        "JOIN programs pr ON pr.handle = t.program_handle "
        "WHERE p.pipeline_type = \"oracle\" "
        "AND (pr.signal_required = 0 OR pr.signal_required IS NULL) "
        "GROUP BY t.program_handle "
        "HAVING julianday(\"now\") - julianday(MAX(p.created_at)) > %d"
        "').fetchall(); "
        "candidates = [r[0] for r in rows]; "
        "random.shuffle(candidates); "
        "print(candidates[0] if candidates else '')" % RESCAN_DAYS
    )
    if handle:
        log("Selected program '%s' for rescan (last oracle scan >%d days ago)" % (handle, RESCAN_DAYS))
        return handle
    log("No programs due for oracle rescan")

    # Phase 4: unscanned signal-required programs (fallback)
    handle = _docker_query(
        "import db, random; conn = db.get_connection(); "
        "scanned = set(r['program_handle'] for r in conn.execute("
        "'SELECT DISTINCT t.program_handle FROM recon_targets t "
        "JOIN pipeline_runs p ON p.target_id = t.id "
        "WHERE p.pipeline_type = \"oracle\"').fetchall()); "
        "rows = conn.execute('"
        "SELECT p.handle FROM programs p "
        "JOIN scopes s ON s.program_id = p.id "
        "WHERE s.eligible_for_bounty = 1 AND s.asset_type IN (\"URL\", \"WILDCARD\") "
        "GROUP BY p.handle "
        "HAVING COUNT(s.id) BETWEEN 1 AND 50"
        "').fetchall(); "
        "candidates = [r[0] for r in rows if r[0] not in scanned]; "
        "random.shuffle(candidates); "
        "print(candidates[0] if candidates else '')"
    )
    if handle:
        log("Selected program '%s' (pool: all, including signal-required)" % handle)
        return handle

    log("No programs available for oracle pipeline — all have been scanned!")
    return None


def get_active_oracle_pipeline():
    """Return (pipeline_id, handle) for any running oracle pipeline, or None."""
    line = _docker_query(
        "import db; conn = db.get_connection(); "
        "row = conn.execute(\"SELECT p.id, t.program_handle FROM pipeline_runs p "
        "JOIN recon_targets t ON t.id = p.target_id "
        "WHERE p.pipeline_type = 'oracle' "
        "AND p.phase_status IN ('running', 'awaiting_approval') "
        "ORDER BY p.id DESC LIMIT 1\").fetchone(); "
        "print('%d %s' % (row['id'], row['program_handle']) if row else '')"
    )
    if line:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            return int(parts[0]), parts[1]
    return None


def start_oracle_pipeline(handle):
    """POST /api/oracle-pipeline/start. Returns pipeline_id or None."""
    resp, status = api_post("/api/oracle-pipeline/start",
                            data={"program_handle": handle})
    if status not in (200, 201):
        log("ERROR starting oracle pipeline for %s: %s" % (
            handle, resp.get("error", "unknown")))
        return None
    pipeline_id = resp.get("pipeline_id")
    log("Oracle pipeline %d started for %s (%d domains)" % (
        pipeline_id, handle, len(resp.get("domains", []))))
    return pipeline_id


def monitor_pipeline(pipeline_id, handle):
    """Poll /api/oracle-pipeline/<id> until terminal. Returns True on success."""
    started = datetime.now()
    last_phase = None
    while True:
        time.sleep(POLL_INTERVAL)

        # Abandon if past timeout
        elapsed_h = (datetime.now() - started).total_seconds() / 3600
        if elapsed_h > PIPELINE_TIMEOUT_HOURS:
            log("Oracle pipeline %d (%s) exceeded %dh timeout — abandoning" % (
                pipeline_id, handle, PIPELINE_TIMEOUT_HOURS))
            return False

        resp, status = api_get("/api/oracle-pipeline/%d" % pipeline_id)
        if status != 200:
            log("ERROR polling pipeline %d: %s" % (pipeline_id, resp.get("error", "unknown")))
            continue

        current_phase = resp.get("current_phase")
        phase_status = resp.get("phase_status")
        phase_name = resp.get("phase_name", "")

        if current_phase != last_phase:
            log("Oracle pipeline %d: phase %d (%s)" % (pipeline_id, current_phase, phase_name))
            last_phase = current_phase

        # Count tools in current phase
        for ph in resp.get("phases", []):
            if ph.get("phase") == current_phase:
                tools = ph.get("tools", [])
                running = [t for t in tools if t.get("status") == "running"]
                done = [t for t in tools if t.get("status") in ("completed", "failed")]
                pending = [t for t in tools if t.get("status") == "pending"]
                if running:
                    log("  phase %d: %d running [%s], %d done, %d pending" % (
                        current_phase, len(running),
                        ", ".join(t["tool"] for t in running),
                        len(done), len(pending)))
                break

        if phase_status in ("completed",) and current_phase >= resp.get("max_phase", 5):
            # All phases done
            findings = resp.get("findings", {})
            total = sum(len(v) for v in findings.values())
            log("Oracle pipeline %d (%s) COMPLETE — %d findings across %d types" % (
                pipeline_id, handle, total, len(findings)))
            for rtype, items in sorted(findings.items()):
                log("  %s: %d" % (rtype, len(items)))
            return True

        if phase_status == "failed":
            log("Oracle pipeline %d (%s) FAILED" % (pipeline_id, handle))
            return False


def poll_pipeline(pipeline_id, handle):
    """Check a pipeline's status once. Returns 'running', 'completed', or 'failed'."""
    resp, status = api_get("/api/oracle-pipeline/%d" % pipeline_id)
    if status != 200:
        return "running"  # assume still going if API is down

    current_phase = resp.get("current_phase")
    phase_status = resp.get("phase_status")
    max_phase = resp.get("max_phase", 5)

    if phase_status in ("completed",) and current_phase >= max_phase:
        findings = resp.get("findings", {})
        total = sum(len(v) for v in findings.values())
        log("[%d/%s] COMPLETE — %d findings across %d types" % (
            pipeline_id, handle, total, len(findings)))
        return "completed"

    if phase_status == "failed":
        log("[%d/%s] FAILED" % (pipeline_id, handle))
        return "failed"

    # Log progress
    for ph in resp.get("phases", []):
        if ph.get("phase") == current_phase:
            tools = ph.get("tools", [])
            running = [t for t in tools if t.get("status") == "running"]
            if running:
                log("[%d/%s] phase %d: %d running [%s]" % (
                    pipeline_id, handle, current_phase, len(running),
                    ", ".join(t["tool"] for t in running[:4])))
            break
    return "running"


def get_all_active_oracle_pipelines():
    """Return list of (pipeline_id, handle) for all running oracle pipelines."""
    line = _docker_query(
        "import db, json; conn = db.get_connection(); "
        "rows = conn.execute(\"SELECT p.id, t.program_handle FROM pipeline_runs p "
        "JOIN recon_targets t ON t.id = p.target_id "
        "WHERE p.pipeline_type = 'oracle' "
        "AND p.phase_status IN ('running', 'awaiting_approval') "
        "ORDER BY p.id\").fetchall(); "
        "print(json.dumps([(r['id'], r['program_handle']) for r in rows]))"
    )
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return []


def run_single(handle):
    """Run a single pipeline to completion (for --once and <handle> modes)."""
    pipeline_id = start_oracle_pipeline(handle)
    if not pipeline_id:
        return False
    save_state({
        "handle": handle,
        "pipeline_id": pipeline_id,
        "started_at": datetime.now().isoformat(),
        "status": "running",
    })
    success = monitor_pipeline(pipeline_id, handle)
    state = load_state()
    state["status"] = "completed" if success else "failed"
    state["finished_at"] = datetime.now().isoformat()
    save_state(state)
    return success


def show_status():
    state = load_state()
    if not state:
        print("No oracle autopilot runs recorded yet.")
        return
    active = state.get("active_pipelines", [])
    print("Oracle autopilot status:")
    print("  Active pipelines: %d / %d" % (len(active), MAX_CONCURRENT_PIPELINES))
    print("  Completed: %d" % state.get("completed_count", 0))
    for p in active:
        print("    Pipeline %s: %s" % (p.get("pipeline_id", "?"), p.get("handle", "?")))
    if state.get("last_completed"):
        print("  Last completed: %s (%s)" % (
            state["last_completed"].get("handle", "?"),
            state["last_completed"].get("finished_at", "?")))


def main():
    Path.home().joinpath("recon").mkdir(exist_ok=True)

    if len(sys.argv) >= 2 and sys.argv[1] == "--status":
        show_status()
        return

    # Single specific handle — run to completion and exit
    if len(sys.argv) >= 2 and sys.argv[1] not in ("--once",):
        run_single(handle=sys.argv[1])
        return

    # --once flag — single random pipeline then exit
    if len(sys.argv) >= 2 and sys.argv[1] == "--once":
        handle = pick_random_program()
        if handle:
            run_single(handle)
        return

    # Default: continuous mode — manage up to MAX_CONCURRENT_PIPELINES simultaneously
    log("Oracle autopilot starting in continuous mode (max %d concurrent)" % MAX_CONCURRENT_PIPELINES)

    # Active pipelines: list of {"pipeline_id": int, "handle": str, "started_at": str}
    active = []
    completed_count = 0
    consecutive_start_failures = 0

    # Adopt any orphaned running pipelines from a previous run
    orphans = get_all_active_oracle_pipelines()
    for pid, handle in orphans[:MAX_CONCURRENT_PIPELINES]:
        log("Adopting orphaned pipeline %d (%s)" % (pid, handle))
        active.append({
            "pipeline_id": pid,
            "handle": handle,
            "started_at": datetime.now().isoformat(),
        })

    while True:
        # 1. Poll all active pipelines and remove finished ones
        still_active = []
        for p in active:
            pid = p["pipeline_id"]
            handle = p["handle"]

            # Check timeout
            try:
                started = datetime.fromisoformat(p["started_at"])
                elapsed_h = (datetime.now() - started).total_seconds() / 3600
                if elapsed_h > PIPELINE_TIMEOUT_HOURS:
                    log("[%d/%s] exceeded %dh timeout — abandoning" % (
                        pid, handle, PIPELINE_TIMEOUT_HOURS))
                    api_post("/api/recon/pipeline/%d/stop" % pid)
                    continue
            except (ValueError, TypeError):
                pass

            result = poll_pipeline(pid, handle)
            if result == "running":
                still_active.append(p)
            else:
                completed_count += 1
                log("[%d/%s] finished (%s) — %d total completed" % (
                    pid, handle, result, completed_count))
        active = still_active

        # 2. Start new pipelines if we have capacity
        # Pre-flight: pause if exit node is down (existing pipelines keep
        # polling — their tools are already SIGSTOP'd by the agent's
        # exit-node monitor).
        if len(active) < MAX_CONCURRENT_PIPELINES:
            wait_for_exit_node()
        while len(active) < MAX_CONCURRENT_PIPELINES:
            handle = pick_random_program()
            if not handle:
                break  # no more programs to scan

            pipeline_id = start_oracle_pipeline(handle)
            if not pipeline_id:
                consecutive_start_failures += 1
                if consecutive_start_failures >= 3:
                    log("3 consecutive start failures — backing off 5 min")
                    time.sleep(300)
                    consecutive_start_failures = 0
                break

            consecutive_start_failures = 0
            active.append({
                "pipeline_id": pipeline_id,
                "handle": handle,
                "started_at": datetime.now().isoformat(),
            })
            log("Now running %d concurrent pipelines" % len(active))
            time.sleep(BETWEEN_RUNS_DELAY)

        # 3. Save state for dashboard visibility
        save_state({
            "active_pipelines": active,
            "active_count": len(active),
            "completed_count": completed_count,
            "status": "running" if active else "idle",
            "timestamp": time.time(),
        })

        # 4. Sleep before next poll cycle
        if not active:
            # Nothing running and nothing to start — longer sleep
            time.sleep(60)
        else:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
