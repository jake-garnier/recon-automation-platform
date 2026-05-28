"""Autopilot — continuously runs recon pipelines against random bounty programs.

Runs as a long-lived service: picks a random program, runs a full pipeline,
then immediately picks the next one. Sleeps briefly between runs and backs
off on repeated failures.

Stdlib-only so it can run on the Kali host alongside recon_agent.py.
Talks to the Flask API at http://127.0.0.1:5000.

Usage:
    python3 autopilot.py              # continuous mode (default)
    python3 autopilot.py --once       # run a single pipeline then exit
    python3 autopilot.py <handle>     # run pipeline for a specific program then exit
    python3 autopilot.py --status     # show status of latest autopilot run
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlencode

API_BASE = os.environ.get("AUTOPILOT_API_URL", "http://127.0.0.1:5000")
STATE_FILE = Path.home() / "recon" / ".autopilot_state.json"
# Multi-pipeline state for parallel mode. Each entry is a per-pipeline state
# dict keyed by pipeline_id. STATE_FILE (single) is still written for the most
# recent run so --status and older tooling keep working.
MULTI_STATE_FILE = Path.home() / "recon" / ".autopilot_multi_state.json"
LOG_FILE = Path.home() / "recon" / ".autopilot.log"
POLL_INTERVAL = 15    # seconds between status checks
BETWEEN_RUNS_DELAY = 30      # seconds to wait between pipeline runs
MAX_BACKOFF = 1800            # max backoff on consecutive failures (30 min)
MAX_RETRY_ROUNDS = 2  # max times to re-inject failed tools into a completed pipeline
# Run up to this many pipelines concurrently. The netns egress pool has 4
# slots (scan1..scan4), so 4 lets continuous mode saturate all egress nodes
# instead of running one-at-a-time and leaving 3 idle. The pool itself is the
# hard concurrency gate — if we try to start a 5th the agent returns 409.
MAX_PARALLEL_PIPELINES = int(os.environ.get("AUTOPILOT_MAX_PARALLEL", "4"))
# When the agent reports exit node down, wait this long before re-checking.
# Long enough to absorb a Tailscale reconnect (~30s) or VPS reboot (~90s)
# without spamming the log; short enough to resume quickly once recovered.
EXIT_NODE_RECHECK_S = 120

# Errors that indicate a tool was legitimately skipped (not worth retrying)
NON_RETRIABLE_ERRORS = (
    "skipped: no input from dependency",
    "skipped: no WordPress sites found",
    "skipped: no Joomla sites found",
    "skipped: no login panels found",
    "skipped: no injectable URLs",
)


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def wait_for_exit_node():
    """Block until the recon agent reports exit_node.online == True.
    Returns immediately if guard is disabled or already healthy.

    Prevents the loop from starting a pipeline (or its retry) when the
    Hetzner exit node is unreachable — see recon_agent.py EXIT_NODE_*."""
    while True:
        resp, status = api_get("/api/recon/agent/health")
        if status != 200:
            log("Agent unreachable (status=%d); waiting %ds..." % (
                status, EXIT_NODE_RECHECK_S))
            time.sleep(EXIT_NODE_RECHECK_S)
            continue
        exit_node = resp.get("exit_node", {})
        # If guard isn't enabled on the agent, don't block — older agents
        # without the guard field also fall through here.
        if not exit_node.get("guard_enabled", False):
            return
        if exit_node.get("online", True):
            return
        log("Exit node DOWN — current=%s expected=%s (failures=%d, since=%s). "
            "Pausing %ds before re-check." % (
                exit_node.get("current_egress_ip"),
                exit_node.get("expected_egress_ip"),
                exit_node.get("consecutive_failures", 0),
                exit_node.get("down_since"),
                EXIT_NODE_RECHECK_S))
        time.sleep(EXIT_NODE_RECHECK_S)


def api_get(path):
    try:
        resp = urlopen("%s%s" % (API_BASE, path), timeout=15)
        return json.loads(resp.read().decode()), resp.status
    except URLError as e:
        return {"error": str(e)}, 0
    except Exception as e:
        return {"error": str(e)}, 0


def api_post(path, data=None, form_data=None):
    if form_data:
        body = urlencode(form_data).encode()
        req = Request("%s%s" % (API_BASE, path), data=body,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    elif data:
        body = json.dumps(data).encode()
        req = Request("%s%s" % (API_BASE, path), data=body,
                      headers={"Content-Type": "application/json"})
    else:
        req = Request("%s%s" % (API_BASE, path), data=b"",
                      headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=15)
        return json.loads(resp.read().decode()), resp.status
    except URLError as e:
        # urllib raises on 4xx/5xx; try to read the body
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


def save_multi_state(states):
    """Persist the dict of active pipeline states (keyed by pipeline_id str)."""
    MULTI_STATE_FILE.parent.mkdir(exist_ok=True, parents=True)
    with open(MULTI_STATE_FILE, "w") as f:
        json.dump(states, f, indent=2)
    # Also mirror the most-recently-updated running pipeline to the legacy
    # single state file so --status and external tooling keep working.
    running = [s for s in states.values() if s.get("status") == "running"]
    if running:
        save_state(running[-1])


def load_multi_state():
    if MULTI_STATE_FILE.exists():
        try:
            with open(MULTI_STATE_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


RESCAN_DAYS = 30  # rescan programs older than this many days


def get_retriable_failures(pipeline_id):
    """Return list of tool names that failed with retriable errors in this pipeline."""
    resp, status = api_get("/api/recon/pipeline/%d/status" % pipeline_id)
    if status != 200:
        return []
    retriable = []
    for phase_num, scans in resp.get("phases", {}).items():
        for s in scans:
            if s["status"] != "failed":
                continue
            err = s.get("error", "") or ""
            # Skip tools with non-retriable errors (legitimate skips)
            if any(nr in err for nr in NON_RETRIABLE_ERRORS):
                continue
            retriable.append(s["tool"])
    return retriable

def pick_random_program():
    """Pick a bounty-eligible program, weighted by bounty size and scope type.

    Priority order:
    1. Unscanned no-signal programs (weighted by bounty + wildcard count)
    2. Programs last scanned >30 days ago (rescan)
    3. Unscanned signal-required programs (fallback)
    """
    resp, status = api_get("/api/recon/agent/tools")
    if status != 200:
        log("ERROR: Cannot reach agent — is the Flask app running?")
        return None

    import subprocess

    # Phase 1: unscanned no-signal programs, weighted by bounty + wildcards
    result = subprocess.run([
        "docker", "compose", "exec", "-T", "web", "python3", "-c",
        "import db, random; conn = db.get_connection(); "
        "scanned = set(r['program_handle'] for r in conn.execute("
        "'SELECT DISTINCT t.program_handle FROM recon_targets t "
        "JOIN pipeline_runs pr ON pr.target_id = t.id "
        "WHERE pr.pipeline_type = \"web\" AND pr.phase_status = \"completed\"').fetchall()); "
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
    ], capture_output=True, text=True, cwd=str(Path.home() / "apps" / "hackerOne"))

    handle = result.stdout.strip()
    if handle:
        log("Selected program '%s' from pool: unscanned no-signal (weighted)" % handle)
        return handle
    log("No unscanned no-signal programs")

    # Phase 2: rescan programs older than RESCAN_DAYS
    result = subprocess.run([
        "docker", "compose", "exec", "-T", "web", "python3", "-c",
        "import db, random; conn = db.get_connection(); "
        "rows = conn.execute('"
        "SELECT t.program_handle, MAX(t.created_at) as last_scan "
        "FROM recon_targets t "
        "JOIN programs p ON p.handle = t.program_handle "
        "WHERE (p.signal_required = 0 OR p.signal_required IS NULL) "
        "GROUP BY t.program_handle "
        "HAVING julianday(\"now\") - julianday(MAX(t.created_at)) > %d"
        "').fetchall(); "
        "candidates = [r[0] for r in rows]; "
        "random.shuffle(candidates); "
        "print(candidates[0] if candidates else '')" % RESCAN_DAYS
    ], capture_output=True, text=True, cwd=str(Path.home() / "apps" / "hackerOne"))

    handle = result.stdout.strip()
    if handle:
        log("Selected program '%s' for rescan (last scanned >%d days ago)" % (handle, RESCAN_DAYS))
        return handle
    log("No programs due for rescan")

    # Phase 3: unscanned signal-required programs (fallback)
    result = subprocess.run([
        "docker", "compose", "exec", "-T", "web", "python3", "-c",
        "import db, random; conn = db.get_connection(); "
        "scanned = set(r['program_handle'] for r in conn.execute("
        "'SELECT DISTINCT t.program_handle FROM recon_targets t "
        "JOIN pipeline_runs pr ON pr.target_id = t.id "
        "WHERE pr.pipeline_type = \"web\" AND pr.phase_status = \"completed\"').fetchall()); "
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
    ], capture_output=True, text=True, cwd=str(Path.home() / "apps" / "hackerOne"))

    handle = result.stdout.strip()
    if handle:
        log("Selected program '%s' from pool: all (including signal-required)" % handle)
        return handle

    log("No unscanned programs found — all programs have been scanned!")
    return None


def create_target(handle):
    """Create a recon target from a program handle. Returns target_id."""
    resp, status = api_post("/api/recon/targets", form_data={"handle": handle})
    if status == 201:
        log("Target created: %s (id=%d, domains=%s)" % (
            handle, resp["id"], resp["domains"]))
        return resp["id"], resp["domains"]
    elif "already" in resp.get("error", "").lower() or status == 409:
        log("Target already exists for %s, looking up ID..." % handle)
        # Find existing target
        import subprocess
        result = subprocess.run([
            "docker", "compose", "exec", "-T", "web", "python3", "-c",
            "import db; conn = db.get_connection(); "
            "t = conn.execute('SELECT id, domains FROM recon_targets WHERE program_handle = ?', "
            "('%s',)).fetchone(); print(t['id'] if t else '')" % handle
        ], capture_output=True, text=True, cwd=str(Path.home() / "apps" / "hackerOne"))
        tid = result.stdout.strip()
        if tid:
            return int(tid), []
    log("ERROR creating target: %s" % resp.get("error", "unknown"))
    return None, []


def run_pipeline(target_id, handle, resume_pipeline_id=None):
    """Run the full 5-phase pipeline with auto-approval.

    After all 5 phases complete, checks for retriable failed tools and
    re-injects them (up to MAX_RETRY_ROUNDS times). On timeout, marks
    pipeline as 'retry' so the next run_once() cycle resumes it instead
    of picking a new program.
    """
    import subprocess

    if resume_pipeline_id:
        pipeline_id = resume_pipeline_id
        log("Resuming pipeline %d for %s" % (pipeline_id, handle))
        state = load_state()
    else:
        # Check if this is a rescan with existing httpx data (incremental mode)
        # If previous pipeline had >50 httpx results, skip Phase 1 enumeration
        start_data = {"target_id": target_id}
        check_result = subprocess.run([
            "docker", "compose", "exec", "-T", "web", "python3", "-c",
            "import db; conn = db.get_connection(); "
            "row = conn.execute('"
            "SELECT s.result_count FROM recon_scans s "
            "JOIN pipeline_runs p ON s.pipeline_id = p.id "
            "WHERE p.target_id = %d AND s.tool = \"httpx-toolkit\" "
            "AND s.status = \"completed\" AND s.result_count > 50 "
            "ORDER BY s.finished_at DESC LIMIT 1"
            "').fetchone(); "
            "print(row[0] if row else 0)" % target_id
        ], capture_output=True, text=True,
            cwd=str(Path.home() / "apps" / "hackerOne"))
        prev_httpx = int(check_result.stdout.strip() or "0")
        if prev_httpx > 50:
            start_data["rescan_incremental"] = True
            log("Incremental rescan: previous httpx had %d results, skipping Phase 1" % prev_httpx)

        resp, status = api_post("/api/recon/pipeline/start", data=start_data)
        if status not in (200, 201):
            log("ERROR starting pipeline: %s" % resp.get("error", "unknown"))
            return False

        pipeline_id = resp["pipeline_id"]
        skipped = " (skipped Phase 1)" if resp.get("skipped_phase1") else ""
        log("Pipeline %d started for %s%s" % (pipeline_id, handle, skipped))

        state = {
            "handle": handle,
            "target_id": target_id,
            "pipeline_id": pipeline_id,
            "started_at": datetime.now().isoformat(),
            "status": "running",
            "retry_round": 0,
        }
        save_state(state)

    retry_round = state.get("retry_round", 0)

    # Monitor and auto-approve through all 5 phases (no timeout — runs until done)
    max_phase = 5
    while True:
        time.sleep(POLL_INTERVAL)

        resp, status = api_get("/api/recon/pipeline/%d/status" % pipeline_id)
        if status != 200:
            log("ERROR polling pipeline: %s" % resp.get("error", "unknown"))
            continue

        current_phase = resp["current_phase"]
        phase_status = resp["phase_status"]
        phase_name = resp.get("phase_name", "")

        # Log scan progress
        phase_scans = resp.get("phases", {}).get(str(current_phase), [])
        running = [s for s in phase_scans if s["status"] == "running"]
        completed = [s for s in phase_scans if s["status"] == "completed"]
        failed = [s for s in phase_scans if s["status"] == "failed"]
        total_results = sum(s.get("result_count", 0) for s in phase_scans)

        if running:
            tools_str = ", ".join(s["tool"] for s in running)
            log("Phase %d (%s): %d running [%s], %d done, %d failed | %d results" % (
                current_phase, phase_name, len(running), tools_str,
                len(completed), len(failed), total_results))

        if phase_status == "awaiting_approval":

            # Log phase summary
            log("Phase %d (%s) complete: %d tools, %d results" % (
                current_phase, phase_name, len(completed) + len(failed), total_results))
            for s in completed + failed:
                log("  %-20s %-12s %d results" % (
                    s["tool"], s["status"], s.get("result_count", 0)))

            if current_phase >= max_phase:
                # All 5 phases done — check for retriable failures before finishing
                retriable = get_retriable_failures(pipeline_id)
                if retriable and retry_round < MAX_RETRY_ROUNDS:
                    retry_round += 1
                    state["retry_round"] = retry_round
                    save_state(state)
                    log("Pipeline %d: %d retriable failures (round %d/%d): %s" % (
                        pipeline_id, len(retriable), retry_round, MAX_RETRY_ROUNDS,
                        ", ".join(retriable)))
                    log("Injecting failed tools back into pipeline...")
                    inject_resp, inject_status = api_post(
                        "/api/recon/pipeline/%d/inject" % pipeline_id,
                        data={"tools": retriable})
                    if inject_status in (200, 201):
                        injected = inject_resp.get("injected", [])
                        log("Injected %d tools: %s" % (len(injected),
                            ", ".join(t["tool"] for t in injected) if injected else "none"))
                        continue  # keep monitoring
                    else:
                        log("ERROR injecting tools: %s" % inject_resp.get("error", "unknown"))
                        # Fall through to completion

                log("Pipeline %d finished — all 5 phases complete!" % pipeline_id)
                if retriable:
                    log("  Remaining failures (exhausted %d retry rounds): %s" % (
                        retry_round, ", ".join(retriable)))
                state["status"] = "completed"
                state["finished_at"] = datetime.now().isoformat()
                save_state(state)
                return True

            # Auto-approve to next phase
            log("Auto-approving Phase %d → Phase %d..." % (
                current_phase, current_phase + 1))
            approve_resp, approve_status = api_post(
                "/api/recon/pipeline/%d/approve" % pipeline_id)
            if approve_status not in (200, 201):
                log("ERROR approving: %s" % approve_resp.get("error", "unknown"))
                state["status"] = "error"
                save_state(state)
                return False

            errors = approve_resp.get("errors", [])
            if errors:
                log("Phase %d warnings: %s" % (current_phase + 1, "; ".join(errors)))

        elif phase_status == "completed":
            # Same retry logic for the "completed" terminal state
            retriable = get_retriable_failures(pipeline_id)
            if retriable and retry_round < MAX_RETRY_ROUNDS:
                retry_round += 1
                state["retry_round"] = retry_round
                save_state(state)
                log("Pipeline %d completed with %d retriable failures (round %d/%d): %s" % (
                    pipeline_id, len(retriable), retry_round, MAX_RETRY_ROUNDS,
                    ", ".join(retriable)))
                inject_resp, inject_status = api_post(
                    "/api/recon/pipeline/%d/inject" % pipeline_id,
                    data={"tools": retriable})
                if inject_status in (200, 201):
                    injected = inject_resp.get("injected", [])
                    log("Injected %d tools: %s" % (len(injected),
                        ", ".join(t["tool"] for t in injected) if injected else "none"))
                    continue
                else:
                    log("ERROR injecting tools: %s" % inject_resp.get("error", "unknown"))

            log("Pipeline %d fully completed" % pipeline_id)
            state["status"] = "completed"
            state["finished_at"] = datetime.now().isoformat()
            save_state(state)
            return True


def _advance_pipeline(state):
    """Non-blocking single tick of pipeline monitoring for parallel mode.

    Mutates `state` in place (retry_round, status, finished_at). Returns one of:
      "running"    — still in progress, call again next tick
      "completed"  — all phases done (terminal)
      "error"      — unrecoverable error (terminal)

    This is the per-tick equivalent of run_pipeline's while-loop body, but
    without the blocking sleep+loop so the caller can interleave N pipelines.
    Phase auto-approval is ALSO done by the Flask reconciler now, so this is
    belt-and-suspenders for approval but is the ONLY place retriable-failure
    re-injection happens.
    """
    pipeline_id = state["pipeline_id"]
    retry_round = state.get("retry_round", 0)
    max_phase = 5

    resp, status = api_get("/api/recon/pipeline/%d/status" % pipeline_id)
    if status != 200:
        return "running"  # transient; try again next tick

    current_phase = resp["current_phase"]
    phase_status = resp["phase_status"]
    phase_name = resp.get("phase_name", "")

    phase_scans = resp.get("phases", {}).get(str(current_phase), [])
    running = [s for s in phase_scans if s["status"] == "running"]
    completed = [s for s in phase_scans if s["status"] == "completed"]
    failed = [s for s in phase_scans if s["status"] == "failed"]
    total_results = sum(s.get("result_count", 0) for s in phase_scans)

    if running:
        tools_str = ", ".join(s["tool"] for s in running)
        log("P%d %s Phase %d (%s): %d running [%s], %d done, %d failed | %d results" % (
            pipeline_id, state.get("handle", "?"), current_phase, phase_name,
            len(running), tools_str, len(completed), len(failed), total_results))

    if phase_status in ("awaiting_approval", "completed"):
        is_terminal = (phase_status == "completed") or (current_phase >= max_phase)
        if is_terminal:
            retriable = get_retriable_failures(pipeline_id)
            if retriable and retry_round < MAX_RETRY_ROUNDS:
                retry_round += 1
                state["retry_round"] = retry_round
                log("P%d %s: %d retriable failures (round %d/%d): %s" % (
                    pipeline_id, state.get("handle", "?"), len(retriable),
                    retry_round, MAX_RETRY_ROUNDS, ", ".join(retriable)))
                inject_resp, inject_status = api_post(
                    "/api/recon/pipeline/%d/inject" % pipeline_id,
                    data={"tools": retriable})
                if inject_status in (200, 201):
                    return "running"  # keep monitoring the re-injected tools
                log("P%d ERROR injecting tools: %s" % (
                    pipeline_id, inject_resp.get("error", "unknown")))
            log("P%d %s fully completed — all phases done" % (
                pipeline_id, state.get("handle", "?")))
            state["status"] = "completed"
            state["finished_at"] = datetime.now().isoformat()
            return "completed"

        # Mid-pipeline awaiting_approval — auto-approve to next phase.
        # (The Flask reconciler usually beats us to this, which is fine —
        # the approve call is idempotent enough; a 4xx just means already done.)
        log("P%d %s auto-approving Phase %d → %d" % (
            pipeline_id, state.get("handle", "?"), current_phase, current_phase + 1))
        approve_resp, approve_status = api_post(
            "/api/recon/pipeline/%d/approve" % pipeline_id)
        if approve_status not in (200, 201):
            # Could be the reconciler already advanced it — re-poll next tick
            # rather than declaring error.
            return "running"

    return "running"


def _exclude_active_handles(handles):
    """pick_random_program() ignores in-flight pipelines (only checks
    'completed'). In parallel mode that means two ticks could pick the same
    handle. We retry selection a few times, skipping any handle already
    active, to avoid duplicate-target races."""
    for _ in range(8):
        h = pick_random_program()
        if not h or h not in handles:
            return h
        log("Skipping '%s' — already active in another slot, re-picking" % h)
    return None


def run_continuous_parallel():
    """Continuous mode running up to MAX_PARALLEL_PIPELINES at once.

    Each tick:
      1. Advance every active pipeline one step (auto-approve / retry / finish).
      2. Drop finished ones.
      3. If we have a free slot and a free netns egress, pick + start a new
         pipeline (skipping handles already active to avoid dup-target races).
    The netns pool (4 slots) is the hard concurrency gate — a 5th start 409s.
    """
    log("Autopilot starting in continuous PARALLEL mode (max %d concurrent)" % MAX_PARALLEL_PIPELINES)
    consecutive_failures = 0

    # Re-adopt any pipelines we were tracking before a restart.
    active = {}
    for pid_str, st in load_multi_state().items():
        if st.get("status") == "running" and st.get("pipeline_id"):
            r, code = api_get("/api/recon/pipeline/%d/status" % st["pipeline_id"])
            if code == 200 and r.get("phase_status") in ("running", "awaiting_approval"):
                active[str(st["pipeline_id"])] = st
                log("Re-adopted pipeline %d for %s after restart" % (
                    st["pipeline_id"], st.get("handle", "?")))

    while True:
        wait_for_exit_node()

        # 1+2. Advance + reap finished pipelines.
        for pid_str in list(active.keys()):
            st = active[pid_str]
            try:
                result = _advance_pipeline(st)
            except Exception as e:
                log("P%s advance error: %s" % (pid_str, e))
                result = "running"
            if result in ("completed", "error"):
                log("Pipeline %s (%s) -> %s" % (pid_str, st.get("handle", "?"), result))
                # Flask's _check_phase_completion already releases the egress
                # netns when a pipeline hits a terminal status, so we don't
                # need to release it here.
                del active[pid_str]
        save_multi_state(active)

        # 3. Fill free slots.
        active_handles = {s.get("handle") for s in active.values()}
        launched_this_tick = 0
        while len(active) < MAX_PARALLEL_PIPELINES:
            handle = _exclude_active_handles(active_handles)
            if not handle:
                break  # nothing new to pick
            target_id, domains = create_target(handle)
            if not target_id:
                consecutive_failures += 1
                break
            resp, code = api_post("/api/recon/pipeline/start", data={"target_id": target_id})
            if code == 409:
                # Pool full / per-target gate — stop launching this tick.
                log("Pool full launching %s (409) — will retry next tick" % handle)
                break
            if code not in (200, 201):
                log("ERROR starting pipeline for %s: %s" % (handle, resp.get("error", "unknown")))
                consecutive_failures += 1
                break
            pid = resp["pipeline_id"]
            st = {
                "handle": handle, "target_id": target_id, "pipeline_id": pid,
                "started_at": datetime.now().isoformat(), "status": "running",
                "retry_round": 0,
            }
            active[str(pid)] = st
            active_handles.add(handle)
            launched_this_tick += 1
            consecutive_failures = 0
            log("Started pipeline %d for %s (%d/%d slots active)" % (
                pid, handle, len(active), MAX_PARALLEL_PIPELINES))
        save_multi_state(active)

        # Backoff only if we have nothing running AND couldn't launch anything.
        if not active and launched_this_tick == 0:
            consecutive_failures += 1
            backoff = min(BETWEEN_RUNS_DELAY * (2 ** consecutive_failures), MAX_BACKOFF)
            log("Idle (%d consecutive). Backing off %d seconds..." % (
                consecutive_failures, backoff))
            time.sleep(backoff)
        else:
            time.sleep(POLL_INTERVAL)


def show_status():
    state = load_state()
    if not state:
        print("No autopilot runs recorded yet.")
        return

    print("Last autopilot run:")
    print("  Program:    %s" % state.get("handle", "?"))
    print("  Target ID:  %s" % state.get("target_id", "?"))
    print("  Pipeline:   %s" % state.get("pipeline_id", "?"))
    print("  Started:    %s" % state.get("started_at", "?"))
    print("  Finished:   %s" % state.get("finished_at", "—"))
    print("  Status:     %s" % state.get("status", "?"))

    if state.get("pipeline_id"):
        resp, status = api_get("/api/recon/pipeline/%d/status" % state["pipeline_id"])
        if status == 200:
            print("\nPipeline details:")
            for phase_num in sorted(resp.get("phases", {}).keys()):
                scans = resp["phases"][phase_num]
                total = sum(s.get("result_count", 0) for s in scans)
                print("  Phase %s: %d tools, %d results" % (phase_num, len(scans), total))
                for s in scans:
                    print("    %-20s %-12s %d results" % (
                        s["tool"], s["status"], s.get("result_count", 0)))


def try_resume_stale():
    """Check for a stale running pipeline and resume it. Returns True if resumed."""
    state = load_state()
    if state.get("status") == "running" and state.get("pipeline_id"):
        started = state.get("started_at", "")
        stale_hours = 0
        if started:
            try:
                started_dt = datetime.fromisoformat(started)
                stale_hours = (datetime.now() - started_dt).total_seconds() / 3600
            except (ValueError, TypeError):
                pass

        if stale_hours > 6:
            log("Pipeline %d for %s has been running for %.1f hours — abandoning" % (
                state["pipeline_id"], state.get("handle", "?"), stale_hours))
            # Stop the DB pipeline so has_active_pipeline() doesn't wedge
            api_post("/api/recon/pipeline/%d/stop" % state["pipeline_id"])
            state["status"] = "abandoned"
            state["finished_at"] = datetime.now().isoformat()
            save_state(state)
            return False

        log("Found stale running pipeline %d for %s (%.1fh), resuming..." % (
            state["pipeline_id"], state.get("handle", "?"), stale_hours))
        resp, status = api_get("/api/recon/pipeline/%d/status" % state["pipeline_id"])
        if status == 200 and resp.get("phase_status") in ("running", "awaiting_approval"):
            success = run_pipeline(state["target_id"], state["handle"],
                                   resume_pipeline_id=state["pipeline_id"])
            if success:
                log("Autopilot complete for %s" % state["handle"])
            else:
                log("Autopilot failed for %s" % state["handle"])
            return True
        else:
            log("Stale pipeline is no longer active, starting fresh")
            state["status"] = "abandoned"
            state["finished_at"] = datetime.now().isoformat()
            save_state(state)
    elif state.get("status") in ("stalled", "timeout"):
        log("Previous run was %s, starting fresh" % state["status"])
    return False


def get_active_pipeline():
    """Return (pipeline_id, target_id, handle) for any active WEB pipeline, or None.

    Filters by pipeline_type='web' — if we don't, the web autopilot picks up an
    oracle pipeline (started by oracle_autopilot) and monitors it forever.  That
    happened on 2026-05-15 with P234 (vimeo oracle) which gated all new web
    pipelines for ~12 hours.  Web and oracle each own their own pipelines.
    """
    import subprocess
    result = subprocess.run([
        "docker", "compose", "exec", "-T", "web", "python3", "-c",
        "import db; conn = db.get_connection(); "
        "row = conn.execute(\"SELECT p.id, p.target_id, t.program_handle FROM pipeline_runs p "
        "JOIN recon_targets t ON t.id = p.target_id "
        "WHERE p.phase_status IN ('running', 'awaiting_approval') "
        "AND (p.pipeline_type = 'web' OR p.pipeline_type IS NULL) "
        "ORDER BY p.id DESC LIMIT 1\").fetchone(); "
        "print('%d %d %s' % (row['id'], row['target_id'], row['program_handle']) if row else '')"
    ], capture_output=True, text=True, cwd=str(Path.home() / "apps" / "hackerOne"))
    line = result.stdout.strip()
    if line:
        parts = line.split(" ", 2)
        if len(parts) == 3:
            return int(parts[0]), int(parts[1]), parts[2]
    return None


def run_once(handle=None):
    """Run a single autopilot cycle. Returns True on success, False on failure."""
    # If a pipeline is already running, adopt and resume it instead of skipping
    active = get_active_pipeline()
    if active:
        pipeline_id, target_id, active_handle = active
        state = load_state()
        # Check if we already own this pipeline
        if state.get("pipeline_id") == pipeline_id and state.get("status") == "running":
            log("Already monitoring pipeline %d (%s)" % (pipeline_id, active_handle))
            return False
        # Adopt the orphaned pipeline
        log("Adopting orphaned pipeline %d for %s" % (pipeline_id, active_handle))
        state = {
            "handle": active_handle,
            "target_id": target_id,
            "pipeline_id": pipeline_id,
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }
        save_state(state)
        success = run_pipeline(target_id, active_handle,
                               resume_pipeline_id=pipeline_id)
        if success:
            log("Autopilot complete for %s" % active_handle)
        else:
            log("Autopilot failed for %s" % active_handle)
        return success

    if handle:
        log("Manual target: %s" % handle)
    else:
        log("Picking random unscanned program...")
        handle = pick_random_program()
        if not handle:
            log("No programs available to scan")
            return False

    log("Selected program: %s" % handle)

    target_id, domains = create_target(handle)
    if not target_id:
        return False

    success = run_pipeline(target_id, handle)

    if success:
        log("Autopilot complete for %s" % handle)
    else:
        log("Autopilot failed for %s" % handle)
    return success


def main():
    Path.home().joinpath("recon").mkdir(exist_ok=True)

    if len(sys.argv) >= 2 and sys.argv[1] == "--status":
        show_status()
        return

    if len(sys.argv) >= 2 and sys.argv[1] == "--resume":
        state = load_state()
        if state.get("status") == "running" and state.get("pipeline_id"):
            log("Resuming pipeline %d for %s..." % (
                state["pipeline_id"], state.get("handle", "?")))
            success = run_pipeline(state["target_id"], state["handle"],
                                   resume_pipeline_id=state["pipeline_id"])
            if success:
                log("Autopilot complete for %s" % state["handle"])
            else:
                log("Autopilot failed for %s" % state["handle"])
        else:
            log("No running pipeline to resume (status: %s)" % state.get("status", "none"))
        return

    # Single specific handle — run once and exit
    if len(sys.argv) >= 2 and sys.argv[1] not in ("--once",):
        try_resume_stale()
        run_once(handle=sys.argv[1])
        return

    # --once flag — single random pipeline then exit
    if len(sys.argv) >= 2 and sys.argv[1] == "--once":
        try_resume_stale() or run_once()
        return

    # Default: continuous mode. Parallel (4 pipelines, saturates the netns
    # egress pool) unless AUTOPILOT_MAX_PARALLEL=1, which falls back to the
    # original serial one-at-a-time loop.
    if MAX_PARALLEL_PIPELINES > 1:
        run_continuous_parallel()
        return

    log("Autopilot starting in continuous mode (serial)")
    consecutive_failures = 0

    # First, try to resume any stale pipeline from before restart
    if try_resume_stale():
        consecutive_failures = 0

    while True:
        # Pre-flight: don't start a pipeline if the exit node is down.
        # Blocks here until guard reports healthy again (or never returns
        # if Hetzner is permanently broken — the user expects that).
        wait_for_exit_node()

        success = run_once()

        if success:
            consecutive_failures = 0
            log("Waiting %d seconds before next pipeline..." % BETWEEN_RUNS_DELAY)
            time.sleep(BETWEEN_RUNS_DELAY)
        else:
            consecutive_failures += 1
            backoff = min(BETWEEN_RUNS_DELAY * (2 ** consecutive_failures), MAX_BACKOFF)
            log("Pipeline failed (%d consecutive). Backing off %d seconds..." % (
                consecutive_failures, backoff))
            time.sleep(backoff)


if __name__ == "__main__":
    main()
