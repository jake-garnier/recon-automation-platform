"""HackerOne Bounty Browser — localhost web dashboard."""

import json, os, subprocess, time
from pathlib import Path
from flask import Flask, render_template, request, abort, jsonify
from app.db import get_connection, init_db
from app.recon_routes import recon_bp
from app.hacktivity_routes import hacktivity_bp
from app import credential_store

# Templates live at the repo root (src/app/web.py -> parents[2] == repo root).
_TEMPLATE_DIR = str(Path(__file__).resolve().parents[2] / "templates")
app = Flask(__name__, template_folder=_TEMPLATE_DIR)
app.register_blueprint(recon_bp)
app.register_blueprint(hacktivity_bp)
PER_PAGE = 50


@app.route("/")
def index():
    conn = get_connection()
    stats = {
        "total_programs": conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
        "bounty_programs": conn.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1").fetchone()[0],
        "open_programs": conn.execute("SELECT COUNT(*) FROM programs WHERE submission_state = 'open'").fetchone()[0],
        "bounty_scopes": conn.execute("SELECT COUNT(*) FROM scopes WHERE eligible_for_bounty = 1").fetchone()[0],
    }
    asset_types = conn.execute("""
        SELECT asset_type, COUNT(*) as count FROM scopes
        WHERE eligible_for_bounty = 1 GROUP BY asset_type ORDER BY count DESC
    """).fetchall()
    top_programs = conn.execute("""
        SELECT p.handle, p.name, p.submission_state, COUNT(s.id) as scope_count
        FROM programs p
        JOIN scopes s ON s.program_id = p.id AND s.eligible_for_bounty = 1
        WHERE p.offers_bounties = 1
        GROUP BY p.id ORDER BY scope_count DESC LIMIT 10
    """).fetchall()
    conn.close()
    return render_template("index.html", stats=stats, asset_types=asset_types, top_programs=top_programs)


@app.route("/programs")
def programs():
    q = request.args.get("q", "").strip()
    state = request.args.get("state", "all")
    asset_type = request.args.get("type", "all")
    signal = request.args.get("signal", "all")
    page = max(1, request.args.get("page", 1, type=int))

    conn = get_connection()
    conditions = ["p.offers_bounties = 1"]
    params = []

    if state and state != "all":
        conditions.append("p.submission_state = ?")
        params.append(state)

    if signal == "none":
        conditions.append("p.signal_required = 0")
    elif signal == "required":
        conditions.append("p.signal_required = 1")
    elif signal == "unknown":
        conditions.append("p.signal_required IS NULL")

    if q:
        conditions.append("(p.handle LIKE ? OR p.name LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])

    if asset_type and asset_type != "all":
        scope_join = "JOIN scopes s ON s.program_id = p.id AND s.eligible_for_bounty = 1 AND s.asset_type = ?"
        join_params = [asset_type]
    else:
        scope_join = "LEFT JOIN scopes s ON s.program_id = p.id AND s.eligible_for_bounty = 1"
        join_params = []

    where = "WHERE " + " AND ".join(conditions)
    count_sql = f"SELECT COUNT(DISTINCT p.id) FROM programs p {scope_join} {where}"
    total = conn.execute(count_sql, join_params + params).fetchone()[0]

    offset = (page - 1) * PER_PAGE
    rows = conn.execute(f"""
        SELECT p.handle, p.name, p.submission_state, COUNT(s.id) as scope_count, p.url,
               p.signal_required
        FROM programs p {scope_join}
        {where}
        GROUP BY p.id
        ORDER BY scope_count DESC
        LIMIT ? OFFSET ?
    """, join_params + params + [PER_PAGE, offset]).fetchall()

    # Get distinct asset types for the filter dropdown
    all_types = conn.execute("""
        SELECT DISTINCT asset_type FROM scopes
        WHERE eligible_for_bounty = 1 ORDER BY asset_type
    """).fetchall()
    conn.close()

    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render_template("programs.html",
        programs=rows, q=q, state=state, asset_type=asset_type,
        signal=signal, page=page, total=total, total_pages=total_pages,
        asset_types=[r[0] for r in all_types],
    )


@app.route("/programs/<handle>")
def program_detail(handle):
    conn = get_connection()
    program = conn.execute("SELECT * FROM programs WHERE handle = ?", (handle,)).fetchone()
    if not program:
        conn.close()
        abort(404)

    scopes = conn.execute("""
        SELECT * FROM scopes WHERE program_id = ? AND eligible_for_bounty = 1
        ORDER BY asset_type, asset_identifier
    """, (program["id"],)).fetchall()
    conn.close()
    return render_template("program.html", program=program, scopes=scopes)


@app.route("/cors-poc")
def cors_poc():
    return render_template("cors_poc.html")


@app.route("/magento-xss-demo")
def magento_xss_demo():
    return render_template("magento_xss_demo.html")


@app.route("/playtika-pam-cors-poc")
def playtika_pam_cors_poc():
    return render_template("playtika_pam_cors_poc.html")


# Files live on the Kali host at /tmp, mounted read-only into container at /host-tmp
_TMP = "/host-tmp" if os.path.isdir("/host-tmp") else "/tmp"

# Each Bleichenbacher runner has its own state file. The Kali runner writes to
# the canonical bleich_fff_attack_state.json (read directly by the dashboard).
# The Mac runner syncs its state file up to Kali every 30s via sync_state.sh,
# landing at bleich_fff_mac_attack_state.json.
BLEICH_INSTANCES = [
    {
        "runner": "kali",
        "label": "Kali (homelab)",
        "egress_ip": "<KALI_EGRESS_IP>",
        "state_file": f"{_TMP}/bleich_fff_attack_state.json",
        "log_file": f"{_TMP}/bleich_fff_persistent.log",
        # Flask container doesn't ship procps, so we can't pgrep from in here.
        # Liveness is inferred from state file freshness (same as Mac).
        "pid_pattern": None,
    },
    {
        "runner": "mac",
        "label": "Mac Studio",
        "egress_ip": "<MAC_EGRESS_IP>",
        "state_file": f"{_TMP}/bleich_fff_mac_attack_state.json",
        # Mac's log is tail-synced (last 50 lines) from the Mac to Kali
        # every 30s by sync_state.sh running on the Mac.
        "log_file": f"{_TMP}/bleich_fff_mac_persistent.log",
        "pid_pattern": None,  # can't check Mac process from inside Kali
    },
]


@app.route("/bleichenbacher")
def bleichenbacher_dashboard():
    return render_template("bleichenbacher.html")


def _load_bleich_instance(instance_cfg):
    """Load state + log for a single Bleichenbacher runner.

    Returns a dict with the same fields as the old single-instance response,
    plus runner metadata (runner, label, egress_ip).
    """
    import re
    result = {
        "runner": instance_cfg["runner"],
        "label": instance_cfg["label"],
        "egress_ip": instance_cfg["egress_ip"],
        "phase": "unknown",
        "error": None,
        "state_file": instance_cfg["state_file"],
    }

    # Read state file
    state_file = instance_cfg["state_file"]
    if not os.path.exists(state_file):
        result["error"] = "state file not found"
        return result
    try:
        with open(state_file) as f:
            state = json.load(f)
        result.update(state)
    except Exception as e:
        result["error"] = f"state: {str(e)[:80]}"
        return result

    # Record when the state file was last written (useful for "is the sync alive" check)
    try:
        result["state_mtime"] = int(os.path.getmtime(state_file))
        result["state_age_s"] = int(time.time() - result["state_mtime"])
    except Exception:
        pass

    # Read log tail (only if a log file is configured — Mac instance has none).
    # The log is used for: (1) displaying the live tail in the UI, (2) parsing
    # the *most recent stats line* (rate, http, etc.) which updates faster
    # than the state file. It is NOT used as the authoritative source of phase
    # — phase is derived uniformly from state data below for both runners.
    log_file = instance_cfg.get("log_file")
    if log_file and os.path.exists(log_file):
        try:
            with open(log_file) as f:
                lines = f.readlines()
            result["log_lines"] = [l.rstrip() for l in lines[-30:]]
            result["log_file"] = log_file

            # Walk backwards through the tail to find the most recent line
            # containing an `r/s` stats header. Skip the "State saved" lines
            # which have the header but none of the tested/scanned info.
            stats_line = None
            for line in reversed(result["log_lines"]):
                if "r/s" in line and "State saved" not in line:
                    stats_line = line
                    break
            if stats_line:
                m = re.search(r'\[(\S+)h\s+(\d+)r\s+(\d+)r/s\s+(\d+)c(?:\s+skip=(\S+?)%)?\]', stats_line)
                if m:
                    result["elapsed_h"] = float(m.group(1))
                    result["http_count"] = int(m.group(2))
                    result["rate"] = int(m.group(3))
                    result["conform_count"] = int(m.group(4))
                    if m.group(5) is not None:
                        result["skip_pct"] = float(m.group(5))
                hs = re.search(r'tested (\d+) valid s \(scanned (\d+), skipped (\d+)\)', stats_line)
                if hs:
                    result["s_tested_log"] = int(hs.group(1))
                    result["s_scanned_log"] = int(hs.group(2))
                    result["skipped_count_log"] = int(hs.group(3))
                sm = re.search(r'searched (\d+) s values', stats_line)
                if sm:
                    result["s_tested_log"] = int(sm.group(1))

            full_text = "\n".join(result["log_lines"])
            # Phase hints from log content (narrowing / complete / s1_found)
            if "RECOVERED" in full_text:
                result["_phase_hint"] = "complete"
            elif "Iter " in full_text:
                result["_phase_hint"] = "narrowing"
                im = re.search(r'Iter (\d+).*?(\d+) intervals.*?(\d+) bits', full_text)
                if im:
                    result["iteration"] = int(im.group(1))
                    result["intervals"] = int(im.group(2))
            elif "Step 2a COMPLETE" in full_text or "★★★" in full_text:
                result["_phase_hint"] = "s1_found"
                s1m = re.search(r's1=(\d+)', full_text)
                if s1m:
                    result["s1"] = int(s1m.group(1))

            # Backfill state fields from log parsing if the state file is stale
            # (state file only writes every 10k s; log line updates every 10k
            # too but offset by one write, so they can lag by ~1-2 batches).
            for field in ("s_tested", "s_scanned", "skipped_count"):
                logval = result.get(f"{field}_log")
                if logval is not None and (result.get(field) or 0) < logval:
                    result[field] = logval
        except Exception as e:
            result["error"] = (result.get("error", "") or "") + f" log: {str(e)[:80]}"

    # Fill in rate / skip_pct from state if the log parsing didn't set them.
    # This runs for runners without a log (Mac) and also patches up runners
    # whose log_lines didn't contain a parseable stats line.
    if not result.get("rate"):
        elapsed_h = result.get("elapsed_h") or 0
        http_count = result.get("http_count") or 0
        if elapsed_h and elapsed_h > 0:
            result["rate"] = int(http_count / (elapsed_h * 3600))
    if "skip_pct" not in result and result.get("s_scanned") and result.get("skipped_count") is not None:
        result["skip_pct"] = round(
            result["skipped_count"] / max(1, result["s_scanned"]) * 100, 1
        )

    # Uniform phase derivation (runs for BOTH Kali and Mac so the dashboard
    # shows consistent phase labels regardless of which runner we're looking
    # at). Precedence:
    #   1. log hint (most specific: s1_found / narrowing / complete)
    #   2. state-field inference: if phase is "init" but http_count > 0,
    #      the runner is actually in step 2a (state file lags)
    #   3. state file phase as-is
    hint = result.pop("_phase_hint", None)
    if hint:
        result["phase"] = hint
    else:
        state_phase = result.get("phase") or "unknown"
        if state_phase == "init" and (result.get("http_count") or 0) > 0:
            result["phase"] = "s2a"
        else:
            result["phase"] = state_phase

    # Check if process is alive
    pid_pat = instance_cfg.get("pid_pattern")
    if pid_pat:
        try:
            ps_cmd = subprocess.run(
                ["pgrep", "-f", pid_pat],
                capture_output=True, text=True, timeout=5
            )
            result["process_alive"] = ps_cmd.returncode == 0
            if ps_cmd.stdout.strip():
                result["pid"] = int(ps_cmd.stdout.strip().split()[0])
        except Exception:
            result["process_alive"] = None
    else:
        # For the Mac runner, alive-ness is inferred from state file freshness.
        # If the sync'd state file is < 120s old, assume the Mac is running.
        age = result.get("state_age_s")
        if age is not None:
            result["process_alive"] = age < 120

    return result


@app.route("/api/bleichenbacher/status")
def bleichenbacher_status():
    """Read attack state for all configured Bleichenbacher runners.

    Returns {instances: [...], combined: {...}} so the dashboard can render
    each runner side-by-side AND show an aggregate throughput/progress view.
    """
    instances = [_load_bleich_instance(cfg) for cfg in BLEICH_INSTANCES]

    # Combined metrics across all instances
    combined = {
        "total_http": sum(inst.get("http_count") or 0 for inst in instances),
        "total_rate": sum(inst.get("rate") or 0 for inst in instances),
        "total_conform": sum(inst.get("conform_count") or 0 for inst in instances),
        "total_s_tested": sum(inst.get("s_tested") or 0 for inst in instances),
        "active_count": sum(1 for inst in instances if inst.get("process_alive")),
        "any_s1_found": any(inst.get("phase") in ("s1_found", "narrowing", "complete") for inst in instances),
        "any_complete": any(inst.get("phase") == "complete" for inst in instances),
    }

    resp = jsonify({"instances": instances, "combined": combined})
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ----- Credentials dashboard -----

@app.route("/credentials")
def credentials_page():
    """Per-program authentication credential status.

    Shows which programs have captured auth state, when it was last
    validated, and whether it's still good. Used as the source-of-truth
    for the auth-status badges in triage prompts."""
    creds = credential_store.list_all()
    # Cross-reference with program names for nicer display
    conn = get_connection()
    handles = list({c["program_handle"] for c in creds})
    if handles:
        placeholders = ",".join("?" for _ in handles)
        rows = conn.execute(
            f"SELECT handle, name FROM programs WHERE handle IN ({placeholders})",
            handles,
        ).fetchall()
        names = {r["handle"]: r["name"] for r in rows}
    else:
        names = {}
    # Group by program for cleaner UI
    by_program: dict[str, dict] = {}
    for c in creds:
        h = c["program_handle"]
        if h not in by_program:
            by_program[h] = {
                "handle": h,
                "name": names.get(h, h),
                "credentials": [],
            }
        by_program[h]["credentials"].append(c)
    programs_list = sorted(by_program.values(), key=lambda p: p["handle"])
    conn.close()
    return render_template("credentials.html", programs=programs_list,
                            total=len(creds))


@app.route("/api/credentials/<int:cred_id>/probe", methods=["POST"])
def credentials_probe(cred_id):
    """Run a liveness probe on a stored credential. Updates status."""
    cred = None
    # Need to fetch decrypted to run probe
    conn = get_connection()
    row = conn.execute(
        "SELECT program_handle, auth_type FROM program_credentials WHERE id = ?",
        (cred_id,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    cred = credential_store.get(row["program_handle"], row["auth_type"])
    if not cred:
        return jsonify({"error": "could not decrypt"}), 500
    ok, err = credential_store.probe(cred)
    credential_store.mark_validated(cred["id"], ok, err)
    return jsonify({
        "ok": ok,
        "error": err,
        "cred_id": cred_id,
        "program_handle": row["program_handle"],
    })


@app.route("/api/credentials/<int:cred_id>", methods=["DELETE"])
def credentials_delete(cred_id):
    credential_store.delete(cred_id)
    return jsonify({"deleted": cred_id})


if __name__ == "__main__":
    init_db()
    # Background phase-advance reconciler — runs every 60s to advance stuck
    # 'running' pipelines (both web and oracle).  Previously this only ran
    # on dashboard view and only for web pipelines, causing oracle pipelines
    # to freeze indefinitely after each phase completed.
    from app.recon_routes import start_reconciler
    start_reconciler()
    app.run(host="0.0.0.0", port=5000)
