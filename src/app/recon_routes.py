"""Recon routes — Flask Blueprint for the recon dashboard."""

import json
import os
import threading
import time
from datetime import datetime

import requests
from flask import Blueprint, jsonify, redirect, render_template, request

from app.db import get_connection

recon_bp = Blueprint("recon", __name__)

AGENT_URL = os.environ.get("RECON_AGENT_URL", "http://host.docker.internal:5001")

# Built-in Python tools that run inside the recon agent process (no external binary).
# These must never be skipped with "tool not installed" — they are always available.
BUILTIN_TOOLS = {
    "s3-takeover", "merge-subs", "merge-urls", "cloud-buckets",
    "secret-scan", "cms-detect", "panel-detect", "linkfinder",
    "crt-sh", "git-dumper", "gitleaks", "corscanner", "nextjs-check",
}

# Tool dependency map: which previous tool's output each tool needs as input
TOOL_DEPS = {
    "dnsgen": ("subfinder", "no completed subfinder scan found, run one first"),
    "shuffledns": ("dnsgen", "no completed dnsgen scan found, run it first"),
    "merge-subs": ("subfinder", "no completed subfinder scan found, run one first"),
    "httpx-toolkit": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "getallurls": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "katana": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "nuclei": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "nuclei-takeover": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "subzy": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "naabu": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "nmap": ("naabu", "no completed naabu scan found, run it first"),
    "s3-takeover": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "merge-urls": ("katana", "no completed katana scan found, run it first"),
    "cloud-buckets": ("merge-urls", "no completed merge-urls scan found, run it first"),
    "linkfinder": ("merge-urls", "no completed merge-urls scan found, run it first"),
    "secret-scan": ("merge-urls", "no completed merge-urls scan found, run it first"),
    "arjun": ("merge-urls", "no completed merge-urls scan found, run it first"),
    "cms-detect": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "panel-detect": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "wpscan": ("cms-detect", "no completed cms-detect scan found, run it first"),
    "ffuf": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "dalfox": ("merge-urls", "no completed merge-urls scan found, run it first"),
    # New tools
    "gospider": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "joomscan": ("cms-detect", "no completed cms-detect scan found, run it first"),
    "sqlmap": ("arjun", "no completed arjun scan found, run it first"),
    "commix": ("arjun", "no completed arjun scan found, run it first"),
    "hydra": ("panel-detect", "no completed panel-detect scan found, run it first"),
    "eyewitness": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "git-dumper": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "nomore403": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "kiterunner": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "corscanner": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "nextjs-check": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "feroxbuster": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "paramspider": ("merge-subs", "no completed merge-subs scan found, run one first"),
    "xhr-capture": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    "spa-catchall-detect": ("httpx-toolkit", "no completed httpx-toolkit scan found, run it first"),
    # trufflehog, dnsx have no cross-phase deps (handled via intra-phase)
    # amass, crt-sh, gitleaks have no deps (root tools like subfinder)
}


def _agent(method, path, **kwargs):
    try:
        resp = getattr(requests, method)(f"{AGENT_URL}{path}", timeout=30, **kwargs)
        return resp.json(), resp.status_code
    except requests.ConnectionError:
        return {"error": "Recon agent not reachable"}, 502
    except requests.Timeout:
        return {"error": "Recon agent timed out"}, 504
    except requests.RequestException as e:
        return {"error": f"Recon agent request failed: {e}"}, 502


# --- Pages ---

@recon_bp.route("/recon")
def recon_dashboard():
    conn = get_connection()
    targets = conn.execute("""
        SELECT t.*, COUNT(s.id) as scan_count,
               MAX(s.created_at) as last_scan
        FROM recon_targets t
        LEFT JOIN recon_scans s ON s.target_id = t.id
        GROUP BY t.id ORDER BY t.created_at DESC
    """).fetchall()

    # Parse domain counts for display
    targets_data = []
    for t in targets:
        td = dict(t)
        td["domain_count"] = len(json.loads(t["domains"]))
        targets_data.append(td)

    # Programs available for targeting (no-signal programs first)
    programs = conn.execute("""
        SELECT p.handle, p.name, COUNT(s.id) as scope_count,
               COUNT(CASE WHEN s.asset_type = 'WILDCARD' THEN 1 END) as wildcards,
               p.signal_required
        FROM programs p
        JOIN scopes s ON s.program_id = p.id AND s.eligible_for_bounty = 1
        WHERE p.offers_bounties = 1 AND p.submission_state = 'open'
          AND s.asset_type IN ('URL', 'WILDCARD')
        GROUP BY p.id
        ORDER BY CASE WHEN p.signal_required = 1 THEN 1 ELSE 0 END,
                 wildcards DESC, scope_count DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    return render_template("recon.html", targets=targets_data, programs=programs)


@recon_bp.route("/recon/targets/<int:target_id>")
def recon_target_detail(target_id):
    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return "Target not found", 404

    # Resolve any stale "running" scans before rendering
    _recover_stale_scans(conn, target_id, target["program_handle"])

    scans = conn.execute("""
        SELECT * FROM recon_scans WHERE target_id = ?
        ORDER BY created_at DESC
    """, (target_id,)).fetchall()

    # Get results grouped by type
    result_counts = conn.execute("""
        SELECT r.result_type, COUNT(*) as cnt
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ?
        GROUP BY r.result_type
    """, (target_id,)).fetchall()

    domains = json.loads(target["domains"])
    conn.close()
    return render_template("recon_target.html", target=target, scans=scans, result_counts=result_counts, domains=domains)


import re as _re


def _parse_scope_exclusions(instruction, exclusions):
    """Extract exclusion keywords from a scope instruction string.

    Handles patterns like:
      "Any subdomain containing uat, oat, mat, dev, jenkins, sandpit, nonprodss"
      "Out of scope: staging, test environments"
      "Exclude: *.dev.example.com, *.staging.example.com"
    """
    text = instruction.lower()
    NOISE = {"are", "is", "the", "any", "that", "not", "in", "scope", "of",
             "out", "subdomain", "subdomains", "containing", "environments",
             "environment", "and", "or", "for", "with", "all", "these", "those"}
    # Pattern: "containing <keyword-list>"
    m = _re.search(r'containing\s+(.+?)(?:\.|$)', text)
    if m:
        raw = m.group(1)
        keywords = _re.split(r'[,\s]+', raw)
        for kw in keywords:
            kw = kw.strip().strip("'\"*.")
            if kw and len(kw) >= 2 and kw not in NOISE:
                exclusions.append(kw)
        return
    # Pattern: "out of scope: <list>" or "exclude: <list>"
    m = _re.search(r'(?:out[- ]?of[- ]?scope|exclude|excluding)[:\s]+(.+)', text)
    if m:
        raw = m.group(1)
        # Extract domain-style patterns (*.dev.example.com → "dev")
        for domain_match in _re.finditer(r'\*\.([a-z0-9-]+)\.', raw):
            exclusions.append(domain_match.group(1))
        # Also extract bare comma-separated keywords (skip full domain entries)
        keywords = _re.split(r'[,\s]+', raw)
        for kw in keywords:
            kw = kw.strip().strip("'\"*.")
            if "." in kw:
                continue  # full domain — already handled above
            if kw and len(kw) >= 2 and kw not in NOISE:
                exclusions.append(kw)


# --- API endpoints ---

_MULTI_LABEL_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.mx", "com.ar", "com.pe", "com.co", "com.tr",
    "com.cn", "com.tw", "com.hk", "com.sg", "com.ph", "com.my",
    "ac.uk", "ac.jp", "ac.in", "ac.kr",
    "gov.uk", "gov.au", "gov.br", "gov.in",
    "org.uk", "net.au", "net.br", "edu.au", "edu.br",
}


def _registrable_domain(host):
    """Return registrable parent (eTLD+1) for a hostname.

    Heuristic, no PSL dep: if the last two labels look like a multi-label
    TLD (e.g. co.uk), return last 3 labels; otherwise last 2.
    """
    if not host:
        return host
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


@recon_bp.route("/api/recon/targets", methods=["POST"])
def create_target():
    handle = request.form.get("handle")
    if not handle:
        return jsonify({"error": "handle required"}), 400

    conn = get_connection()
    program = conn.execute("SELECT * FROM programs WHERE handle = ?", (handle,)).fetchone()
    if not program:
        conn.close()
        return jsonify({"error": f"program {handle} not found"}), 404

    # Pull *all* in-scope URL/WILDCARD assets (eligible OR not). Bounty-ineligible
    # wildcards (e.g. "*ripio.com") are still useful for enumeration — we just
    # filter results back into the eligible list afterwards. Without this, programs
    # whose only WILDCARD is bounty-ineligible (ripio is the canonical case) fall
    # back to enumerating exact-subdomain URL items as if they were parents, which
    # produces 0 subfinder results and a hollow pipeline.
    scopes = conn.execute("""
        SELECT asset_identifier, instruction, eligible_for_bounty FROM scopes
        WHERE program_id = ?
          AND asset_type IN ('URL', 'WILDCARD')
    """, (program["id"],)).fetchall()

    domains = []
    scope_exclusions = []
    for s in scopes:
        d = s["asset_identifier"]
        # Parse exclusion keywords from scope instructions (eligible scopes only —
        # ineligible scope notes can include exclusions for other reasons)
        instruction = s["instruction"] or ""
        if instruction and s["eligible_for_bounty"]:
            _parse_scope_exclusions(instruction, scope_exclusions)
        # Clean wildcard prefix and URL prefixes
        if d.startswith("*."):
            d = d[2:]
        elif d.startswith("*"):
            # "*ripio.com" form — no leading dot
            d = d[1:]
        if d.startswith("http://"):
            d = d[7:]
        if d.startswith("https://"):
            d = d[8:]
        d = d.rstrip("/").split("/")[0].lower()
        if d and d not in domains:
            domains.append(d)
        # Also add the registrable parent so subfinder can enumerate sibling
        # subdomains. Without this, scope=trade.ripio.com would only ever ask
        # subfinder for *.trade.ripio.com (which usually returns nothing).
        parent = _registrable_domain(d)
        if parent and parent != d and parent not in domains:
            domains.append(parent)

    # Deduplicate exclusions
    scope_exclusions = sorted(set(scope_exclusions))

    if not domains:
        conn.close()
        return jsonify({"error": "no domains found in scope"}), 400

    # Wildcard pre-flight detection.  Ask the agent (which has DNS access
    # on the Kali host) to probe each parent domain for wildcard DNS so
    # the pipeline can skip dnsgen/shuffledns/active-amass on parents
    # that resolve every subdomain to the same IP.  We pass only the
    # *parent* domains, not full subdomain scopes, to keep latency low —
    # detection is ~1 sec per parent (5 random DNS lookups).
    wildcard_parents = []
    try:
        wc_resp, wc_status = _agent("post", "/wildcard-detect",
                                    json={"domains": domains})
        if wc_status == 200 and isinstance(wc_resp, dict):
            wildcard_parents = wc_resp.get("wildcard_parents", []) or []
    except Exception:
        # Detection is best-effort — if the agent is slow or unreachable
        # we still create the target (just without the wildcard hint).
        pass
    wildcard_detected_at = (
        datetime.utcnow().isoformat() if wildcard_parents else None
    )

    conn.execute(
        "INSERT INTO recon_targets (program_handle, program_name, domains, "
        "scope_exclusions, wildcard_parents, wildcard_detected_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (handle, program["name"], json.dumps(domains),
         json.dumps(scope_exclusions),
         json.dumps(wildcard_parents) if wildcard_parents else None,
         wildcard_detected_at),
    )
    conn.commit()
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Write exclusions file to agent target dir so merge-subs can filter
    if scope_exclusions:
        _agent("post", "/scan/write-exclusions", json={
            "target_name": handle,
            "exclusions": scope_exclusions,
        })

    conn.close()

    return jsonify({
        "id": target_id, "handle": handle, "domains": domains,
        "scope_exclusions": scope_exclusions,
        "wildcard_parents": wildcard_parents,
    }), 201


@recon_bp.route("/api/recon/targets/<int:target_id>", methods=["DELETE"])
def delete_target(target_id):
    conn = get_connection()
    conn.execute("DELETE FROM recon_results WHERE scan_id IN (SELECT id FROM recon_scans WHERE target_id = ?)", (target_id,))
    conn.execute("DELETE FROM recon_scans WHERE target_id = ?", (target_id,))
    conn.execute("DELETE FROM recon_targets WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


@recon_bp.route("/api/recon/scans", methods=["POST"])
def launch_scan():
    data = request.get_json()
    target_id = data.get("target_id")
    tool = data.get("tool")
    options = data.get("options", {})

    if not target_id or not tool:
        return jsonify({"error": "target_id and tool required"}), 400

    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    domains = json.loads(target["domains"])
    target_name = target["program_handle"]

    # Build agent request
    agent_data = {"tool": tool, "target_name": target_name, "options": options}

    if tool == "subfinder":
        agent_data["domains"] = domains
    elif tool in TOOL_DEPS:
        input_file = data.get("input_file")
        if not input_file:
            dep_tool, dep_error = TOOL_DEPS[tool]
            prev_scan = conn.execute("""
                SELECT * FROM recon_scans
                WHERE target_id = ? AND tool = ? AND status = 'completed'
                ORDER BY finished_at DESC LIMIT 1
            """, (target_id, dep_tool)).fetchone()
            if not prev_scan:
                conn.close()
                return jsonify({"error": dep_error}), 400
            # Get the output file from agent
            files_resp, _ = _agent("get", f"/files/{target_name}")
            if "error" in files_resp:
                conn.close()
                return jsonify(files_resp), 502
            # Find the most recent output file for the dep tool
            # Some tools produce output files with different prefixes than their name
            _tool_input_prefix = {
                "linkfinder": "js_urls",
                "secret-scan": "js_urls",
                "arjun": "unique_endpoints",
                "dalfox": "all_urls",
            }
            if tool in _tool_input_prefix:
                prefix = _tool_input_prefix[tool]
                suffix = ".txt"
            else:
                prefix_map = {
                    "httpx-toolkit": "httpx",
                    "merge-subs": "all_subs",
                    "merge-urls": "all_urls",
                }
                prefix = prefix_map.get(dep_tool, dep_tool)
                suffix = ".json" if dep_tool == "httpx-toolkit" else ".txt"
            candidates = [f for f in files_resp.get("files", []) if f["name"].startswith(prefix) and f["name"].endswith(suffix)]
            if not candidates:
                conn.close()
                return jsonify({"error": f"no {dep_tool} output file found on host"}), 404
            input_file = candidates[-1]["name"]
        agent_data["input_file"] = input_file

    # Call agent to start scan
    agent_resp, status_code = _agent("post", "/scan/start", json=agent_data)
    if status_code != 201:
        conn.close()
        return jsonify(agent_resp), status_code

    pid = agent_resp["pid"]

    # Record in DB — save output filenames so we can ingest from disk later
    output_file = agent_resp.get("output_file")
    json_output = agent_resp.get("json_output")
    conn.execute("""
        INSERT INTO recon_scans (target_id, tool, status, pid, output_file, json_output, started_at)
        VALUES (?, ?, 'running', ?, ?, ?, datetime('now'))
    """, (target_id, tool, pid, output_file, json_output))
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    return jsonify({
        "scan_id": scan_id,
        "pid": pid,
        "tool": tool,
        "output_file": agent_resp.get("output_file"),
    }), 201


@recon_bp.route("/api/recon/scans/<int:scan_id>/status")
def scan_status(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "scan not found"}), 404

    pid = scan["pid"]
    if not pid or scan["status"] in ("completed", "failed"):
        conn.close()
        return jsonify({
            "scan_id": scan_id,
            "tool": scan["tool"],
            "status": scan["status"],
            "result_count": scan["result_count"],
            "error": scan["error"],
        })

    # Poll agent
    agent_resp, status_code = _agent("get", f"/scan/{pid}/status")

    # Agent lost scan state (restarted) — try to recover from disk
    if status_code != 200 and scan["status"] == "running":
        target = conn.execute("SELECT program_handle FROM recon_targets WHERE id = ?",
                              (scan["target_id"],)).fetchone()
        output_file = scan["output_file"]
        if target and output_file:
            files_resp, _ = _agent("get", f"/files/{target['program_handle']}")
            files_listing = files_resp.get("files", [])
            file_exists = any(f["name"] == output_file for f in files_listing)
            # gospider-style tools write to json_output (a directory) and only
            # create output_file at ingestion time. Fall back to checking the
            # raw dir so reboot-orphaned scans can be recovered.
            if not file_exists and scan["json_output"]:
                file_exists = any(
                    f["name"] == scan["json_output"]
                    and (f.get("is_dir") or f.get("size", 0) > 0)
                    for f in files_listing
                )
            if file_exists:
                # File exists on disk — scan completed but agent lost state
                count = _ingest_results(conn, scan_id, pid, scan["tool"])
                conn.execute("""
                    UPDATE recon_scans SET status = 'completed', result_count = ?, finished_at = datetime('now')
                    WHERE id = ?
                """, (count, scan_id))
                conn.commit()
                conn.close()
                return jsonify({
                    "scan_id": scan_id, "tool": scan["tool"],
                    "status": "completed", "result_count": count,
                })
        # Agent doesn't know about the scan and no output file — process died
        conn.execute("""
            UPDATE recon_scans SET status = 'failed', error = 'process lost (agent restarted)', finished_at = datetime('now')
            WHERE id = ?
        """, (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({"scan_id": scan_id, "tool": scan["tool"], "status": "failed", "result_count": 0})

    if status_code != 200:
        conn.close()
        return jsonify({"scan_id": scan_id, "status": scan["status"], "agent_error": agent_resp})

    agent_status = agent_resp.get("status", "unknown")
    result_count = agent_resp.get("result_count", 0)

    if agent_status in ("completed", "failed") and scan["status"] == "running":
        conn.execute("""
            UPDATE recon_scans SET status = ?, result_count = ?, finished_at = datetime('now')
            WHERE id = ?
        """, (agent_status, result_count, scan_id))

        # If completed, ingest results
        if agent_status == "completed":
            _ingest_results(conn, scan_id, pid, scan["tool"])

        conn.commit()

    conn.close()
    return jsonify({
        "scan_id": scan_id,
        "tool": scan["tool"],
        "status": agent_status,
        "result_count": result_count,
        "elapsed": agent_resp.get("elapsed"),
    })


@recon_bp.route("/api/recon/scans/<int:scan_id>/log")
def scan_log(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT pid FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan or not scan["pid"]:
        return jsonify({"log": ""})

    agent_resp, _ = _agent("get", f"/scan/{scan['pid']}/output")
    return jsonify(agent_resp)


@recon_bp.route("/api/recon/scans/<int:scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "scan not found"}), 404

    if scan["pid"] and scan["status"] == "running":
        _agent("post", f"/scan/{scan['pid']}/kill")
        conn.execute("""
            UPDATE recon_scans SET status = 'failed', error = 'killed by user', finished_at = datetime('now')
            WHERE id = ?
        """, (scan_id,))
        conn.commit()

    conn.close()
    return jsonify({"status": "stopped"})


@recon_bp.route("/api/recon/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "scan not found"}), 404

    # Kill if still running
    if scan["pid"] and scan["status"] == "running":
        _agent("post", f"/scan/{scan['pid']}/kill")

    conn.execute("DELETE FROM recon_results WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM recon_scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


@recon_bp.route("/api/recon/scans/<int:scan_id>/ingest", methods=["POST"])
def manual_ingest(scan_id):
    """Manually trigger result ingestion for a completed scan."""
    conn = get_connection()
    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "scan not found"}), 404

    if scan["status"] != "completed":
        conn.close()
        return jsonify({"error": "scan not completed"}), 400

    count = _ingest_results(conn, scan_id, scan["pid"], scan["tool"])
    conn.commit()
    conn.close()
    return jsonify({"ingested": count})


@recon_bp.route("/api/recon/results/<int:target_id>")
def get_results(target_id):
    result_type = request.args.get("type", "subdomain")
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 100
    search = request.args.get("q", "").strip()

    conn = get_connection()

    # Build search filter clause
    search_clause = ""
    search_params = []
    if search:
        search_clause = " AND (r.value LIKE ? OR r.metadata LIKE ?)"
        search_params = [f"%{search}%", f"%{search}%"]

    # For subdomains and URLs, deduplicate across scans with source tracking
    if result_type in ("subdomain", "url"):
        base_params = [target_id, result_type] + search_params
        total = conn.execute(f"""
            SELECT COUNT(DISTINCT r.value) FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ? AND r.result_type = ?{search_clause}
        """, base_params).fetchone()[0]

        rows = conn.execute(f"""
            SELECT r.value, GROUP_CONCAT(DISTINCT s.tool) as sources
            FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ? AND r.result_type = ?{search_clause}
            GROUP BY r.value
            ORDER BY r.value
            LIMIT ? OFFSET ?
        """, base_params + [per_page, (page - 1) * per_page]).fetchall()

        results = [{"value": r["value"], "sources": r["sources"]} for r in rows]
    else:
        base_params = [target_id, result_type] + search_params
        total = conn.execute(f"""
            SELECT COUNT(*) FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ? AND r.result_type = ?{search_clause}
        """, base_params).fetchone()[0]

        rows = conn.execute(f"""
            SELECT r.* FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ? AND r.result_type = ?{search_clause}
            ORDER BY r.id DESC
            LIMIT ? OFFSET ?
        """, base_params + [per_page, (page - 1) * per_page]).fetchall()

        results = []
        for r in rows:
            meta = json.loads(r["metadata"]) if r["metadata"] else {}
            results.append({"value": r["value"], **meta})

    conn.close()
    return jsonify({"total": total, "page": page, "results": results})


@recon_bp.route("/api/recon/agent/tools")
def agent_tools():
    resp, status = _agent("get", "/tools")
    return jsonify(resp), status


@recon_bp.route("/api/recon/programs/<handle>/signal", methods=["POST"])
def set_signal_required(handle):
    """Mark a program as requiring signal (1) or not (0).

    POST body: {"signal_required": 1} or {"signal_required": 0}
    Also accepts form data: signal_required=1
    """
    if request.is_json:
        val = request.json.get("signal_required")
    else:
        val = request.form.get("signal_required")
    if val is None:
        return jsonify({"error": "signal_required is required (0 or 1)"}), 400
    val = int(val)
    if val not in (0, 1):
        return jsonify({"error": "signal_required must be 0 or 1"}), 400

    conn = get_connection()
    row = conn.execute("SELECT id FROM programs WHERE handle = ?", (handle,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "program not found"}), 404
    conn.execute("UPDATE programs SET signal_required = ? WHERE handle = ?", (val, handle))
    conn.commit()
    conn.close()
    return jsonify({"handle": handle, "signal_required": val}), 200


@recon_bp.route("/api/recon/programs/signal", methods=["POST"])
def bulk_set_signal_required():
    """Bulk-mark programs as requiring signal.

    POST body: {"handles": ["prog1", "prog2"], "signal_required": 1}
    """
    data = request.json or {}
    handles = data.get("handles", [])
    val = data.get("signal_required")
    if not handles or val is None:
        return jsonify({"error": "handles and signal_required are required"}), 400
    val = int(val)
    if val not in (0, 1):
        return jsonify({"error": "signal_required must be 0 or 1"}), 400

    conn = get_connection()
    updated = 0
    for handle in handles:
        cur = conn.execute("UPDATE programs SET signal_required = ? WHERE handle = ?", (val, handle))
        updated += cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({"updated": updated, "signal_required": val}), 200


# Notable finding types worth investigating for bug bounties
FINDING_TYPES = ("vulnerability", "secret", "exposed_panel", "takeover", "cloud_bucket", "directory")

# Severity ranking for sorting
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


@recon_bp.route("/api/recon/findings/<int:target_id>")
def get_findings(target_id):
    """Return aggregated notable findings for bug bounty investigation."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 100
    search = request.args.get("q", "").strip()
    severity_filter = request.args.get("severity", "").strip().lower()

    conn = get_connection()

    search_clause = ""
    search_params = []
    if search:
        search_clause = " AND (r.value LIKE ? OR r.metadata LIKE ?)"
        search_params = [f"%{search}%", f"%{search}%"]

    severity_clause = ""
    if severity_filter:
        severity_clause = " AND json_extract(r.metadata, '$.severity') = ?"
        search_params.append(severity_filter)

    type_placeholders = ",".join("?" for _ in FINDING_TYPES)
    base_params = [target_id] + list(FINDING_TYPES) + search_params

    total = conn.execute(f"""
        SELECT COUNT(*) FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ({type_placeholders}){search_clause}{severity_clause}
    """, base_params).fetchone()[0]

    rows = conn.execute(f"""
        SELECT r.*, s.tool FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ({type_placeholders}){search_clause}{severity_clause}
        ORDER BY r.id DESC
        LIMIT ? OFFSET ?
    """, base_params + [per_page, (page - 1) * per_page]).fetchall()

    # Summarize counts by type and severity
    summary_rows = conn.execute(f"""
        SELECT r.result_type,
               json_extract(r.metadata, '$.severity') as severity,
               COUNT(*) as cnt
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ({type_placeholders})
        GROUP BY r.result_type, severity
        ORDER BY r.result_type
    """, [target_id] + list(FINDING_TYPES)).fetchall()

    summary = {}
    for sr in summary_rows:
        rtype = sr["result_type"]
        sev = sr["severity"] or "info"
        if rtype not in summary:
            summary[rtype] = {"total": 0, "by_severity": {}}
        summary[rtype]["total"] += sr["cnt"]
        summary[rtype]["by_severity"][sev] = sr["cnt"]

    results = []
    for r in rows:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        severity = meta.get("severity", "")
        # Classify finding priority
        priority = "info"
        if r["result_type"] == "vulnerability":
            priority = severity or "medium"
        elif r["result_type"] == "secret":
            pattern = meta.get("pattern", "")
            value = r["value"] or ""
            # High-value secrets: AWS keys, private keys, secret Stripe keys
            if any(k in pattern for k in ("aws", "private", "secret")):
                priority = "critical"
            elif any(k in pattern for k in ("github_token", "slack_token", "stripe_secret", "stripe_test_secret")):
                priority = "high"
            elif pattern in ("google_api", "jwt", "generic_secret"):
                priority = "medium"
            else:
                priority = "low"
        elif r["result_type"] == "exposed_panel":
            priority = "medium"
        elif r["result_type"] == "takeover":
            status = meta.get("status", "")
            if status.upper() == "VULNERABLE" or meta.get("bucket_status") == "nosuchbucket":
                priority = "critical"
            else:
                priority = "info"
        elif r["result_type"] == "cloud_bucket":
            priority = "high" if meta.get("permissions") else "medium"
        elif r["result_type"] == "directory":
            status_code = meta.get("status", 0)
            priority = "medium" if status_code in (200, 301, 302, 403) else "low"

        results.append({
            "value": r["value"],
            "result_type": r["result_type"],
            "tool": r["tool"],
            "priority": priority,
            **meta,
        })

    conn.close()
    return jsonify({"total": total, "page": page, "results": results, "summary": summary})


# --- Triage System (agentic analysis) ---

# All result types the pipeline can produce
ALL_RESULT_TYPES = (
    "subdomain", "live_host", "url", "open_port", "vulnerability",
    "secret", "exposed_panel", "takeover", "cloud_bucket", "directory",
    "endpoint", "parameter", "cms_finding", "merged_url",
)

# Triage passes — each is a focused analytical lens

# Maps result_type / tool / finding pattern → Obsidian technique note path.
# Used in triage prompts to point analysts to deep-dive methodology docs.
TECHNIQUE_REFERENCES = {
    # result_type → technique note
    "vulnerability": [
        ("sql", "03-Techniques/sql-injection.md"),
        ("xss", "03-Techniques/xss.md"),
        ("command", "03-Techniques/command-injection.md"),
        ("rce", "03-Techniques/command-injection.md"),
        ("ssrf", "03-Techniques/ssrf.md"),
        ("redirect", "03-Techniques/open-redirect.md"),
        ("cors", "03-Techniques/cors-misconfiguration.md"),
        ("smuggl", "03-Techniques/request-smuggling.md"),
        ("race", "03-Techniques/race-condition.md"),
        ("dos", "03-Techniques/denial-of-service.md"),
        ("graphql", "03-Techniques/graphql-misconfiguration.md"),
        ("jwt", "03-Techniques/account-takeover.md"),
        ("oauth", "03-Techniques/oauth-misconfiguration.md"),
        ("keycloak", "03-Techniques/keycloak-misconfiguration.md"),
        ("nextjs", "03-Techniques/source-map-exposure.md"),
        ("wordpress", "03-Techniques/cms-vulnerability.md"),
        ("joomla", "03-Techniques/cms-vulnerability.md"),
        ("drupal", "03-Techniques/cms-vulnerability.md"),
    ],
    "takeover": [("", "03-Techniques/subdomain-takeover.md")],
    "secret": [
        ("aws", "03-Techniques/api-key-exposure.md"),
        ("api.key", "03-Techniques/api-key-exposure.md"),
        ("", "03-Techniques/secret-exposure.md"),
    ],
    "cloud_bucket": [("", "03-Techniques/broken-access-control.md")],
    "cors_misconfiguration": [("", "03-Techniques/cors-misconfiguration.md")],
    "bypass": [("", "03-Techniques/authentication-bypass.md")],
    "default_cred": [("", "03-Techniques/brute-force.md")],
    "live_host": [("", "03-Techniques/information-disclosure.md")],
    "open_port": [("", "03-Techniques/information-disclosure.md")],
    "cms_finding": [("", "03-Techniques/cms-vulnerability.md")],
    "exposed_panel": [
        ("keycloak", "03-Techniques/keycloak-misconfiguration.md"),
        ("sentry", "03-Techniques/sentry-misconfiguration.md"),
        ("actuator", "03-Techniques/actuator-exposure.md"),
        ("swagger", "03-Techniques/openapi-exposure.md"),
        ("", "03-Techniques/authentication-bypass.md"),
    ],
    "directory": [("", "03-Techniques/configuration-disclosure.md")],
    "url": [
        ("redirect", "03-Techniques/open-redirect.md"),
        ("graphql", "03-Techniques/graphql-misconfiguration.md"),
        ("actuator", "03-Techniques/actuator-exposure.md"),
        ("swagger", "03-Techniques/openapi-exposure.md"),
        ("", "03-Techniques/information-disclosure.md"),
    ],
    "endpoint": [
        ("admin", "03-Techniques/authorization-bypass.md"),
        ("api", "03-Techniques/authorization-bypass.md"),
        ("user", "03-Techniques/authorization-bypass.md"),
        ("", "03-Techniques/broken-access-control.md"),
    ],
    "parameter": [
        ("id", "03-Techniques/idor.md"),
        ("user", "03-Techniques/idor.md"),
        ("", "03-Techniques/authorization-bypass.md"),
    ],
    "subdomain": [("", "03-Techniques/subdomain-takeover.md")],
    "api_endpoint": [
        ("", "03-Techniques/authorization-bypass.md"),
    ],
    "xhr_endpoint": [
        # XHR-discovered URLs hint at the live API. Cross-origin ones are the
        # high-value lead — they reveal the API host the SPA actually calls.
        ("graphql", "03-Techniques/graphql-misconfiguration.md"),
        ("", "03-Techniques/authorization-bypass.md"),
    ],
    "screenshot": [("", "03-Techniques/information-disclosure.md")],
}

# Tech-stack → technique injection. When httpx reports these stacks, pre-load the
# matching technique notes so Claude doesn't miss tech-specific attack paths.
TECH_STACK_REFERENCES = {
    "keycloak": "03-Techniques/keycloak-misconfiguration.md",
    "next.js": "03-Techniques/source-map-exposure.md",
    "nextjs": "03-Techniques/source-map-exposure.md",
    "react": "03-Techniques/source-map-exposure.md",
    "webpack": "03-Techniques/supply-chain.md",
    "vite": "03-Techniques/supply-chain.md",
    "spring": "03-Techniques/actuator-exposure.md",
    "sentry": "03-Techniques/sentry-misconfiguration.md",
    "wordpress": "03-Techniques/cms-vulnerability.md",
    "drupal": "03-Techniques/cms-vulnerability.md",
    "joomla": "03-Techniques/cms-vulnerability.md",
    "graphql": "03-Techniques/graphql-misconfiguration.md",
    "swagger": "03-Techniques/openapi-exposure.md",
    "openapi": "03-Techniques/openapi-exposure.md",
    "haproxy": "03-Techniques/request-smuggling.md",
    "nginx": "03-Techniques/request-smuggling.md",
    "akamai": "03-Techniques/request-smuggling.md",
    "cloudflare": "03-Techniques/request-smuggling.md",
    "fastly": "03-Techniques/cache-poisoning.md",
    "varnish": "03-Techniques/cache-poisoning.md",
    "apollo": "03-Techniques/graphql-node-id-idor.md",
    "relay": "03-Techniques/graphql-node-id-idor.md",
    "argo": "03-Techniques/broken-access-control.md",
    "argocd": "03-Techniques/broken-access-control.md",
    "jenkins": "03-Techniques/broken-access-control.md",
    "salesforce": "03-Techniques/salesforce-aura-misconfig.md",
    "force.com": "03-Techniques/salesforce-aura-misconfig.md",
    "lightning": "03-Techniques/salesforce-aura-misconfig.md",
    "saml": "03-Techniques/xxe.md",
    "soap": "03-Techniques/xxe.md",
    "okta": "03-Techniques/scim-provisioning-bypass.md",
    "branch.io": "03-Techniques/mobile-deeplink-token-theft.md",
    "firebase": "03-Techniques/mobile-deeplink-token-theft.md",
}

# Build a flat reference string for triage prompts
_TECHNIQUE_REF_BLOCK = """
== OBSIDIAN TECHNIQUE REFERENCES ==
When you encounter a finding, consult the corresponding technique note in the
Obsidian vault (03-Techniques/) for deep investigation methodology, bypass
techniques, real-world examples, and tool-specific guidance. Key mappings:

| Finding Type | Technique Note | What It Covers |
|---|---|---|
| Nuclei vuln (SQLi) | [[sql-injection]] | UNION/blind/time-based detection, sqlmap tamper scripts, WAF bypass |
| Nuclei vuln (XSS) | [[xss]] | Reflected/stored/DOM, CSP bypass, polyglot payloads, mXSS |
| Nuclei vuln (RCE/CMDi) | [[command-injection]] | OS command separators, blind detection, space/filter bypass |
| SSRF finding | [[ssrf]] | Cloud metadata (IMDSv1/v2), gopher://, DNS rebinding, IP encoding |
| CORS misconfiguration | [[cors-misconfiguration]] | Origin reflection + credentials check, null origin, subdomain chain |
| Subdomain takeover | [[subdomain-takeover]] | CNAME verification, Fastly protection, can-i-take-over-xyz |
| Exposed secret/API key | [[secret-exposure]] / [[api-key-exposure]] | Key type identification, liveness testing, AWS enumerate-iam |
| OAuth/OIDC endpoint | [[oauth-misconfiguration]] | redirect_uri bypass, state CSRF, PKCE downgrade, dirty dancing |
| Keycloak instance | [[keycloak-misconfiguration]] | Open registration, password grant abuse, realm enumeration |
| Open redirect | [[open-redirect]] | Payload list, OAuth token theft chain, javascript: URI |
| GraphQL endpoint | [[graphql-misconfiguration]] | Introspection, batching, alias bombing, IDOR via node queries |
| Actuator/Spring Boot | [[actuator-exposure]] | /env secrets, heapdump creds, Jolokia RCE, gateway RCE |
| Swagger/OpenAPI | [[openapi-exposure]] | Hidden endpoints, unauthenticated routes, admin API discovery |
| Admin/login panel | [[authentication-bypass]] | Forced browsing, default creds, path traversal, IP header bypass |
| Any authenticated endpoint | [[authorization-bypass]] / [[broken-access-control]] | OWASP #1 (40% surge in 2025). Horizontal/vertical privesc, mass assignment, two-account testing, IDOR-via-GraphQL-alias, missing function-level access control |
| CMS detected | [[cms-vulnerability]] | WPScan, xmlrpc brute force, Joomla CVEs, Drupalgeddon |
| IDOR pattern | [[idor]] | Two-account testing, UUID predictability, array wrapping bypass |
| Source map found | [[source-map-exposure]] / [[supply-chain]] | unwebpack-sourcemap, secret grep, **plus extract `node_modules/@scope/` names → check public registry for dependency confusion (Birsan technique, $130k+ historical bounties)** |
| Sentry instance | [[sentry-misconfiguration]] | DSN extraction, event injection, self-registration, SSRF |
| Race condition | [[race-condition]] | Single-packet attack, limit-overrun, Turbo Intruder |
| Request smuggling | [[request-smuggling]] / [[request-smuggling-field-notes-2026-04]] / [[request-smuggling-target-candidates]] | CL.TE/TE.CL probes, H2 downgrade, session hijacking; field notes contain operational learnings from Elastic investigation |
| Config file exposed | [[configuration-disclosure]] | .env, .git, phpinfo, backup files, CI/CD configs |
| 403 bypass | [[authentication-bypass]] | Verb tampering, path traversal, header injection |
| Default credentials | [[brute-force]] | Rate limit bypass, OTP brute force, credential stuffing |
| Login/reset/registration endpoint | [[user-enumeration]] | **Differential response: status code, length, timing, error wording. P4 baseline, P3+ when chained to credential stuffing or PII exposure** |
| Memory corruption | [[memory-corruption]] | Fuzzing with AFL++, ASAN output, heap spray, ROP |
| Supply chain / CI/CD / npm scope | [[supply-chain]] | **Dependency confusion (unclaimed `@scope/` on npm/PyPI), typosquatting, GitHub Actions tag-pin attacks, lockfile poisoning, phantom dependencies. Alex Birsan paid $130k+ across 35 companies** |
| User enumeration | [[user-enumeration]] | Login/reset differential responses, timing attacks |
| DoS finding | [[denial-of-service]] | ReDoS, GraphQL depth, XML bombs, Slowloris |
| Account takeover | [[account-takeover]] | Password reset poisoning, JWT none alg, OAuth ATO chains |
| TLS / crypto / SAML / JWE | [[oracle-attacks-taxonomy]] / [[bleichenbacher-rsa-oracle]] / [[cbc-padding-oracle]] / [[xml-encryption-oracle]] | Oracle pipeline targets; consult taxonomy for full classification |
| GraphQL `node(id:)` / Relay global ID / persisted query | [[graphql-node-id-idor]] | **H1 #1618347 $25k, #1819832 $15k, #2207248 $5k. Test EVERY operation taking `id`/`gid`/`nodeId` with two accounts; check delete-mutations with foreign IDs in arrays; extract persisted-query hashes from source maps + replay with swapped variables.** |
| postMessage handler on any JS app | [[postmessage-xss]] | **H1 #2089042 Yelp ATO, #603764 $2.5k Upserve, 8+ Shopify reports. Grep JS for `addEventListener("message"`; check origin validation (startsWith/endsWith/includes are bypassable); identify data sink (innerHTML, eval, location, cookie write); build self-contained evil.com PoC.** |
| CDN-fronted host (cdn.* / static.* / *.cloudfront / *.fastly) | [[cache-poisoning]] | **H1 #1695604 $3.8k Shopify, #409370 $2.5k H1, #1096609 $2.9k Shopify. Test cache key normalization (backslash, trailing dot/slash, semicolons); probe unkeyed header reflection (`X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Scheme`); use `?cb=$RANDOM` cache busters. Use Param Miner.** |
| Any OTP / verification / approval / invitation / coupon redemption / mass-assignable PATCH | [[business-logic-bypass]] | **H1 #1543159 $5k Reddit, #1849626 $5k Stripe, #2588329 $2k Indrive. Test OTP=`0000`/`1234`; client-supplied state fields (`admin_approval: APPROVED`); re-redemption (N calls succeed); mass-assignment (`role`, `verified`, `plan`, `tenant_id`); step-skip (call final endpoint without earlier steps); negative numbers / type confusion.** |
| Object-detail URL (`/reports/<id>`, `/users/<id>`, `/orders/<id>`) | [[information-disclosure]] | **H1 #3000510 $25k. ALWAYS test `.json/.xml/.csv/.rss/.atom/.pdf` suffix + `?_format=json` — alternative-format views often bypass HTML-view field filters and leak fields hidden in the UI.** |
| Avatar / image / SVG upload | [[file-upload]] (new) | **H1 #2107680 Basecamp $8.8k via SVG → librsvg memory leak → AWS keys + session cookies. For every avatar upload: identify converter (ImageMagick/librsvg/Ghostscript); test polyglot SVG + memory-disclosure payloads.** |
| Admin panel + cousin subdomain | CSRF chain via [[broken-access-control]] | **H1 #2326194 $4.6k ArgoCD. SameSite=Lax does NOT block cross-cousin-subdomain attacks. Test if admin panel accepts `Content-Type: text/plain` POST (no preflight); chain with stored XSS / weak content on a sibling subdomain.** |
| Connector / integration / datasource config field | [[command-injection]] (extended) | **H1 #1529790 + #1547877 $5k each Aiven. Test JDBC URL injection (`jdbc:sqlite:`, `jdbc:h2:mem:`); JAAS `JndiLoginModule`; JNDI URLs (`ldap://`, `rmi://`); CRLF injection in SMTP/log/webhook URL fields (#1200647 Grafana $5k).** |
| SSO / SCIM provisioning endpoint (`/scim/v2/Users`) | [[scim-provisioning-bypass]] | **H1 #3178999 SCIM email-swap ATO of default sandbox users. Test: create user with username=victim, edit email field to attacker-controlled, password reset → ATO. Default-created users (demo-*, admin-*) are mass-impact targets.** |
| Salesforce host (`*.force.com`, `*.my.salesforce-sites.com`, `*.lightning.force.com`) | [[salesforce-aura-misconfig]] | **H1 #1023572 Acronis Aura unauth read. POST `/aura` or `/s/sfsites/aura` with `getItems` action + `entityNameOrId: Event` (or any custom `__c` object). Unauth read of internal records. Standard objects: Event, Case, Contact, User, Account, Attachment.** |
| XML-accepting endpoint (sitemap import, SAML, SOAP, KML/SVG/docx/xlsx upload) | [[xxe]] | **H1 #248668 Twitter SXMP $X, #312543 Semrush sitemap.xml $X. Submit `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` payload. Test parameter-entity blind XXE if not reflected. ZIP-of-XML formats (docx/xlsx/pptx/nupkg) carry XXE via metadata.** |
| Import / copy / move / fork / package-upload / archive-extract feature | [[path-traversal]] | **H1 #827052 GitLab UploadsRewriter **$20k**; #822262 Nuget Zip-Slip $12k. Test `../`, `..%2F`, double-encoded variants. Test path traversal in **filenames inside uploaded zip** (Zip-Slip pattern). Test markdown `![alt](/uploads/<traversal>)` for "copy-attachments-during-move" features.** |
| Mobile app deeplink (Android intent-filter / iOS universal link) | [[mobile-deeplink-token-theft]] | **H1 #855618 Shopify Arrive Branch.io, #1122177 Reddit, #532225 Zomato $750. Extract APK, parse AndroidManifest.xml for intent-filters carrying tokens. For each domain: check `/.well-known/assetlinks.json` — if missing, build malicious-app PoC to intercept tokens → ATO.** |
| SSRF primitive (webhook, image preview, sitemap fetch, PDF generator, profile import) | [[ssrf-cloud-metadata]] | **H1 #341876 Shopify Exchange $50k+ full chain: SSRF → GCP `/v1beta1` metadata (no header needed) → `kube-env` dump → Kubelet certs → kubectl exec → cluster root. AWS IMDSv1 still common. Test 303-redirect bypass when direct IPs blocked.** |

Use `mcp__obsidian__read_note` to fetch the full technique note when you need
detailed payloads, bypass techniques, or real-world report examples for your analysis.
"""

TRIAGE_PASSES = {
    1: {
        "name": "Critical & High-Value Findings",
        "description": "Quick wins: confirmed vulnerabilities, takeovers, exposed secrets, misconfigured cloud buckets. These are directly reportable with minimal extra investigation.",
        "focus_types": ["vulnerability", "takeover", "secret", "cloud_bucket"],
        "prompt": (
            "You are analyzing bug bounty recon results for {program} ({domains}).\n"
            "This is PASS 1: Critical & High-Value quick wins.\n\n"
            "SCOPE: {scope_note}\n\n"
            + _TECHNIQUE_REF_BLOCK + "\n\n"
            "Review EVERY finding below. For each one, determine:\n"
            "1. Is this a real, exploitable vulnerability or a false positive?\n"
            "2. What is the actual security impact?\n"
            "3. What manual verification steps should be taken?\n"
            "4. Is this reportable to HackerOne as-is, or does it need more investigation?\n\n"
            "When a finding matches a known vulnerability class, consult the corresponding\n"
            "technique note above for detection methodology, exploitation steps, bypass\n"
            "techniques, and real-world examples that inform your analysis.\n\n"
            "Be skeptical of nuclei results — many templates produce false positives. "
            "Cross-reference with the host context provided.\n\n"
            "--- FINDINGS ({count} total) ---\n{data}"
        ),
    },
    2: {
        "name": "Attack Surface Correlation",
        "description": "Per-host deep dive: for each live host, correlate its ports, tech stack, CMS, directories, and endpoints. This is where non-obvious bugs hide — an outdated framework + exposed admin panel + open database port = a real finding.",
        "focus_types": ["live_host", "open_port", "cms_finding", "exposed_panel", "directory"],
        "prompt": (
            "You are analyzing bug bounty recon results for {program} ({domains}).\n"
            "This is PASS 2: Attack Surface Correlation.\n\n"
            "SCOPE: {scope_note}\n\n"
            + _TECHNIQUE_REF_BLOCK + "\n\n"
            "Below are hosts grouped with ALL their associated data (ports, tech stack, CMS, "
            "directories, panels). For each host, look for:\n"
            "1. Dangerous combinations (e.g. admin panel + default credentials tech + open DB port)\n"
            "2. Outdated software versions with known CVEs\n"
            "3. Exposed management interfaces (phpMyAdmin, Grafana, Jenkins, ArgoCD, etc.)\n"
            "4. Services that shouldn't be public (databases, caches, message queues)\n"
            "5. Subdomain takeover candidates (CNAME to deprovisioned services)\n"
            "6. Hosts that warrant manual investigation (interesting tech stack, unusual ports)\n\n"
            "When you identify a technology (Keycloak, Spring Boot, WordPress, Sentry, etc.),\n"
            "consult the corresponding technique note for targeted attack methodology.\n\n"
            "== TECH-STACK AUTO-LOAD ==\n"
            "If httpx tech-detection reports any of these stacks for a host, ALSO consult the\n"
            "corresponding technique note before moving on:\n"
            "  keycloak → [[keycloak-misconfiguration]]\n"
            "  next.js / react / webpack / vite → [[source-map-exposure]] AND [[supply-chain]]\n"
            "    (every modern JS app is a dependency-confusion candidate via source-map name leak)\n"
            "  spring-boot / spring → [[actuator-exposure]]\n"
            "  sentry → [[sentry-misconfiguration]]\n"
            "  wordpress / drupal / joomla → [[cms-vulnerability]]\n"
            "  graphql → [[graphql-misconfiguration]]\n"
            "  swagger / openapi / redoc → [[openapi-exposure]]\n"
            "  haproxy / nginx / akamai / cloudflare / fastly → [[request-smuggling]] and\n"
            "    [[request-smuggling-field-notes-2026-04]] (operational learnings from Elastic)\n"
            "  any login page → [[user-enumeration]] AND [[authentication-bypass]]\n"
            "  any /api/ or /v1/ path → [[authorization-bypass]] (OWASP #1, 40% surge in 2025)\n"
            "  cdn.* / static.* / assets.* / *.cloudfront.net / *.fastly.net → [[cache-poisoning]]\n"
            "    (cache key normalization + unkeyed-header reflection are routine $2k-$4k bugs)\n"
            "  any JS-heavy app (React/Vue/Angular/Next/Svelte) → [[postmessage-xss]]\n"
            "    (grep JS for `addEventListener(\"message\"`; chain with cookie bridge or OAuth code theft)\n"
            "  ArgoCD / Jenkins / Grafana / Airflow / Jupyter / K8s dashboard → [[broken-access-control]]\n"
            "    (test if endpoints accept `Content-Type: text/plain` without CSRF — H1 #2326194 paid $4.6k for Argo CSRF→k8s RCE)\n"
            "  any connector/integration/datasource config field → [[command-injection]]\n"
            "    (JDBC URLs, JNDI URLs, SMTP/webhook CRLF — H1 #1529790, #1547877, #1200647 all paid $5k)\n"
            "  Salesforce host (*.force.com, *.salesforce-sites.com, *.lightning.force.com) → [[salesforce-aura-misconfig]]\n"
            "    (POST /aura or /s/sfsites/aura with `getItems` action — unauth read of Event/Case/Contact/User/Account/custom__c objects)\n"
            "  SSO + SCIM (`/scim/v2/Users`, `/api/scim/v2/Users`) → [[scim-provisioning-bypass]]\n"
            "    (email-swap ATO; default-created users e.g. demo-* are mass-impact targets)\n"
            "  ANY webhook / image-preview / link-unfurl / PDF-gen / sitemap-fetch / profile-import → [[ssrf-cloud-metadata]]\n"
            "    (#341876 Shopify Exchange paid the $50k+ chain via GCP /v1beta1 → kube-env → kubectl)\n"
            "  XML-accepting endpoints (SAML /sso, SOAP, sitemap-import, .docx/.xlsx/.kml/.svg upload) → [[xxe]]\n"
            "    (test `<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>`; ZIP-of-XML formats are common vector)\n\n"
            "Don't just list what you see — reason about what attack paths each host enables.\n\n"
            "--- HOSTS ({count} total) ---\n{data}"
        ),
    },
    3: {
        "name": "URL & Endpoint Analysis",
        "description": "Review crawled URLs, JS-extracted endpoints, and discovered parameters for IDOR patterns, API keys in URLs, debug/admin endpoints, sensitive file paths, and parameter injection points.",
        "focus_types": ["url", "endpoint", "parameter", "merged_url", "xhr_endpoint", "api_endpoint"],
        "prompt": (
            "You are analyzing bug bounty recon results for {program} ({domains}).\n"
            "This is PASS 3: URL & Endpoint Deep Dive.\n\n"
            "SCOPE: {scope_note}\n\n"
            + _TECHNIQUE_REF_BLOCK + "\n\n"
            "Below are crawled URLs, JS-extracted endpoints, and discovered parameters.\n"
            "Look for:\n"
            "1. IDOR patterns — sequential IDs, user-specific paths (e.g. /api/users/123/profile)\n"
            "   → Consult [[idor]] for two-account testing, array wrapping bypass, GraphQL aliases\n"
            "2. API keys, tokens, or secrets in URL parameters\n"
            "   → Consult [[api-key-exposure]] for key type identification and liveness testing\n"
            "3. Debug/admin endpoints (e.g. /debug, /actuator, /elmah, /__debug__)\n"
            "   → Consult [[actuator-exposure]] for Spring Boot, [[openapi-exposure]] for Swagger\n"
            "4. Sensitive file paths (e.g. .env, .git/config, backup.sql, wp-config.php)\n"
            "   → Consult [[configuration-disclosure]] for exploitation and git-dumper usage\n"
            "5. Parameters that suggest injection points (e.g. url=, redirect=, file=, path=, cmd=)\n"
            "   → Consult [[sql-injection]], [[command-injection]], [[ssrf]], [[open-redirect]]\n"
            "6. API versioning that suggests older, less-secured versions exist\n"
            "7. GraphQL endpoints, Swagger/OpenAPI docs\n"
            "   → Consult [[graphql-misconfiguration]], [[openapi-exposure]]\n"
            "8. Unprotected file upload endpoints\n"
            "9. Source map files (.js.map) — DO BOTH things, not just secret extraction:\n"
            "   a. Consult [[source-map-exposure]] for reconstruction and secret extraction\n"
            "   b. **Extract every `node_modules/@scope/<name>` and `node_modules/<name>` path from\n"
            "      the `sources` array. For each unique internal-looking name, check the public\n"
            "      registry: `curl -s -o /dev/null -w '%{{http_code}}' https://registry.npmjs.org/<name>`.\n"
            "      Any 404 is a dependency confusion candidate (consult [[supply-chain]]).** This is\n"
            "      the Alex Birsan technique that paid $130k across 35 major companies.\n"
            "   c. If you see an `@<company-scope>/` prefix, also check whether the scope itself\n"
            "      is registered: `curl https://www.npmjs.com/org/<company-scope>` — unclaimed\n"
            "      scopes can be registered by anyone.\n"
            "10. Authenticated-looking endpoints (anything under /api/, /admin/, /user/, /v1/)\n"
            "    → Consult [[authorization-bypass]] for two-account methodology, mass assignment,\n"
            "      horizontal/vertical privesc. This is OWASP #1 in 2025 and undertested compared\n"
            "      to IDOR. Don't stop at IDOR — also try changing roles, tenant IDs, mass-assigning\n"
            "      `isAdmin`/`role` fields, and stripping auth headers entirely.\n"
            "11. Login / password-reset / registration endpoints\n"
            "    → Consult [[user-enumeration]]. Submit valid + invalid usernames and compare:\n"
            "      status code, Content-Length (1-byte diffs matter), response timing (>= 5ms is\n"
            "      exploitable), Set-Cookie behavior, error wording (subtle trailing period etc.).\n"
            "12. **Object-detail URLs (`/<thing>/<id>` style)** — for EVERY such URL discovered,\n"
            "    test `.json/.xml/.csv/.pdf/.rss/.atom` suffix + `?_format=json` / `?format=xml`.\n"
            "    → Consult [[information-disclosure]]. H1 #3000510 paid **$25,000** for\n"
            "      `/reports/<id>.json` leaking fields hidden in the HTML view (email, OTP backup\n"
            "      codes, phone, secret tokens). This is the highest-paying info-disclosure pattern\n"
            "      in the H1 hacktivity index — and the pipeline does not currently probe for it.\n"
            "13. **GraphQL endpoints / persisted-query hashes** — beyond introspection:\n"
            "    → Consult [[graphql-node-id-idor]]. For EVERY operation name extracted from JS or\n"
            "      source maps (e.g. `BillDetails`, `getModel`, `DeleteStorySnaps`), if the operation\n"
            "      takes an `id`/`gid`/`nodeId` variable, swap it for a foreign ID with two test\n"
            "      accounts. Snapchat paid $15k, HackerOne $25k, Shopify $5k, GitLab $1.16k for this\n"
            "      specific bug class. Also test `node(id:\"gid://...\")` directly with sequential IDs.\n"
            "14. **OTP / verification / approval / coupon endpoints** — for EACH, run the\n"
            "    [[business-logic-bypass]] checks:\n"
            "      - OTP: submit `0000`, `1234`, `123456`, empty, null, OTP-for-different-identifier\n"
            "      - State fields: send `{{\"status\":\"APPROVED\",\"admin_approval\":\"APPROVED\"}}` (Reddit $5k)\n"
            "      - Mass assignment: send `{{\"role\":\"admin\",\"verified\":true,\"plan\":\"enterprise\"}}` in PATCH\n"
            "      - Re-redemption: call the endpoint 5-10 times sequentially (Stripe $5k)\n"
            "      - Step skip: call the final endpoint without earlier verification steps\n"
            "15. **postMessage handlers in any JS app** — grep every JS bundle for\n"
            "    `addEventListener(\"message\"` or `window.onmessage`.\n"
            "    → Consult [[postmessage-xss]]. Extract the handler body. If origin validation is\n"
            "      missing, weak (`startsWith`/`endsWith`/`includes`), or absent: build self-contained\n"
            "      evil.com PoC. Shopify alone has 8+ disclosed postMessage XSS reports.\n"
            "16. **Import / copy / move / fork / package-upload / archive-extract features** —\n"
            "    for EACH such feature found, test [[path-traversal]] with `../`, `..%2F`,\n"
            "    double-encoded variants, and (for zip-uploads) Zip-Slip filenames inside the archive.\n"
            "    GitLab paid **$20,000** for UploadsRewriter traversal, **$12,000** for Nuget Zip-Slip.\n"
            "17. **XML-accepting endpoints** (sitemap-import, SAML, SOAP, .docx/.xlsx/.kml upload):\n"
            "    test [[xxe]] with `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`. Use parameter-entity\n"
            "    + external DTD for blind XXE via OOB callback.\n"
            "18. **SSRF candidates** (webhook URL, image preview, link-unfurl, PDF generator, profile-import):\n"
            "    test [[ssrf-cloud-metadata]] full chain. AWS IMDSv1, GCP /v1beta1 (no header needed),\n"
            "    Azure IMDS. If GCP: fetch `kube-env` → Kubelet certs → kubectl. Shopify paid $50k+ for this chain.\n"
            "19. **Salesforce-hosted hosts** (`*.force.com`, `*.salesforce-sites.com`):\n"
            "    test [[salesforce-aura-misconfig]] — POST to `/aura` or `/s/sfsites/aura` with `getItems`\n"
            "    action enumerating Event/Case/Contact/User/Account/custom__c objects.\n"
            "20. **SSO + SCIM endpoints** (`/scim/v2/Users`): test [[scim-provisioning-bypass]] —\n"
            "    email-swap ATO of default-created users (demo-member, support, etc.) in sandbox/tenant.\n"
            "21. **Mobile apps** (if program scope includes Android/iOS): extract APK/IPA,\n"
            "    enumerate intent-filters and universal-links, test [[mobile-deeplink-token-theft]].\n\n"
            "For interesting findings, suggest specific curl commands to verify.\n\n"
            "--- URLs & ENDPOINTS ({count} total) ---\n{data}"
        ),
    },
    4: {
        "name": "Gap Analysis & Missed Opportunities",
        "description": "What did the pipeline miss? Subdomains with no further probing, tools that failed or were skipped, high-value hosts that weren't fully scanned. Identifies what to investigate manually.",
        "focus_types": [],  # uses scan metadata, not results
        "prompt": (
            "You are analyzing bug bounty recon results for {program} ({domains}).\n"
            "This is PASS 4: Gap Analysis.\n\n"
            "SCOPE: {scope_note}\n\n"
            + _TECHNIQUE_REF_BLOCK + "\n\n"
            "Below is a summary of what the automated pipeline found AND what it missed.\n"
            "Identify:\n"
            "1. Subdomains that were discovered but never probed (no httpx/naabu data)\n"
            "2. Live hosts that were probed but never scanned (no nuclei/katana data)\n"
            "3. Tools that failed or were skipped — what would they have found?\n"
            "4. High-value targets (based on tech stack, naming) that deserve manual testing\n"
            "5. Common bug classes the automated tools can't detect — for EACH, reference the\n"
            "   technique note that contains the manual testing methodology:\n"
            "   - CORS → [[cors-misconfiguration]] (origin reflection + credentials check)\n"
            "   - Auth bypass → [[authentication-bypass]] (forced browsing, default creds)\n"
            "   - Business logic → [[race-condition]] (single-packet attack, limit-overrun)\n"
            "   - SSRF → [[ssrf]] (URL params, webhooks, PDF generators)\n"
            "   - OAuth → [[oauth-misconfiguration]] (redirect_uri, state, PKCE)\n"
            "   - IDOR → [[idor]] (two-account testing methodology)\n"
            "   - Authz → [[authorization-bypass]] (mass assignment, role switch, missing FLAC)\n"
            "   - User enum → [[user-enumeration]] (differential responses, timing)\n"
            "   - Supply chain → [[supply-chain]] (dep confusion from source maps)\n"
            "   - GraphQL node IDOR → [[graphql-node-id-idor]] ($5k-$25k disclosed; test every\n"
            "     `id`/`gid`/`nodeId` variable with two accounts; persisted-query operation swap)\n"
            "   - postMessage XSS → [[postmessage-xss]] (grep JS for `addEventListener(\"message\"`;\n"
            "     check origin validation; build evil.com PoC). Hugely undertested.\n"
            "   - Cache poisoning → [[cache-poisoning]] (Param Miner methodology; test cache key\n"
            "     normalization on every CDN-fronted host; unkeyed-header reflection probes)\n"
            "   - Business logic → [[business-logic-bypass]] (OTP `0000`, client-supplied state,\n"
            "     mass-assignment, re-redemption, step-skip — pipeline can't find these)\n"
            "   - Object `.json` ext → [[information-disclosure]] (test every `/object/<id>` URL\n"
            "     with `.json/.xml/.csv/.rss/.atom/.pdf` and `?_format=json` — alternative formats\n"
            "     often leak fields the HTML view hides. H1 #3000510 paid **$25,000** for this pattern.)\n"
            "   - SCIM email-swap → [[scim-provisioning-bypass]] (H1 #3178999; default-created\n"
            "     users in tenants are mass-impact ATO targets)\n"
            "   - Salesforce Aura → [[salesforce-aura-misconfig]] (H1 #1023572; unauth read of\n"
            "     Event/Case/Contact/User objects via `/aura` or `/s/sfsites/aura`)\n"
            "   - XXE → [[xxe]] (H1 #248668, #312543; sitemap/SAML/SOAP/docx/xlsx upload vectors)\n"
            "   - Path traversal in import/copy → [[path-traversal]] (H1 #827052 **$20k**, #822262 $12k;\n"
            "     test Zip-Slip in archive uploads; markdown attachment-copy traversal)\n"
            "   - Mobile deeplink → [[mobile-deeplink-token-theft]] (H1 #855618, #532225;\n"
            "     extract APK, check `/.well-known/assetlinks.json` per domain in intent-filters)\n"
            "   - SSRF cloud metadata chain → [[ssrf-cloud-metadata]] (H1 #341876 Shopify $50k+;\n"
            "     test GCP /v1beta1 bypass, kube-env extraction, kubectl exec chain)\n"
            "6. Specific manual tests to run based on the tech stack discovered\n\n"
            "Be concrete — don't just say 'test for CORS', say 'test playback.example.com for CORS "
            "origin reflection because it's a streaming server that likely handles credentials, "
            "see [[cors-misconfiguration]] for the full testing checklist'.\n\n"
            "== VAULT COVERAGE AUDIT ==\n"
            "Before finishing, do this check explicitly:\n"
            "1. Call `mcp__obsidian__list_directory` with `path: '03-Techniques'` to list every\n"
            "   technique note in the knowledge base.\n"
            "2. For each technique, decide: was it exercised against this target by the pipeline\n"
            "   or by your analysis in passes 1-3? Answer EXERCISED or NOT-EXERCISED.\n"
            "3. For every NOT-EXERCISED technique, write one concrete sentence on whether it\n"
            "   plausibly applies to this target's tech stack/attack surface and what specific\n"
            "   manual test would surface it. If it doesn't apply (e.g. memory-corruption on a\n"
            "   pure web target with no native binaries), say so and move on.\n"
            "4. Highlight the top 3 NOT-EXERCISED techniques most likely to yield a finding here.\n"
            "These three become your concrete next-action list for manual testing in Caido.\n\n"
            "--- PIPELINE COVERAGE ---\n{data}"
        ),
    },
}


def _extract_host(value, metadata):
    """Extract a canonical hostname from a result value/metadata."""
    if not value:
        return None
    # JSONL live_host entries have url field
    if isinstance(metadata, dict) and "url" in metadata:
        value = metadata["url"]
    # Strip protocol and path
    v = value.strip()
    for prefix in ("https://", "http://"):
        if v.lower().startswith(prefix):
            v = v[len(prefix):]
    # Remove port, path, query
    v = v.split("/")[0].split("?")[0].split("#")[0]
    # For host:port format (naabu), strip port
    if ":" in v:
        v = v.rsplit(":", 1)[0]
    return v.lower() if v else None


@recon_bp.route("/api/recon/triage/<int:target_id>")
def get_triage_data(target_id):
    """Return all results grouped by host for agentic triage analysis."""
    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    # Fetch ALL results for this target
    rows = conn.execute("""
        SELECT r.result_type, r.value, r.metadata, s.tool, s.status as scan_status
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ?
        ORDER BY r.result_type, r.id
    """, (target_id,)).fetchall()

    # Fetch scan metadata for gap analysis
    scans = conn.execute("""
        SELECT tool, status, result_count, started_at, finished_at, error
        FROM recon_scans WHERE target_id = ?
        ORDER BY created_at
    """, (target_id,)).fetchall()

    # Fetch program scope info
    program = conn.execute(
        "SELECT * FROM programs WHERE handle = ?", (target["program_handle"],)
    ).fetchone()
    scope_info = []
    if program:
        scope_rows = conn.execute("""
            SELECT asset_type, asset_identifier, max_severity, instruction
            FROM scopes WHERE program_id = ? AND eligible_for_bounty = 1
        """, (program["id"],)).fetchall()
        scope_info = [dict(s) for s in scope_rows]

    conn.close()

    # Group results by host
    hosts = {}  # hostname -> {result_type -> [results]}
    ungrouped = {}  # result_type -> [results] (things that don't map to a host)

    for r in rows:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        host = _extract_host(r["value"], meta)
        entry = {
            "value": r["value"],
            "type": r["result_type"],
            "tool": r["tool"],
            **meta,
        }

        if host:
            if host not in hosts:
                hosts[host] = {}
            rtype = r["result_type"]
            if rtype not in hosts[host]:
                hosts[host][rtype] = []
            hosts[host][rtype].append(entry)
        else:
            rtype = r["result_type"]
            if rtype not in ungrouped:
                ungrouped[rtype] = []
            ungrouped[rtype].append(entry)

    # Build summary counts
    type_counts = {}
    for r in rows:
        rtype = r["result_type"]
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

    domains = json.loads(target["domains"])
    exclusions = json.loads(target["scope_exclusions"]) if target["scope_exclusions"] else []

    return jsonify({
        "target_id": target_id,
        "program": target["program_handle"],
        "program_name": target["program_name"],
        "domains": domains,
        "scope_exclusions": exclusions,
        "scope_info": scope_info,
        "result_counts": type_counts,
        "total_results": len(rows),
        "total_hosts": len(hosts),
        "hosts": hosts,
        "ungrouped": ungrouped,
        "scans": [dict(s) for s in scans],
        "passes": {
            str(k): {"name": v["name"], "description": v["description"]}
            for k, v in TRIAGE_PASSES.items()
        },
    })


@recon_bp.route("/api/recon/triage/<int:target_id>/pass/<int:pass_num>")
def get_triage_pass(target_id, pass_num):
    """Return formatted data for a specific triage analysis pass.

    Query params:
        max_lines: cap output at this many lines (default 2000, 0=unlimited)
        offset: skip this many results before building output (default 0)
    """
    if pass_num not in TRIAGE_PASSES:
        return jsonify({"error": f"invalid pass number, valid: {list(TRIAGE_PASSES.keys())}"}), 400

    max_lines = request.args.get("max_lines", 2000, type=int)
    offset = request.args.get("offset", 0, type=int)

    tpass = TRIAGE_PASSES[pass_num]
    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    domains = json.loads(target["domains"])
    exclusions = json.loads(target["scope_exclusions"]) if target["scope_exclusions"] else []
    scope_note = f"Domains: {', '.join(domains)}"
    if exclusions:
        scope_note += f"\nExclusions (out-of-scope keywords): {', '.join(exclusions)}"

    # Fetch program scope details for context
    program = conn.execute(
        "SELECT * FROM programs WHERE handle = ?", (target["program_handle"],)
    ).fetchone()
    if program:
        scope_rows = conn.execute("""
            SELECT asset_type, asset_identifier, max_severity, instruction
            FROM scopes WHERE program_id = ? AND eligible_for_bounty = 1
        """, (program["id"],)).fetchall()
        scope_lines = []
        for s in scope_rows:
            line = f"  {s['asset_type']}: {s['asset_identifier']} (max: {s['max_severity'] or 'N/A'})"
            if s["instruction"]:
                line += f" — {s['instruction'][:100]}"
            scope_lines.append(line)
        if scope_lines:
            scope_note += "\nIn-scope assets:\n" + "\n".join(scope_lines)

    # Auth-status badge: tells the triager whether we have a captured session
    # for this program. Pipeline tools (xhr-capture) auto-attach when set,
    # but Pass 1-3 prompts should also explicitly call out the "test as
    # authenticated user" attack paths when auth is available.
    try:
        from app import credential_store
        creds = credential_store.list_all(status='active')
        program_creds = [c for c in creds if c["program_handle"] == target["program_handle"]]
        if program_creds:
            cred_lines = []
            for c in program_creds:
                line = f"  ✓ {c['auth_type']}"
                if c.get("account_email"):
                    line += f" ({c['account_email']})"
                if c.get("tier"):
                    line += f" [{c['tier']}]"
                line += f" — captured {c['captured_at'][:10]}"
                if c.get("last_validated_at"):
                    line += f", validated {c['last_validated_at'][:10]}"
                else:
                    line += ", never validated (re-probe via /credentials)"
                cred_lines.append(line)
            scope_note += (
                "\n\nAUTH STATUS: ✓ Authenticated session(s) available for this program.\n"
                + "\n".join(cred_lines)
                + "\n→ Run authenticated probes per [[authorization-bypass]] and "
                "[[idor]] (two-account testing). Don't waste time on unauth-only "
                "attack paths when this gives you access to the full attack surface."
            )
        else:
            scope_note += (
                "\n\nAUTH STATUS: ✗ No captured session for this program. "
                "Recon is unauth-only.\n"
                "→ If the program allows self-signup, capture a session via "
                "scripts/capture_session.py (see /credentials page for the workflow)."
            )
    except Exception:
        # credential_store unavailable (pyrage not installed yet) — omit badge
        pass

    # SPA-catchall warning: if Phase 2's spa-catchall-detect flagged any
    # hosts, surface them at the top of every pass so the triager knows to
    # discount endpoint/url rows from those hosts.  See
    # feedback_spa_catchall_endpoint_trap.md.
    catchall_rows = conn.execute("""
        SELECT r.value, r.metadata FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type = 'spa_catchall'
        ORDER BY r.id
    """, (target_id,)).fetchall()
    if catchall_rows:
        catchall_lines = [f"  ✗ {row['value']}" for row in catchall_rows[:50]]
        if len(catchall_rows) > 50:
            catchall_lines.append(f"  ... ({len(catchall_rows) - 50} more)")
        scope_note += (
            "\n\nSPA-CATCHALL HOSTS (endpoint rows from these are FRONTEND ROUTING CONSTANTS, "
            f"NOT server URLs — discount them):\n" + "\n".join(catchall_lines)
            + "\n→ JS-extracted endpoints (`linkfinder`, `getallurls`, `katana`, "
            "`gospider`) on these hosts are React Router / Vue Router constants the "
            "server doesn't actually serve.  Real API surface lives on different "
            "hostnames — surface them via `xhr-capture` with auth.  Do NOT chase "
            "`/admin/*` / `/api/v1/*` / `/v1/accounts:*` on a catch-all host."
        )

    if pass_num == 4:
        # Gap analysis — uses scan metadata, always small
        data = _build_gap_analysis_data(conn, target_id, target)
    else:
        data = _build_pass_data(conn, target_id, target, tpass["focus_types"], pass_num,
                                max_lines=max_lines, offset=offset)

    lines = data.split("\n")
    total_lines = len(lines)
    truncated = False

    if max_lines and total_lines > max_lines:
        lines = lines[:max_lines]
        truncated = True
        lines.append(f"\n... TRUNCATED ({total_lines - max_lines} lines remaining, use ?offset={offset + max_lines} to continue)")
        data = "\n".join(lines)

    count = len(lines)
    conn.close()

    prompt = tpass["prompt"].format(
        program=target["program_handle"],
        domains=", ".join(domains),
        scope_note=scope_note,
        count=count,
        data=data,
    )

    return jsonify({
        "pass": pass_num,
        "name": tpass["name"],
        "description": tpass["description"],
        "prompt": prompt,
        "data_lines": count,
        "total_lines": total_lines,
        "truncated": truncated,
        "offset": offset,
        "max_lines": max_lines,
    })


def _build_pass_data(conn, target_id, target, focus_types, pass_num,
                     max_lines=2000, offset=0):
    """Build formatted data string for passes 1-3."""
    if pass_num == 2:
        # Attack surface correlation: group by host
        return _build_host_grouped_data(conn, target_id, offset=offset)

    # Passes 1 and 3: flat list filtered by focus types
    type_placeholders = ",".join("?" for _ in focus_types)
    limit_clause = f"LIMIT {max_lines + offset}" if max_lines else ""
    rows = conn.execute(f"""
        SELECT r.result_type, r.value, r.metadata, s.tool
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ({type_placeholders})
        ORDER BY r.result_type, r.id
        {limit_clause}
    """, [target_id] + list(focus_types)).fetchall()

    if offset:
        rows = rows[offset:]

    if not rows:
        return "(no results of these types found)\n"

    lines = []
    current_type = None
    for r in rows:
        if r["result_type"] != current_type:
            current_type = r["result_type"]
            lines.append(f"\n## {current_type.upper()} ({r['tool']})")
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        # Compact single-line representation
        meta_str = ""
        if meta:
            # Pick the most useful fields depending on type
            interesting = {k: v for k, v in meta.items() if v and k not in ("raw",)}
            if interesting:
                meta_str = " | " + json.dumps(interesting, separators=(",", ":"))
        lines.append(f"  {r['value']}{meta_str}")

    return "\n".join(lines) + "\n"


def _build_host_grouped_data(conn, target_id, offset=0):
    """Build per-host grouped data for Pass 2 (attack surface correlation)."""
    # Types relevant for host correlation
    host_types = ("live_host", "open_port", "cms_finding", "exposed_panel",
                  "directory", "vulnerability", "takeover", "secret",
                  "xhr_endpoint")
    type_placeholders = ",".join("?" for _ in host_types)

    rows = conn.execute(f"""
        SELECT r.result_type, r.value, r.metadata, s.tool
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ({type_placeholders})
        ORDER BY r.id
    """, [target_id] + list(host_types)).fetchall()

    if not rows:
        return "(no host-level results found)\n"

    # Group by extracted hostname
    hosts = {}
    for r in rows:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        host = _extract_host(r["value"], meta)
        if not host:
            host = "(unknown)"
        if host not in hosts:
            hosts[host] = []
        hosts[host].append({
            "type": r["result_type"],
            "tool": r["tool"],
            "value": r["value"],
            "meta": meta,
        })

    # Sort hosts by number of findings (most interesting first)
    sorted_hosts = sorted(hosts.items(), key=lambda x: len(x[1]), reverse=True)

    # Apply offset (skip N hosts for pagination)
    if offset:
        sorted_hosts = sorted_hosts[offset:]

    lines = []
    for hostname, results in sorted_hosts:
        # Summarize what we know about this host
        types_present = set(r["type"] for r in results)
        lines.append(f"\n### {hostname} ({len(results)} findings: {', '.join(sorted(types_present))})")

        # Group results by type within host
        by_type = {}
        for r in results:
            if r["type"] not in by_type:
                by_type[r["type"]] = []
            by_type[r["type"]].append(r)

        for rtype in ("live_host", "open_port", "cms_finding", "exposed_panel",
                       "directory", "vulnerability", "takeover", "secret",
                       "xhr_endpoint"):
            if rtype not in by_type:
                continue
            lines.append(f"  [{rtype}]")
            for r in by_type[rtype]:
                meta_str = ""
                if r["meta"]:
                    interesting = {k: v for k, v in r["meta"].items() if v and k not in ("raw",)}
                    if interesting:
                        meta_str = " " + json.dumps(interesting, separators=(",", ":"))
                lines.append(f"    {r['value']}{meta_str}")

    return "\n".join(lines) + "\n"


def _build_gap_analysis_data(conn, target_id, target):
    """Build gap analysis data for Pass 4."""
    # Get all scans and their status
    scans = conn.execute("""
        SELECT tool, status, result_count, error, started_at, finished_at
        FROM recon_scans WHERE target_id = ?
        ORDER BY created_at
    """, (target_id,)).fetchall()

    # Get result counts by type
    type_counts = conn.execute("""
        SELECT r.result_type, COUNT(*) as cnt
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ?
        GROUP BY r.result_type
    """, (target_id,)).fetchall()

    # Get subdomains vs probed hosts
    sub_count = conn.execute("""
        SELECT COUNT(DISTINCT r.value) FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type = 'subdomain'
    """, (target_id,)).fetchone()[0]

    live_count = conn.execute("""
        SELECT COUNT(DISTINCT r.value) FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type = 'live_host'
    """, (target_id,)).fetchone()[0]

    # Get live hosts that have NO associated vulnerability/directory/endpoint results
    # by comparing host sets
    live_hosts = conn.execute("""
        SELECT DISTINCT r.value FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type = 'live_host'
    """, (target_id,)).fetchall()

    scanned_hosts = conn.execute("""
        SELECT DISTINCT r.value FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ? AND r.result_type IN ('vulnerability', 'directory', 'endpoint', 'secret')
    """, (target_id,)).fetchall()

    live_set = set()
    for row in live_hosts:
        h = _extract_host(row["value"], {})
        if h:
            live_set.add(h)
    scanned_set = set()
    for row in scanned_hosts:
        h = _extract_host(row["value"], {})
        if h:
            scanned_set.add(h)

    unscanned = sorted(live_set - scanned_set)

    lines = []
    lines.append("## Pipeline Scan Results")
    lines.append(f"  Subdomains discovered: {sub_count}")
    lines.append(f"  Live hosts (httpx): {live_count}")
    lines.append(f"  Hosts with scan results (nuclei/ffuf/etc): {len(scanned_set)}")
    lines.append(f"  Live hosts with NO scan results: {len(unscanned)}")

    lines.append("\n## Tool Execution Summary")
    for s in scans:
        status_icon = "OK" if s["status"] == "completed" else s["status"].upper()
        count_str = f"{s['result_count']} results" if s["result_count"] else "0 results"
        err = f" — ERROR: {s['error'][:100]}" if s["error"] else ""
        lines.append(f"  [{status_icon}] {s['tool']}: {count_str}{err}")

    # Check which expected tools never ran
    ran_tools = set(s["tool"] for s in scans)
    all_expected = set()
    for phase_tools in PIPELINE_PHASES.values():
        all_expected.update(phase_tools)
    never_ran = sorted(all_expected - ran_tools)
    if never_ran:
        lines.append(f"\n## Tools That Never Ran: {', '.join(never_ran)}")

    lines.append("\n## Result Counts by Type")
    for tc in type_counts:
        lines.append(f"  {tc['result_type']}: {tc['cnt']}")

    if unscanned:
        lines.append(f"\n## Unscanned Live Hosts ({len(unscanned)} hosts)")
        lines.append("  These hosts responded to httpx but have no vulnerability/directory/secret scan results:")
        for h in unscanned[:100]:  # cap at 100
            lines.append(f"  - {h}")
        if len(unscanned) > 100:
            lines.append(f"  ... and {len(unscanned) - 100} more")

    # Include tech stacks of unscanned hosts for prioritization
    if unscanned:
        tech_rows = conn.execute("""
            SELECT r.value, r.metadata FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ? AND r.result_type = 'live_host'
        """, (target_id,)).fetchall()
        interesting_unscanned = []
        for row in tech_rows:
            host = _extract_host(row["value"], json.loads(row["metadata"]) if row["metadata"] else {})
            if host in unscanned:
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
                tech = meta.get("tech", [])
                title = meta.get("title", "")
                status = meta.get("status_code", meta.get("status", ""))
                if tech or title:
                    interesting_unscanned.append(f"  {host}: status={status} title=\"{title}\" tech={tech}")
        if interesting_unscanned:
            lines.append(f"\n## Unscanned Hosts — Tech Details (for prioritization)")
            lines.extend(interesting_unscanned[:50])

    return "\n".join(lines) + "\n"


@recon_bp.route("/recon/targets/<int:target_id>/triage")
def triage_page(target_id):
    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return "Target not found", 404

    domains = json.loads(target["domains"])

    # Get result counts for display
    type_counts = conn.execute("""
        SELECT r.result_type, COUNT(*) as cnt
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.target_id = ?
        GROUP BY r.result_type
        ORDER BY cnt DESC
    """, (target_id,)).fetchall()

    total_results = sum(tc["cnt"] for tc in type_counts)
    conn.close()

    return render_template("triage.html",
        target=target, domains=domains,
        type_counts=type_counts, total_results=total_results,
        passes=TRIAGE_PASSES)


# --- Pipeline Engine ---

# Phase definitions: phase number → list of tools in that phase
# Tools with a tuple (tool, dep) mean tool depends on dep finishing first within the same phase
PIPELINE_PHASES = {
    # amass disabled 2026-05-15: v5.0.0 has an internal bug where the engine
    # drops Location/Phone/Person events ("no handlers registered for the
    # EventType"), causing enumeration to stall at 0 p/s.  0/30 runs ever
    # produced results; every attempt got killed at the 45-min stale-scan
    # timeout, costing ~45 min per pipeline.  subfinder (which itself
    # queries 30+ data sources), crt-sh, and dnsgen+shuffledns together
    # cover the passive enumeration role amass used to fill.  Re-enable
    # only if amass v5.1+ resolves the issue.
    1: ["subfinder", "crt-sh", "gitleaks", "trufflehog", "dnsgen", "shuffledns", "dnsx", "merge-subs"],
    2: ["httpx-toolkit", "naabu", "subzy", "s3-takeover", "nuclei-takeover", "eyewitness", "xhr-capture", "spa-catchall-detect"],
    3: ["katana", "getallurls", "gospider", "paramspider", "nuclei", "merge-urls", "cloud-buckets", "nmap", "kiterunner", "feroxbuster"],
    4: ["linkfinder", "secret-scan", "arjun", "cms-detect", "git-dumper", "corscanner", "nextjs-check", "nomore403"],
    5: ["panel-detect", "wpscan", "joomscan", "sqlmap", "commix", "hydra"],
}

# Intra-phase dependencies: tools that must wait for another tool in the same phase.
# Value can be a single tool name (string) or a list of tool names (all must complete).
INTRA_PHASE_DEPS = {
    "dnsgen": "subfinder",
    "shuffledns": "dnsgen",
    "dnsx": "shuffledns",
    "merge-subs": "dnsx",
    "nuclei-takeover": "httpx-toolkit",
    "eyewitness": "httpx-toolkit",
    "xhr-capture": "httpx-toolkit",
    "spa-catchall-detect": "httpx-toolkit",
    "merge-urls": ["getallurls", "katana", "gospider"],
    "cloud-buckets": "merge-urls",
}

def _get_deps(tool, pipeline_type="web"):
    """Return intra-phase deps as a list (normalizes string → [string]).

    Pipeline-type aware: looks up the correct INTRA_PHASE_DEPS dict based on
    whether the caller is orchestrating a web or oracle pipeline.
    """
    deps_dict = _intra_deps_for(pipeline_type)
    dep = deps_dict.get(tool)
    if dep is None:
        return []
    return dep if isinstance(dep, list) else [dep]

PHASE_NAMES = {
    1: "Discovery",
    2: "Probing",
    3: "Crawling & Scanning",
    4: "Analysis",
    5: "Exploitation",
}

# ============================================================
# Oracle Pipeline (cryptographic oracle candidate detection)
# ============================================================
#
# This pipeline is a separate workflow from the web pipeline above. It targets
# programs for cryptographic oracle vulnerabilities (Bleichenbacher, Vaudenay,
# Manger, ROBOT, XML-Enc, JWT/JWE, ROCA, BREACH, etc.). See
# 03-Techniques/oracle-target-recon.md in the Obsidian vault for the full
# design.
#
# Phase 1 (Discovery): subfinder → merge-subs → httpx-toolkit. Minimal
#   subdomain enum + live host probing — just enough to give the oracle tools
#   a set of hosts to examine. No amass, no brute forcing, no crawling.
# Phase 2 (TLS/Cert harvesting): sslscan, sslyze run against httpx hosts;
#   roca-scan runs offline over captured certs.
# Phase 3 (Web surface fingerprinting): saml-fingerprint, jwt-jwe-harvest,
#   cookie-harvest probe known auth/SAML paths and collect tokens.
# Phase 4 (Passive candidate detection): breach-candidate analyses compressed
#   responses for reflected-content + secret-token combinations.
# Phase 5 (Active oracle probes): tls-oracle-probe (ROBOT), xmlenc-oracle-probe
#   (XML-Enc Bleichenbacher). These are the "confirmation" tools — they
#   actively probe endpoints flagged by earlier phases.
#
# All oracle tools that do HTTP are built-in Python (stdlib-only), living as
# methods in recon_agent.py alongside existing built-ins like crt-sh and
# merge-subs.
ORACLE_PIPELINE_PHASES = {
    1: ["subfinder", "merge-subs", "httpx-toolkit"],
    2: ["sslscan", "sslyze", "roca-scan", "ssh-terrapin-scan", "gcm-nonce-scan"],
    3: ["saml-fingerprint", "jwt-jwe-harvest", "cookie-harvest",
        "viewstate-fingerprint"],
    4: ["breach-candidate"],
    5: ["tls-oracle-probe", "xmlenc-oracle-probe", "cbc-padding-probe",
        "marvin-probe", "xsw-probe", "jwe-invalid-curve-probe",
        "manger-oaep-probe", "raccoon-probe"],
}

ORACLE_INTRA_PHASE_DEPS = {
    # Phase 1: minimal discovery chain
    "merge-subs": "subfinder",
    "httpx-toolkit": "merge-subs",
    # Phase 2: roca-scan runs after sslscan/sslyze have captured certs
    "roca-scan": ["sslscan", "sslyze"],
    # Phase 5: probes depend on detection tools from phase 2 and 3
    # (handled via cross-phase TOOL_DEPS below, not intra-phase)
}

# Cross-phase input dependencies for oracle pipeline tools. Same structure as
# TOOL_DEPS but scoped to the oracle workflow. Every tool's input comes from
# the closest completed ancestor.
ORACLE_TOOL_DEPS = {
    "merge-subs": ("subfinder", "no completed subfinder scan found"),
    "httpx-toolkit": ("merge-subs", "no completed merge-subs scan found"),
    "sslscan": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "sslyze": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "roca-scan": ("sslyze", "no completed sslyze scan found"),
    "ssh-terrapin-scan": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "gcm-nonce-scan": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "saml-fingerprint": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "jwt-jwe-harvest": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "cookie-harvest": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "viewstate-fingerprint": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "breach-candidate": ("httpx-toolkit", "no completed httpx-toolkit scan found"),
    "tls-oracle-probe": ("sslscan", "no completed sslscan scan found"),
    "xmlenc-oracle-probe": ("saml-fingerprint", "no completed saml-fingerprint scan found"),
    # Extended phase 5 probes
    "cbc-padding-probe": ("cookie-harvest", "no completed cookie-harvest scan found"),
    "marvin-probe": ("sslscan", "no completed sslscan scan found"),
    "xsw-probe": ("saml-fingerprint", "no completed saml-fingerprint scan found"),
    "jwe-invalid-curve-probe": ("jwt-jwe-harvest", "no completed jwt-jwe-harvest scan found"),
    "manger-oaep-probe": ("jwt-jwe-harvest", "no completed jwt-jwe-harvest scan found"),
    "raccoon-probe": ("sslscan", "no completed sslscan scan found"),
}

ORACLE_PHASE_NAMES = {
    1: "Discovery",
    2: "TLS & Cert Harvesting",
    3: "Web Surface Fingerprinting",
    4: "Passive Candidate Detection",
    5: "Active Oracle Probes",
}

# Built-in oracle tools (stdlib Python, live in recon_agent.py)
ORACLE_BUILTIN_TOOLS = {
    "saml-fingerprint", "jwt-jwe-harvest", "cookie-harvest",
    "roca-scan", "breach-candidate", "tls-oracle-probe",
    "xmlenc-oracle-probe",
    # Extended oracle built-ins
    "cbc-padding-probe", "marvin-probe", "xsw-probe",
    "viewstate-fingerprint", "jwe-invalid-curve-probe",
    "manger-oaep-probe", "ssh-terrapin-scan",
    "gcm-nonce-scan", "raccoon-probe",
}


def _phases_for(pipeline_type):
    """Return the PIPELINE_PHASES dict appropriate for the pipeline_type."""
    if pipeline_type == "oracle":
        return ORACLE_PIPELINE_PHASES
    return PIPELINE_PHASES


def _intra_deps_for(pipeline_type):
    """Return the INTRA_PHASE_DEPS dict appropriate for the pipeline_type."""
    if pipeline_type == "oracle":
        return ORACLE_INTRA_PHASE_DEPS
    return INTRA_PHASE_DEPS


def _tool_deps_for(pipeline_type):
    """Return the TOOL_DEPS dict appropriate for the pipeline_type."""
    if pipeline_type == "oracle":
        return ORACLE_TOOL_DEPS
    return TOOL_DEPS


def _phase_names_for(pipeline_type):
    """Return the PHASE_NAMES dict appropriate for the pipeline_type."""
    if pipeline_type == "oracle":
        return ORACLE_PHASE_NAMES
    return PHASE_NAMES


def _max_phase_for(pipeline_type):
    """Return the highest phase number for the given pipeline_type."""
    phases = _phases_for(pipeline_type)
    return max(phases.keys()) if phases else 0


def _builtin_tools_for(pipeline_type):
    """Return the set of built-in tools for a given pipeline_type."""
    if pipeline_type == "oracle":
        return BUILTIN_TOOLS | ORACLE_BUILTIN_TOOLS
    return BUILTIN_TOOLS


def _pipeline_type(pipeline_row):
    """Extract pipeline_type from a pipeline_runs row, defaulting to 'web'."""
    if pipeline_row is None:
        return "web"
    try:
        keys = pipeline_row.keys()
        if "pipeline_type" in keys:
            return pipeline_row["pipeline_type"] or "web"
    except Exception:
        pass
    return "web"


@recon_bp.route("/recon/targets/<int:target_id>/pipeline")
def pipeline_view(target_id):
    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return "Target not found", 404

    # Get or show latest pipeline run
    pipeline = conn.execute("""
        SELECT * FROM pipeline_runs WHERE target_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, (target_id,)).fetchone()

    # If the latest pipeline for this target is an oracle pipeline, redirect to
    # the oracle dashboard — this viewer renders against PIPELINE_PHASES (web)
    # which would show all the wrong tools for an oracle run.
    if pipeline and _pipeline_type(pipeline) == "oracle":
        conn.close()
        return redirect(f"/oracle-pipeline/{pipeline['id']}")

    domains = json.loads(target["domains"])

    # Get all scans for this pipeline run (latest per tool per phase)
    scans = []
    if pipeline:
        _recover_stale_pipeline_scans(conn, pipeline["id"], target["program_handle"])
        scans = conn.execute("""
            SELECT s.* FROM recon_scans s
            INNER JOIN (
                SELECT tool, pipeline_phase, MAX(id) as max_id
                FROM recon_scans
                WHERE pipeline_run_id = ?
                GROUP BY tool, pipeline_phase
            ) latest ON s.id = latest.max_id
            ORDER BY s.pipeline_phase, s.created_at
        """, (pipeline["id"],)).fetchall()

    # Get available tools from agent
    tools_resp, _ = _agent("get", "/tools")
    available_tools = {k: v.get("available", False) for k, v in tools_resp.items()} if isinstance(tools_resp, dict) and "error" not in tools_resp else {}

    # Get result counts
    result_counts = {}
    if pipeline:
        rows = conn.execute("""
            SELECT r.result_type, COUNT(*) as cnt
            FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.pipeline_run_id = ?
            GROUP BY r.result_type
        """, (pipeline["id"],)).fetchall()
        result_counts = {r["result_type"]: r["cnt"] for r in rows}

    # Recompute effective phase status from actual scan data
    scans_dicts = [dict(s) for s in scans]
    if pipeline:
        effective_status = _effective_phase_status(pipeline, scans_dicts)
        pipeline = dict(pipeline)
        pipeline["phase_status"] = effective_status

    conn.close()
    return render_template("pipeline.html",
        target=target, domains=domains, pipeline=pipeline,
        scans=scans_dicts, phase_names=PHASE_NAMES,
        pipeline_phases=PIPELINE_PHASES, available_tools=available_tools,
        result_counts=result_counts)


def _allocate_egress_netns(conn, pipeline_id):
    """Call /netns/allocate and store the assigned slot on the pipeline row.

    Returns (netns_slot, error_msg). On error, the pipeline row is left with
    egress_netns=NULL — caller should consider rolling back / marking failed.
    """
    alloc_resp, alloc_status = _agent("post", "/netns/allocate",
                                       json={"pipeline_id": pipeline_id})
    if alloc_status != 200:
        return None, f"agent /netns/allocate returned {alloc_status}: {alloc_resp}"
    slot = alloc_resp.get("netns")
    if not slot:
        return None, "agent /netns/allocate returned no netns: %r" % alloc_resp
    conn.execute("UPDATE pipeline_runs SET egress_netns = ? WHERE id = ?",
                 (slot, pipeline_id))
    conn.commit()
    return slot, None


def _release_egress_netns(pipeline_id):
    """Best-effort release of a pipeline's netns claim. Idempotent — safe even
    if the pipeline never had a claim (agent returns released=null in that case).
    """
    try:
        _agent("post", "/netns/release", json={"pipeline_id": pipeline_id})
    except Exception:
        pass  # release is best-effort; the reaper will free stale claims


@recon_bp.route("/api/recon/pipeline/start", methods=["POST"])
def pipeline_start():
    data = request.get_json()
    target_id = data.get("target_id")
    rescan_incremental = data.get("rescan_incremental", False)

    if not target_id:
        return jsonify({"error": "target_id required"}), 400

    conn = get_connection()
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    # Check for already-running pipeline (per-target).
    existing = conn.execute("""
        SELECT * FROM pipeline_runs WHERE target_id = ? AND phase_status IN ('running', 'awaiting_approval')
        ORDER BY created_at DESC LIMIT 1
    """, (target_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "pipeline already active", "pipeline_id": existing["id"]}), 409

    # Multi-egress slot allocation: each pipeline runs through a dedicated
    # WireGuard netns (scan1..scan4) backed by its own Hetzner egress node.
    # Up to 4 pipelines can run concurrently, each with its own conntrack table.
    #
    # Probe pool capacity FIRST (cheap; doesn't claim).  If pool is full, refuse
    # the pipeline_runs INSERT entirely so we don't create a row we can't run.
    # After INSERT we'll re-call /netns/allocate with the real pipeline_id.
    status_resp, status_code = _agent("get", "/netns/status")
    if status_code == 200:
        pool = status_resp.get("pool", {})
        free_slots = [s for s, info in pool.items()
                      if info.get("claimed_by") is None and info.get("online")]
        if not free_slots:
            claims = {s: info.get("claimed_by") for s, info in pool.items()}
            conn.close()
            return jsonify({
                "error": "no egress slot available (4 pipelines already running)",
                "current_claims": claims,
            }), 409
    # If /netns/status fails (agent unreachable), proceed anyway — the actual
    # allocate call below will fail loudly and we'll roll back the INSERT.

    # Incremental rescan: skip Phase 1 if previous httpx data exists on disk
    skipped_phase1 = False
    if rescan_incremental:
        prev_httpx = conn.execute("""
            SELECT s.output_file, s.result_count FROM recon_scans s
            JOIN pipeline_runs p ON s.pipeline_id = p.id
            WHERE p.target_id = ? AND s.tool = 'httpx-toolkit'
            AND s.status = 'completed' AND s.result_count > 50
            ORDER BY s.finished_at DESC LIMIT 1
        """, (target_id,)).fetchone()
        if prev_httpx and prev_httpx["output_file"]:
            # Verify the file still exists on the agent
            files_resp, _ = _agent("get", f"/files/{target['program_handle']}")
            file_exists = any(f["name"] == prev_httpx["output_file"]
                             for f in files_resp.get("files", []))
            if file_exists:
                skipped_phase1 = True

    if skipped_phase1:
        # Start at Phase 2, mark Phase 1 as reused
        auto_approve = 1
        conn.execute("""
            INSERT INTO pipeline_runs (target_id, current_phase, phase_status, config, auto_approve)
            VALUES (?, 2, 'running', '{}', ?)
        """, (target_id, auto_approve))
        conn.commit()
        pipeline_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Allocate egress netns now that we have the real pipeline_id
        netns_slot, alloc_err = _allocate_egress_netns(conn, pipeline_id)
        if alloc_err:
            conn.execute("UPDATE pipeline_runs SET phase_status = 'failed' WHERE id = ?",
                         (pipeline_id,))
            conn.commit()
            conn.close()
            return jsonify({"error": "egress allocation failed: " + alloc_err,
                            "pipeline_id": pipeline_id}), 503

        # Record Phase 1 tools as completed (reused from previous scan)
        phase1_tools = PIPELINE_PHASES.get(1, [])
        for tool_name in phase1_tools:
            conn.execute("""
                INSERT INTO recon_scans (target_id, tool, status, pipeline_run_id, pipeline_phase,
                result_count, error, started_at, finished_at)
                VALUES (?, ?, 'completed', ?, 1, 0, 'reused from previous scan (incremental rescan)',
                datetime('now'), datetime('now'))
            """, (target_id, tool_name, pipeline_id))
        # Also record httpx as reused with its previous result count
        conn.execute("""
            INSERT INTO recon_scans (target_id, tool, status, pipeline_run_id, pipeline_phase,
            result_count, error, output_file, started_at, finished_at)
            VALUES (?, 'httpx-toolkit', 'completed', ?, 1, ?,
            'reused from previous scan (incremental rescan)', ?, datetime('now'), datetime('now'))
        """, (target_id, pipeline_id, prev_httpx["result_count"], prev_httpx["output_file"]))
        conn.commit()

        # Launch Phase 2 tools
        errors = _launch_phase_tools(conn, pipeline_id, target, 2)
        conn.close()
        return jsonify({"pipeline_id": pipeline_id, "phase": 2,
                        "skipped_phase1": True, "errors": errors,
                        "egress_netns": netns_slot}), 201

    # Normal start: Phase 1
    auto_approve = 1
    conn.execute("""
        INSERT INTO pipeline_runs (target_id, current_phase, phase_status, config, auto_approve)
        VALUES (?, 1, 'running', '{}', ?)
    """, (target_id, auto_approve))
    conn.commit()
    pipeline_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Allocate egress netns now that we have the real pipeline_id
    netns_slot, alloc_err = _allocate_egress_netns(conn, pipeline_id)
    if alloc_err:
        conn.execute("UPDATE pipeline_runs SET phase_status = 'failed' WHERE id = ?",
                     (pipeline_id,))
        conn.commit()
        conn.close()
        return jsonify({"error": "egress allocation failed: " + alloc_err,
                        "pipeline_id": pipeline_id}), 503

    # Launch Phase 1 tools
    errors = _launch_phase_tools(conn, pipeline_id, target, 1)
    conn.close()

    return jsonify({"pipeline_id": pipeline_id, "phase": 1,
                    "skipped_phase1": False, "errors": errors,
                    "egress_netns": netns_slot}), 201


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/status")
def pipeline_status(pipeline_id):
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (pipeline["target_id"],)).fetchone()

    # Check if current phase is done
    _check_phase_completion(conn, pipeline_id, target["program_handle"])

    # Re-fetch after potential update
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()

    scans = conn.execute("""
        SELECT s.id, s.tool, s.status, s.result_count, s.pipeline_phase,
               s.error, s.started_at, s.finished_at
        FROM recon_scans s
        INNER JOIN (
            SELECT tool, pipeline_phase, MAX(id) as max_id
            FROM recon_scans
            WHERE pipeline_run_id = ?
            GROUP BY tool, pipeline_phase
        ) latest ON s.id = latest.max_id
        ORDER BY s.pipeline_phase, s.created_at
    """, (pipeline_id,)).fetchall()

    # Group scans by phase
    phases = {}
    for s in scans:
        phase = s["pipeline_phase"] or 0
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(dict(s))

    auto_approve = pipeline["auto_approve"] if "auto_approve" in pipeline.keys() else 1
    # Recompute effective status from actual scan data
    all_scans_dicts = [dict(s) for s in scans]
    effective_status = _effective_phase_status(pipeline, all_scans_dicts)

    # Persist corrected status so DB matches reality
    if effective_status != pipeline["phase_status"]:
        conn.execute("""
            UPDATE pipeline_runs SET phase_status = ?, updated_at = datetime('now')
            WHERE id = ?
        """, (effective_status, pipeline_id))
        conn.commit()

    conn.close()
    return jsonify({
        "pipeline_id": pipeline_id,
        "current_phase": pipeline["current_phase"],
        "phase_status": effective_status,
        "phase_name": PHASE_NAMES.get(pipeline["current_phase"], "Unknown"),
        "auto_approve": bool(auto_approve),
        "phases": phases,
    })


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/approve", methods=["POST"])
def pipeline_approve(pipeline_id):
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    # Recompute effective status — manual reruns may have fixed a "failed" pipeline
    scans = conn.execute("""
        SELECT s.* FROM recon_scans s
        INNER JOIN (
            SELECT tool, pipeline_phase, MAX(id) as max_id
            FROM recon_scans WHERE pipeline_run_id = ?
            GROUP BY tool, pipeline_phase
        ) latest ON s.id = latest.max_id
    """, (pipeline_id,)).fetchall()
    effective_status = _effective_phase_status(pipeline, [dict(s) for s in scans])

    if effective_status != "awaiting_approval":
        conn.close()
        return jsonify({"error": f"pipeline is '{effective_status}', not awaiting approval"}), 400

    pipeline_type = _pipeline_type(pipeline)
    phases_dict = _phases_for(pipeline_type)
    phase_names_dict = _phase_names_for(pipeline_type)
    max_phase = _max_phase_for(pipeline_type)

    next_phase = pipeline["current_phase"] + 1
    if next_phase > max_phase:
        conn.execute("""
            UPDATE pipeline_runs SET phase_status = 'completed', updated_at = datetime('now')
            WHERE id = ?
        """, (pipeline_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "completed", "message": "all phases complete"})

    # Skip empty phases
    while next_phase <= max_phase and not phases_dict.get(next_phase):
        next_phase += 1

    if next_phase > max_phase:
        conn.execute("""
            UPDATE pipeline_runs SET phase_status = 'completed', current_phase = ?,
            updated_at = datetime('now') WHERE id = ?
        """, (max_phase, pipeline_id))
        conn.commit()
        conn.close()
        return jsonify({"status": "completed", "message": "all phases complete"})

    # Move to next phase
    conn.execute("""
        UPDATE pipeline_runs SET current_phase = ?, phase_status = 'running',
        updated_at = datetime('now') WHERE id = ?
    """, (next_phase, pipeline_id))
    conn.commit()

    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (pipeline["target_id"],)).fetchone()
    errors = _launch_phase_tools(conn, pipeline_id, target, next_phase)
    conn.close()

    return jsonify({
        "status": "running",
        "phase": next_phase,
        "phase_name": phase_names_dict.get(next_phase, "Unknown"),
        "errors": errors,
    })


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/auto-approve", methods=["POST"])
def pipeline_toggle_auto_approve(pipeline_id):
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    data = request.get_json() or {}
    auto_approve = 1 if data.get("auto_approve", True) else 0
    conn.execute("UPDATE pipeline_runs SET auto_approve = ? WHERE id = ?", (auto_approve, pipeline_id))
    conn.commit()

    # If turning on auto_approve and effectively awaiting_approval, immediately advance
    scans = conn.execute("""
        SELECT s.* FROM recon_scans s
        INNER JOIN (
            SELECT tool, pipeline_phase, MAX(id) as max_id
            FROM recon_scans WHERE pipeline_run_id = ?
            GROUP BY tool, pipeline_phase
        ) latest ON s.id = latest.max_id
    """, (pipeline_id,)).fetchall()
    effective_status = _effective_phase_status(pipeline, [dict(s) for s in scans])
    if auto_approve and effective_status == "awaiting_approval":
        # Trigger approval
        conn.close()
        return pipeline_approve(pipeline_id)

    conn.close()
    return jsonify({"auto_approve": bool(auto_approve)})


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/stop", methods=["POST"])
def pipeline_stop(pipeline_id):
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    # Kill all running scans in this pipeline
    running_scans = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ? AND status = 'running'
    """, (pipeline_id,)).fetchall()

    for scan in running_scans:
        if scan["pid"]:
            _agent("post", f"/scan/{scan['pid']}/kill")
        conn.execute("""
            UPDATE recon_scans SET status = 'failed', error = 'pipeline stopped',
            finished_at = datetime('now') WHERE id = ?
        """, (scan["id"],))

    # Mark pending/queued scans as skipped (they never ran)
    pending_scans = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ? AND status = 'pending'
    """, (pipeline_id,)).fetchall()
    for scan in pending_scans:
        conn.execute("""
            UPDATE recon_scans SET status = 'completed', result_count = 0,
            error = 'skipped: pipeline stopped before scan could start',
            finished_at = datetime('now') WHERE id = ?
        """, (scan["id"],))

    conn.execute("""
        UPDATE pipeline_runs SET phase_status = 'failed', updated_at = datetime('now')
        WHERE id = ?
    """, (pipeline_id,))
    conn.commit()
    conn.close()
    # Release the netns slot so the next pipeline can claim it
    _release_egress_netns(pipeline_id)
    return jsonify({"status": "stopped"})


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/delete", methods=["POST"])
def pipeline_delete(pipeline_id):
    """Delete a pipeline and all its associated scans.

    Kills any running scans first, then removes all DB records.
    The recon target is preserved so a new pipeline can be started.
    """
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    # Kill running scans — by PID and by any status (not just 'running',
    # since agent restart can leave processes alive with DB status 'failed')
    all_scans = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ?
        AND status IN ('running', 'failed', 'pending')
    """, (pipeline_id,)).fetchall()
    killed_pids = set()
    for scan in all_scans:
        if scan["pid"]:
            _agent("post", f"/scan/{scan['pid']}/kill")
            killed_pids.add(scan["pid"])

    # Also kill orphaned processes: ask agent to kill all scans for this target
    target = conn.execute("SELECT program_handle FROM recon_targets WHERE id = ?",
                          (pipeline["target_id"],)).fetchone()
    if target:
        _agent("post", "/scan/kill-target", json={"target_name": target["program_handle"]})

    # Delete results, scans, and the pipeline record (respecting FK order)
    scan_ids = [r["id"] for r in conn.execute(
        "SELECT id FROM recon_scans WHERE pipeline_run_id = ?", (pipeline_id,)
    ).fetchall()]
    scan_count = len(scan_ids)

    # Delete recon_results that reference these scans (FK constraint)
    for sid in scan_ids:
        conn.execute("DELETE FROM recon_results WHERE scan_id = ?", (sid,))

    conn.execute("DELETE FROM recon_scans WHERE pipeline_run_id = ?", (pipeline_id,))
    conn.execute("DELETE FROM pipeline_runs WHERE id = ?", (pipeline_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "pipeline_id": pipeline_id,
                     "scans_deleted": scan_count})


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/injectable", methods=["GET"])
def pipeline_injectable_tools(pipeline_id):
    """Return tools that haven't been run in this pipeline and could be injected.

    Useful for discovering new tools added after a pipeline already completed.
    """
    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    target_id = pipeline["target_id"]
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    target_name = target["program_handle"]

    # Get all tools already run in this pipeline
    existing_scans = conn.execute("""
        SELECT tool, status, error FROM recon_scans WHERE pipeline_run_id = ?
    """, (pipeline_id,)).fetchall()
    run_tools = {s["tool"] for s in existing_scans}

    # Pipeline-type aware dicts
    pipeline_type = _pipeline_type(pipeline)
    phases_dict = _phases_for(pipeline_type)
    deps_dict = _tool_deps_for(pipeline_type)
    builtin_tools = _builtin_tools_for(pipeline_type)

    # Check tool availability
    tools_resp, _ = _agent("get", "/tools")
    available = {}
    if isinstance(tools_resp, dict) and "error" not in tools_resp:
        available = {k: v.get("available", False) for k, v in tools_resp.items()}

    injectable = []
    for phase_num, phase_tools in sorted(phases_dict.items()):
        for tool in phase_tools:
            if tool in run_tools:
                continue
            # Check if input dependency can be resolved
            can_run = True
            reason = ""
            if tool in deps_dict:
                input_file = _resolve_input_file(conn, target_id, target_name, tool, pipeline_type)
                if input_file is None:
                    can_run = False
                    dep_tool, _ = deps_dict[tool]
                    reason = f"dependency {dep_tool} output not available"
            if not available.get(tool, False) and tool not in builtin_tools:
                can_run = False
                reason = "tool not installed"
            injectable.append({
                "tool": tool,
                "phase": phase_num,
                "can_run": can_run,
                "reason": reason,
                "available": available.get(tool, tool in ("merge-subs", "merge-urls", "crt-sh", "git-dumper")),
            })

    conn.close()
    return jsonify({"pipeline_id": pipeline_id, "injectable": injectable})


@recon_bp.route("/api/recon/pipeline/<int:pipeline_id>/inject", methods=["POST"])
def pipeline_inject_tools(pipeline_id):
    """Inject individual tools into an existing pipeline run.

    Launches the specified tools with proper pipeline_run_id and pipeline_phase
    so they appear in the pipeline viewer. Useful for retrying tools that were
    silently dropped or skipped.

    Body: {"tools": ["nuclei", "getallurls"]}
    """
    data = request.get_json()
    tools_to_inject = data.get("tools", [])

    if not tools_to_inject:
        return jsonify({"error": "tools list required"}), 400

    conn = get_connection()
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "pipeline not found"}), 404

    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                          (pipeline["target_id"],)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "target not found"}), 404

    target_id = target["id"]
    target_name = target["program_handle"]
    domains = json.loads(target["domains"])

    pipeline_type = _pipeline_type(pipeline)
    phases_dict = _phases_for(pipeline_type)
    builtin_tools = _builtin_tools_for(pipeline_type)

    # Validate all tools belong to a known phase
    tool_to_phase = {}
    for phase_num, phase_tools in phases_dict.items():
        for t in phase_tools:
            tool_to_phase[t] = phase_num

    invalid = [t for t in tools_to_inject if t not in tool_to_phase]
    if invalid:
        conn.close()
        return jsonify({"error": f"unknown tools: {invalid}"}), 400

    # Check which tools are available on the agent
    tools_resp, _ = _agent("get", "/tools")
    agent_reachable = isinstance(tools_resp, dict) and "error" not in tools_resp
    available = {}
    if agent_reachable:
        available = {k: v.get("available", False) for k, v in tools_resp.items()}

    launched = []
    errors = []

    for tool in tools_to_inject:
        phase = tool_to_phase[tool]

        # Delete old failed/skipped/pending records so the tool can be retried.
        # Without this, a 429 on inject leaves the old "failed" record as latest,
        # and _launch_phase_tools sees it as terminal and skips the tool.
        conn.execute("""
            DELETE FROM recon_scans
            WHERE pipeline_run_id = ? AND tool = ?
              AND status IN ('failed', 'pending')
              AND pipeline_phase = ?
        """, (pipeline_id, tool, phase))
        conn.execute("""
            DELETE FROM recon_scans
            WHERE pipeline_run_id = ? AND tool = ?
              AND status = 'completed' AND error LIKE 'skipped:%'
              AND pipeline_phase = ?
        """, (pipeline_id, tool, phase))

        # Check availability — if agent unreachable, only block external tools
        if not agent_reachable and tool not in builtin_tools:
            errors.append(f"{tool}: agent not reachable, try again later")
            continue
        if not available.get(tool, False) and tool not in builtin_tools:
            errors.append(f"{tool}: not installed on agent")
            continue

        # Build agent request — pipeline_id so the agent uses the right netns
        agent_data = {"tool": tool, "target_name": target_name,
                      "pipeline_id": pipeline_id}

        if tool in ("subfinder", "amass", "crt-sh"):
            agent_data["domains"] = domains
        elif tool == "gitleaks":
            agent_data["options"] = {"org": target_name}
        elif tool in ("merge-subs", "merge-urls"):
            pass
        else:
            input_file = _resolve_input_file(conn, target_id, target_name, tool, pipeline_type)
            if input_file is None:
                # For wpscan: if cms-detect completed but found no WordPress sites,
                # mark as cleanly skipped (not a failure — just no targets)
                if tool == "wpscan":
                    dep_scan = conn.execute("""
                        SELECT id FROM recon_scans
                        WHERE target_id = ? AND tool = 'cms-detect'
                          AND status = 'completed' AND (error IS NULL OR error = '')
                    """, (target_id,)).fetchone()
                    if dep_scan:
                        errors.append(f"{tool}: no wordpress targets detected, skipping")
                        conn.execute("""
                            INSERT INTO recon_scans
                            (target_id, tool, status, result_count, error, started_at, finished_at,
                             pipeline_run_id, pipeline_phase)
                            VALUES (?, ?, 'completed', 0, 'skipped: no wordpress targets detected',
                                    datetime('now'), datetime('now'), ?, ?)
                        """, (target_id, tool, pipeline_id, phase))
                        continue
                errors.append(f"{tool}: no input file available (dependency not met)")
                continue
            agent_data["input_file"] = input_file

        # Launch via agent
        try:
            agent_resp, status_code = _agent("post", "/scan/start", json=agent_data)
        except Exception as e:
            errors.append(f"{tool}: agent error: {e}")
            continue

        if status_code != 201:
            error_msg = agent_resp.get("error", "agent error")
            errors.append(f"{tool}: {error_msg}")
            if status_code in (429, 502, 504):
                # Record as 'pending' so _check_phase_completion retries later
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, error, started_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'pending', ?, datetime('now'), ?, ?)
                """, (target_id, tool, f"queued: {error_msg}", pipeline_id, phase))
                continue
            conn.execute("""
                INSERT INTO recon_scans
                (target_id, tool, status, result_count, error, started_at, finished_at,
                 pipeline_run_id, pipeline_phase)
                VALUES (?, ?, 'completed', 0, ?, datetime('now'), datetime('now'), ?, ?)
            """, (target_id, tool, f"skipped: {error_msg}", pipeline_id, phase))
            continue

        pid = agent_resp["pid"]
        output_file = agent_resp.get("output_file")
        json_output = agent_resp.get("json_output")

        conn.execute("""
            INSERT INTO recon_scans
            (target_id, tool, status, pid, output_file, json_output, started_at,
             pipeline_run_id, pipeline_phase)
            VALUES (?, ?, 'running', ?, ?, ?, datetime('now'), ?, ?)
        """, (target_id, tool, pid, output_file, json_output, pipeline_id, phase))

        launched.append({"tool": tool, "phase": phase, "pid": pid})

    # Set pipeline back to 'running' so the reconciler picks up the new scans.
    # We need to do this even when launched=[] because tools that hit the 429
    # concurrency cap are recorded as 'pending' for later retry — and the
    # reconciler only retries pending scans on pipelines in 'running' state.
    # Without this, injecting into a 'completed' pipeline when all scan slots
    # are full leaves the pending records orphaned forever.
    pending_phases = [row["pipeline_phase"] for row in conn.execute("""
        SELECT pipeline_phase FROM recon_scans
        WHERE pipeline_run_id = ? AND status = 'pending'
    """, (pipeline_id,)).fetchall()]
    all_active_phases = [t["phase"] for t in launched] + pending_phases
    if all_active_phases:
        earliest_phase = min(all_active_phases)
        conn.execute("""
            UPDATE pipeline_runs SET current_phase = ?, phase_status = 'running',
            updated_at = datetime('now') WHERE id = ?
        """, (earliest_phase, pipeline_id))

    conn.commit()
    conn.close()

    return jsonify({
        "launched": launched,
        "errors": errors,
        "pipeline_id": pipeline_id,
    }), 201 if (launched or all_active_phases) else 400


def _launch_phase_tools(conn, pipeline_id, target, phase):
    """Launch all tools for a given phase. Returns list of errors (if any).

    Skips unavailable tools and immediately triggers their intra-phase dependents.
    Pipeline-type aware: looks up the correct PIPELINE_PHASES + dependency dicts
    based on pipeline_runs.pipeline_type.
    """
    # Look up pipeline_type to select the right phase/dependency tables
    pipeline_row = conn.execute(
        "SELECT pipeline_type FROM pipeline_runs WHERE id = ?", (pipeline_id,)
    ).fetchone()
    pipeline_type = _pipeline_type(pipeline_row)

    # Concurrency gating now lives at the netns-pool layer (4 slots in
    # recon_agent.py NETNS_POOL). pipeline_start() refuses to INSERT a row
    # if no egress slot is available, so by the time we get here the pipeline
    # already has its own conntrack table + dedicated Hetzner egress IP.
    # The agent's MAX_CONCURRENT_HEAVY=2 still caps total heavy tools (amass,
    # eyewitness, feroxbuster, kiterunner, nuclei, gospider) across all
    # pipelines, so CPU/RAM pressure is bounded without serializing.
    # Oracle pipelines: never gated (oracle_autopilot caps at 3).

    phases_dict = _phases_for(pipeline_type)
    builtin_tools = _builtin_tools_for(pipeline_type)

    tools = phases_dict.get(phase, [])
    if not tools:
        return []

    target_id = target["id"]
    target_name = target["program_handle"]
    domains = json.loads(target["domains"])
    errors = []

    # Check which tools are available on the agent
    tools_resp, tools_status = _agent("get", "/tools")
    agent_reachable = isinstance(tools_resp, dict) and "error" not in tools_resp
    available = {}
    if agent_reachable:
        available = {k: v.get("available", False) for k, v in tools_resp.items()}

    # Track skipped tools so dependents can fire immediately
    skipped = set()

    for tool in tools:
      try:
        # Skip tools that already have a record for this pipeline (already launched or skipped)
        # Exception: 'pending' records are retryable (created on 429 concurrency limit)
        # Use the LATEST record (ORDER BY id DESC) — a tool may have an older "skipped"
        # record AND a newer "pending" record from an intra-phase dep retry.
        existing = conn.execute("""
            SELECT id, status FROM recon_scans WHERE pipeline_run_id = ? AND tool = ?
            ORDER BY id DESC LIMIT 1
        """, (pipeline_id, tool)).fetchone()
        was_pending = False
        if existing:
            if existing["status"] == "pending":
                # Delete the pending placeholder so we can re-attempt launch
                conn.execute("DELETE FROM recon_scans WHERE id = ?", (existing["id"],))
                was_pending = True
            else:
                continue

        # If agent is unreachable, preserve pending state so recovery retries later
        if not agent_reachable and tool not in builtin_tools:
            if was_pending:
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, error, started_at, pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'pending', 'queued: agent not reachable', datetime('now'), ?, ?)
                """, (target_id, tool, pipeline_id, phase))
            errors.append(f"{tool}: agent not reachable, will retry")
            continue

        # Skip tools that have intra-phase deps not yet completed (and not skipped)
        deps = _get_deps(tool, pipeline_type)
        if deps:
            all_deps_ready = True
            for dep in deps:
                if dep in skipped:
                    continue  # skipped deps count as ready
                dep_scan = conn.execute("""
                    SELECT * FROM recon_scans
                    WHERE pipeline_run_id = ? AND tool = ? AND status = 'completed'
                """, (pipeline_id, dep)).fetchone()
                if not dep_scan:
                    all_deps_ready = False
                    break
            if not all_deps_ready:
                continue  # will be launched when deps complete

        # Check availability — skip and mark if tool not installed
        if not available.get(tool, False) and tool not in builtin_tools:
            skipped.add(tool)
            errors.append(f"{tool}: not installed, skipping")
            # Record in DB so phase completion knows this tool was expected
            conn.execute("""
                INSERT INTO recon_scans
                (target_id, tool, status, result_count, error, started_at, finished_at,
                 pipeline_run_id, pipeline_phase)
                VALUES (?, ?, 'completed', 0, 'skipped: tool not installed', datetime('now'),
                        datetime('now'), ?, ?)
            """, (target_id, tool, pipeline_id, phase))
            continue

        # Build agent request — include pipeline_id so the agent wraps tool
        # spawns with `sudo ip netns exec scanN` for this pipeline's egress slot.
        agent_data = {"tool": tool, "target_name": target_name,
                      "pipeline_id": pipeline_id}

        # Pass cached wildcard_parents (detected at target creation) to DNS-brute
        # tools so they can skip parents that resolve every subdomain to the
        # same IP — saves egress bandwidth and resolver load.
        DNS_BRUTE_TOOLS = {"shuffledns", "dnsgen", "dnsx", "amass"}
        if tool in DNS_BRUTE_TOOLS:
            wc_raw = target["wildcard_parents"] if "wildcard_parents" in target.keys() else None
            if wc_raw:
                try:
                    wc_list = json.loads(wc_raw)
                    if wc_list:
                        agent_data.setdefault("options", {})["wildcard_parents"] = wc_list
                except (ValueError, TypeError):
                    pass

        if tool in ("subfinder", "amass", "crt-sh"):
            agent_data["domains"] = domains
        elif tool in ("gitleaks", "trufflehog"):
            # gitleaks/trufflehog need org name via options, uses target_name as fallback
            agent_data["options"] = {"org": target_name}
        elif tool in ("merge-subs", "merge-urls"):
            pass  # these scan the target dir, no input_file needed
        else:
            # Resolve input file from dependency
            input_file = _resolve_input_file(conn, target_id, target_name, tool, pipeline_type)
            if input_file is None:
                # For wpscan: if cms-detect ran but found no WordPress sites, clean skip
                if tool == "wpscan":
                    dep_scan = conn.execute("""
                        SELECT id FROM recon_scans
                        WHERE target_id = ? AND tool = 'cms-detect'
                          AND status = 'completed' AND (error IS NULL OR error = '')
                    """, (target_id,)).fetchone()
                    if dep_scan:
                        errors.append(f"{tool}: no wordpress targets detected, skipping")
                        skipped.add(tool)
                        conn.execute("""
                            INSERT INTO recon_scans
                            (target_id, tool, status, result_count, error, started_at, finished_at,
                             pipeline_run_id, pipeline_phase)
                            VALUES (?, ?, 'completed', 0, 'skipped: no wordpress targets detected',
                                    datetime('now'), datetime('now'), ?, ?)
                        """, (target_id, tool, pipeline_id, phase))
                        continue
                # For joomscan: if cms-detect ran but found no Joomla sites, clean skip
                if tool == "joomscan":
                    dep_scan = conn.execute("""
                        SELECT id FROM recon_scans
                        WHERE target_id = ? AND tool = 'cms-detect'
                          AND status = 'completed' AND (error IS NULL OR error = '')
                    """, (target_id,)).fetchone()
                    if dep_scan:
                        errors.append(f"{tool}: no joomla targets detected, skipping")
                        skipped.add(tool)
                        conn.execute("""
                            INSERT INTO recon_scans
                            (target_id, tool, status, result_count, error, started_at, finished_at,
                             pipeline_run_id, pipeline_phase)
                            VALUES (?, ?, 'completed', 0, 'skipped: no joomla targets detected',
                                    datetime('now'), datetime('now'), ?, ?)
                        """, (target_id, tool, pipeline_id, phase))
                        continue
                # For hydra: if panel-detect ran but found no login panels, clean skip
                if tool == "hydra":
                    dep_scan = conn.execute("""
                        SELECT id FROM recon_scans
                        WHERE target_id = ? AND tool = 'panel-detect'
                          AND status = 'completed' AND (error IS NULL OR error = '')
                    """, (target_id,)).fetchone()
                    if dep_scan:
                        errors.append(f"{tool}: no login panels detected, skipping")
                        skipped.add(tool)
                        conn.execute("""
                            INSERT INTO recon_scans
                            (target_id, tool, status, result_count, error, started_at, finished_at,
                             pipeline_run_id, pipeline_phase)
                            VALUES (?, ?, 'completed', 0, 'skipped: no login panels detected',
                                    datetime('now'), datetime('now'), ?, ?)
                        """, (target_id, tool, pipeline_id, phase))
                        continue
                errors.append(f"{tool}: no input file available (dependency not met)")
                skipped.add(tool)
                # Record skipped scan so it shows in UI
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, result_count, error, started_at, finished_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'completed', 0, 'skipped: no input from dependency', datetime('now'),
                            datetime('now'), ?, ?)
                """, (target_id, tool, pipeline_id, phase))
                continue
            agent_data["input_file"] = input_file

        # Call agent
        agent_resp, status_code = _agent("post", "/scan/start", json=agent_data)
        if status_code != 201:
            error_msg = agent_resp.get("error", "agent error")
            errors.append(f"{tool}: {error_msg}")
            if status_code in (429, 502, 504):
                # 429 = concurrency limit, 502/504 = agent down/restarting
                # Record as 'pending' so _check_phase_completion can retry later
                # (without a record, tools are silently lost and the phase stalls)
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, error, started_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'pending', ?, datetime('now'), ?, ?)
                """, (target_id, tool, f"queued: {error_msg}", pipeline_id, phase))
                continue
            # Permanent error (400, 404, etc.) — record as skipped
            conn.execute("""
                INSERT INTO recon_scans
                (target_id, tool, status, result_count, error, started_at, finished_at,
                 pipeline_run_id, pipeline_phase)
                VALUES (?, ?, 'completed', 0, ?, datetime('now'),
                        datetime('now'), ?, ?)
            """, (target_id, tool, f"skipped: {error_msg}", pipeline_id, phase))
            skipped.add(tool)
            continue

        pid = agent_resp["pid"]
        output_file = agent_resp.get("output_file")
        json_output = agent_resp.get("json_output")

        conn.execute("""
            INSERT INTO recon_scans
            (target_id, tool, status, pid, output_file, json_output, started_at,
             pipeline_run_id, pipeline_phase)
            VALUES (?, ?, 'running', ?, ?, ?, datetime('now'), ?, ?)
        """, (target_id, tool, pid, output_file, json_output, pipeline_id, phase))
      except Exception as e:
        errors.append(f"{tool}: unexpected error: {e}")
        skipped.add(tool)
        conn.execute("""
            INSERT INTO recon_scans
            (target_id, tool, status, result_count, error, started_at, finished_at,
             pipeline_run_id, pipeline_phase)
            VALUES (?, ?, 'completed', 0, ?, datetime('now'),
                    datetime('now'), ?, ?)
        """, (target_id, tool, f"skipped: {e}", pipeline_id, phase))

    conn.commit()
    return errors


def _resolve_input_file(conn, target_id, target_name, tool, pipeline_type="web"):
    """Find the input file for a tool based on its dependency.

    Falls back through the dependency chain when intermediate tools were skipped.
    E.g. if merge-subs didn't run, httpx-toolkit falls back to subfinder output.

    Pipeline-type aware: uses ORACLE_TOOL_DEPS for oracle pipelines, TOOL_DEPS
    otherwise. Falls back to checking both maps if the tool isn't in the
    declared pipeline_type's dict (defensive — supports shared tools).
    """
    deps_dict = _tool_deps_for(pipeline_type)
    if tool not in deps_dict:
        # Fallback: check the other pipeline's dict (for shared tools like subfinder,
        # merge-subs, httpx-toolkit which exist in both).
        other_dict = TOOL_DEPS if pipeline_type == "oracle" else ORACLE_TOOL_DEPS
        if tool in other_dict:
            deps_dict = other_dict
        else:
            return None

    dep_tool, _ = deps_dict[tool]

    # Try the primary dependency first, then fall back up the chain
    fallback_chain = [dep_tool]
    # Build fallback: merge-subs → shuffledns → dnsgen → subfinder
    visited = {dep_tool}
    current = dep_tool
    while current in deps_dict:
        parent, _ = deps_dict[current]
        if parent in visited:
            break
        fallback_chain.append(parent)
        visited.add(parent)
        current = parent

    files_resp, _ = _agent("get", f"/files/{target_name}")
    if "error" in files_resp:
        return None

    # Some tools need a secondary output file from their dependency
    # (e.g. linkfinder needs js_urls from merge-urls, not all_urls)
    tool_input_prefix = {
        "linkfinder": "js_urls",
        "secret-scan": "js_urls",
        "arjun": "unique_endpoints",
        "wpscan": "wordpress_targets",
        "dalfox": "all_urls",
        "joomscan": "cms_detect",
        "hydra": "panels",
    }

    for dep in fallback_chain:
        prev_scan = conn.execute("""
            SELECT * FROM recon_scans
            WHERE target_id = ? AND tool = ? AND status = 'completed'
            ORDER BY finished_at DESC LIMIT 1
        """, (target_id, dep)).fetchone()
        if not prev_scan:
            # If this tool needs a specific secondary output (e.g. wpscan needs
            # wordpress_targets from cms-detect) and the primary dep didn't complete,
            # don't fall back to generic tools — the input would be wrong.
            if tool in tool_input_prefix and dep == fallback_chain[0]:
                return None
            continue

        # Check for tool-specific secondary output first
        if tool in tool_input_prefix and dep in ("merge-urls", "cms-detect", "panel-detect"):
            prefix = tool_input_prefix[tool]
        else:
            prefix_map = {
                "httpx-toolkit": "httpx",
                "merge-subs": "all_subs",
                "naabu": "naabu",
                "merge-urls": "all_urls",
                "cloud-buckets": "cloud_buckets",
                "cms-detect": "httpx",
                "panel-detect": "panels",
                "arjun": "arjun",
                "dnsx": "shuffledns",
            }
            prefix = prefix_map.get(dep, dep)
        # Determine file suffix — secondary outputs from tool_input_prefix
        if tool in tool_input_prefix and dep in ("merge-urls", "cms-detect", "panel-detect"):
            # Most secondary outputs are .txt, but cms_detect and panels are .json
            if tool_input_prefix[tool] in ("cms_detect", "panels"):
                suffix = ".json"
            else:
                suffix = ".txt"
        else:
            suffix = ".json" if dep in ("httpx-toolkit", "cloud-buckets", "cms-detect", "panel-detect") else ".txt"
        candidates = [f for f in files_resp.get("files", [])
                      if f["name"].startswith(prefix) and f["name"].endswith(suffix)]
        if candidates:
            found_file = candidates[-1]["name"]
            # Fix 2: If httpx was wildcard-wiped, fall back to subfinder/merge-subs
            # for tools that can accept domain lists (not URL-only tools)
            if dep == "httpx-toolkit" and found_file:
                wipe_flags = [f for f in files_resp.get("files", [])
                              if f["name"] == "httpx_wildcard_wiped.json"]
                if wipe_flags:
                    # Tools that can work with domain lists instead of URLs
                    domain_input_tools = {"nuclei", "nuclei-takeover", "subzy",
                                          "s3-takeover", "naabu"}
                    if tool in domain_input_tools:
                        # Fall back to merge-subs or subfinder output
                        sub_candidates = [f for f in files_resp.get("files", [])
                                          if f["name"].startswith("all_subs") and f["name"].endswith(".txt")]
                        if sub_candidates:
                            return sub_candidates[-1]["name"]
                        sub_candidates = [f for f in files_resp.get("files", [])
                                          if f["name"].startswith("subfinder") and f["name"].endswith(".txt")]
                        if sub_candidates:
                            return sub_candidates[-1]["name"]
                    # URL-only tools (katana, gospider, etc.) get None → skip
                    else:
                        return None
            return found_file

        # If this tool needs a secondary output and the dep ran but didn't produce it,
        # don't fall back to other tools (e.g. wpscan needs wordpress_targets from cms-detect)
        if tool in tool_input_prefix and dep == fallback_chain[0]:
            return None

    return None


def _effective_phase_status(pipeline, scans):
    """Recompute pipeline phase_status from actual scan data.

    When the stored phase_status is stale (e.g. 'failed' after a manual rerun,
    or 'running' after agent restart resolved all scans), this function returns
    a corrected status based on the latest scan per tool per phase.

    Pipeline-type aware: uses the max phase number from the relevant phase dict.
    """
    stored = pipeline["phase_status"]
    if stored not in ("failed", "running"):
        return stored  # only override stale failures and stale running

    pipeline_type = _pipeline_type(pipeline)
    max_phase = _max_phase_for(pipeline_type)

    phase = pipeline["current_phase"]
    phase_scans = [s for s in scans if (s["pipeline_phase"] or 0) == phase]
    if not phase_scans:
        return stored

    statuses = [s["status"] for s in phase_scans]
    if any(st in ("running", "pending") for st in statuses):
        return "running"
    if all(st in ("completed", "failed") for st in statuses):
        all_completed = all(st == "completed" for st in statuses)
        if all_completed and phase >= max_phase:
            return "completed"
        elif all_completed:
            return "awaiting_approval"
        # Mix of completed and failed — still done
        if phase >= max_phase:
            return "completed"
        else:
            return "awaiting_approval"
    return stored


def _phase_is_dead(conn, pipeline_id, phase):
    """Return True if a critical scan in *phase* completed with zero usable output.

    Pipeline-killing checks:
      - Phase 1: merge-subs produced 0 results → no subdomains → all of Phase 2+ will be empty
      - Phase 2: httpx-toolkit produced 0 results → no live hosts → all of Phase 3+ will be empty

    For higher phases we don't bail (a Phase 4 with 0 nuclei results just means
    the target's clean, not that the pipeline is broken).
    """
    if phase == 1:
        critical = "merge-subs"
    elif phase == 2:
        critical = "httpx-toolkit"
    else:
        return False
    row = conn.execute("""
        SELECT status, result_count FROM recon_scans
        WHERE pipeline_run_id = ? AND tool = ? AND pipeline_phase = ?
        ORDER BY id DESC LIMIT 1
    """, (pipeline_id, critical, phase)).fetchone()
    if not row:
        return False
    return row["status"] in ("completed", "failed") and (row["result_count"] or 0) == 0


def _check_phase_completion(conn, pipeline_id, program_handle):
    """Check if all scans in the current phase are done. If so, transition to awaiting_approval.

    Pipeline-type aware: selects the correct PIPELINE_PHASES / deps dicts
    and respects the correct max phase number for this pipeline type.
    """
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if not pipeline or pipeline["phase_status"] not in ("running", "failed"):
        return

    pipeline_type = _pipeline_type(pipeline)
    phases_dict = _phases_for(pipeline_type)
    max_phase = _max_phase_for(pipeline_type)

    phase = pipeline["current_phase"]
    scans = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
    """, (pipeline_id, phase)).fetchall()

    if not scans:
        # current_phase advanced but no tools launched yet for this phase
        # (agent restart, single-pipeline gate previously blocked us, or
        # _launch_phase_tools was never called for this phase).  Try to
        # launch now — same idempotent path used below for unlaunched tools.
        target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                              (pipeline["target_id"],)).fetchone()
        if target:
            _launch_phase_tools(conn, pipeline_id, target, phase)
        return

    # Recover stale scans (per-tool timeout — must exceed recon_agent.TOOL_RUNTIME_LIMITS
    # plus slack, otherwise we kill scans that are still legitimately running).
    # Default 90 min covers most fast tools; heavy long-running tools get explicit budgets.
    DEFAULT_STALE_MIN = 90
    STALE_TIMEOUTS = {
        # Phase 3 crawlers — heavy
        "feroxbuster": 240,   # recon_agent caps at 180min; allow slack for ingestion
        "kiterunner":  180,   # large wordlist brute-force
        "getallurls":  150,   # recon_agent caps at 120min
        "gospider":    150,   # recon_agent caps at 120min
        "katana":      120,   # depth-5 crawl on large targets
        "nuclei":      180,   # DAST fuzzing + KEV templates
        # Phase 4 analysis
        "arjun":       180,   # parameter discovery is slow per URL
        "linkfinder":  90,
        # Phase 5 exploitation — verified slow
        "sqlmap":      180,
        "commix":      150,
        "wpscan":      120,
        # Phase 1/2 enumeration — quick failure should be quick
        "subfinder":   60,
        "amass":       90,
        "shuffledns":  60,
        "dnsx":        60,
        "httpx-toolkit": 90,
        "naabu":       90,
        "nmap":        120,
        "eyewitness":  90,
    }

    def _stale_limit(tool):
        return STALE_TIMEOUTS.get(tool, DEFAULT_STALE_MIN)

    for scan in scans:
        if scan["status"] == "running" and scan["pid"]:
            agent_resp, status_code = _agent("get", f"/scan/{scan['pid']}/status")
            tool_stale_min = _stale_limit(scan["tool"])
            if status_code == 200:
                agent_status = agent_resp.get("status", "unknown")
                if agent_status in ("completed", "failed"):
                    result_count = agent_resp.get("result_count", 0)
                    if agent_status == "completed":
                        result_count = _ingest_results(conn, scan["id"], scan["pid"], scan["tool"])
                    conn.execute("""
                        UPDATE recon_scans SET status = ?, result_count = ?, finished_at = datetime('now')
                        WHERE id = ?
                    """, (agent_status, result_count, scan["id"]))
                    conn.commit()

                    # Check for intra-phase deps that can now be launched
                    _launch_intra_phase_deps(conn, pipeline_id, pipeline["target_id"], phase, scan["tool"])
                elif agent_status == "running":
                    # Agent says scan is still running — check if it's been too long
                    if scan["started_at"]:
                        from datetime import datetime, timedelta
                        try:
                            started = datetime.fromisoformat(scan["started_at"])
                            elapsed = (datetime.now() - started).total_seconds() / 60
                            if elapsed > tool_stale_min:
                                # Kill the stale scan and mark as failed
                                _agent("post", f"/scan/{scan['pid']}/kill")
                                conn.execute("""
                                    UPDATE recon_scans SET status = 'failed',
                                    error = ?,
                                    finished_at = datetime('now') WHERE id = ?
                                """, ("stale: running >%dmin, killed" % tool_stale_min, scan["id"]))
                                conn.commit()
                        except (ValueError, TypeError):
                            pass
            elif scan["status"] == "running":
                # Agent lost scan (404/error) — check time and try disk recovery
                is_stale = False
                if scan["started_at"]:
                    from datetime import datetime, timedelta
                    try:
                        started = datetime.fromisoformat(scan["started_at"])
                        elapsed = (datetime.now() - started).total_seconds() / 60
                        is_stale = elapsed > tool_stale_min
                    except (ValueError, TypeError):
                        pass

                output_file = scan["output_file"]
                if output_file:
                    files_resp, _ = _agent("get", f"/files/{program_handle}")
                    files_listing = files_resp.get("files", [])
                    file_exists = any(f["name"] == output_file for f in files_listing)
                    # gospider writes to a directory (json_output), and the
                    # merged .txt (output_file) is only created at ingest time.
                    # If the agent lost the scan post-reboot, the .txt won't
                    # exist yet but the raw dir will. Fall back to checking
                    # json_output so we can recover the data instead of dropping
                    # 100K+ URLs on the floor.
                    if not file_exists and scan["json_output"]:
                        file_exists = any(
                            f["name"] == scan["json_output"]
                            and (f.get("is_dir") or f.get("size", 0) > 0)
                            for f in files_listing
                        )
                    if file_exists:
                        count = _ingest_results(conn, scan["id"], scan["pid"], scan["tool"])
                        conn.execute("""
                            UPDATE recon_scans SET status = 'completed', result_count = ?,
                            finished_at = datetime('now') WHERE id = ?
                        """, (count, scan["id"]))
                    elif is_stale:
                        conn.execute("""
                            UPDATE recon_scans SET status = 'failed',
                            error = ?,
                            finished_at = datetime('now') WHERE id = ?
                        """, ("stale: running >%dmin, agent lost scan" % tool_stale_min, scan["id"]))
                    else:
                        conn.execute("""
                            UPDATE recon_scans SET status = 'failed',
                            error = 'process lost (agent restarted)',
                            finished_at = datetime('now') WHERE id = ?
                        """, (scan["id"],))
                    conn.commit()
                elif is_stale:
                    # No output file and stale — just fail it
                    conn.execute("""
                        UPDATE recon_scans SET status = 'failed',
                        error = ?,
                        finished_at = datetime('now') WHERE id = ?
                    """, ("stale: running >%dmin, agent lost scan, no output" % tool_stale_min, scan["id"]))
                    conn.commit()

    # Recover scans that were marked "process lost" but actually wrote output to disk
    # (race condition: agent restarted while scan was finishing, output file wasn't ready yet)
    lost_scans = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
        AND status = 'failed' AND error = 'process lost (agent restarted)'
        AND output_file IS NOT NULL
    """, (pipeline_id, phase)).fetchall()
    if lost_scans:
        files_resp, _ = _agent("get", f"/files/{program_handle}")
        available_files = {f["name"]: f.get("size", 0) for f in files_resp.get("files", [])}
        for scan in lost_scans:
            fname = scan["output_file"]
            if fname in available_files and available_files[fname] > 0:
                count = _ingest_results(conn, scan["id"], scan["pid"], scan["tool"])
                conn.execute("""
                    UPDATE recon_scans SET status = 'completed', result_count = ?,
                    error = NULL, finished_at = datetime('now') WHERE id = ?
                """, (count, scan["id"]))
                conn.commit()
                _launch_intra_phase_deps(conn, pipeline_id, pipeline["target_id"], phase, scan["tool"])

    # Re-check all scans after updates
    scans = conn.execute("""
        SELECT status, tool FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
    """, (pipeline_id, phase)).fetchall()

    # Attempt to launch any expected phase tools that have no record yet OR are pending retry
    # (pending = created on 429 concurrency limit, _launch_phase_tools will delete & re-attempt)
    # Use the LATEST record per tool — a tool may have an older "skipped" record AND a newer
    # "pending" record from an intra-phase dep retry.  Only the latest matters.
    scans = conn.execute("""
        SELECT status, tool FROM recon_scans
        WHERE pipeline_run_id = ? AND pipeline_phase = ?
        ORDER BY id ASC
    """, (pipeline_id, phase)).fetchall()
    latest_by_tool = {}
    for s in scans:
        latest_by_tool[s["tool"]] = s["status"]  # last row wins (highest id)
    launched_tools = {tool for tool, st in latest_by_tool.items() if st != "pending"}
    expected_tools = phases_dict.get(phase, [])
    unlaunched = [t for t in expected_tools if t not in launched_tools]
    if unlaunched:
        target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                              (pipeline["target_id"],)).fetchone()
        if target:
            # Fire intra-phase deps for any completed tools whose dependents weren't launched
            # (handles agent restart case where the completion trigger was missed)
            completed_tools = {s["tool"] for s in scans if s["status"] in ("completed", "failed")}
            for ct in completed_tools:
                _launch_intra_phase_deps(conn, pipeline_id, target["id"], phase, ct)
            _launch_phase_tools(conn, pipeline_id, target, phase)
            scans = conn.execute("""
                SELECT status, tool FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
                ORDER BY id ASC
            """, (pipeline_id, phase)).fetchall()
            latest_by_tool = {}
            for s in scans:
                latest_by_tool[s["tool"]] = s["status"]
            launched_tools = {tool for tool, st in latest_by_tool.items() if st != "pending"}

        # Check which tools are still missing records (or still pending retry)
        still_missing = [t for t in expected_tools if t not in launched_tools]
        if still_missing:
            # Don't block completion for tools whose intra-phase dep chain is entirely
            # skipped/failed — they'll never launch. Record them as skipped so the phase
            # can finish.
            any_truly_pending = False
            for tool in still_missing:
                # If the latest record is 'pending' (429 concurrency limit), treat as
                # genuinely pending — don't walk the dep chain and prematurely skip it.
                if latest_by_tool.get(tool) == "pending":
                    any_truly_pending = True
                    continue
                deps = _get_deps(tool, pipeline_type)
                if deps:
                    # Walk up the ENTIRE ancestor chain to see if any ancestor is
                    # still running or pending launch.  The old code only checked the
                    # immediate dep, which caused premature skipping when a grandparent
                    # was still running (e.g. subfinder running → dnsgen not launched
                    # → shuffledns wrongly marked "dependency not launched").
                    chain_alive = False
                    for dep_root in deps:
                        ancestor = dep_root
                        while ancestor:
                            a_scan = conn.execute("""
                                SELECT status FROM recon_scans
                                WHERE pipeline_run_id = ? AND tool = ?
                                ORDER BY id DESC LIMIT 1
                            """, (pipeline_id, ancestor)).fetchone()
                            if a_scan and a_scan["status"] == "running":
                                chain_alive = True
                                break
                            elif a_scan and a_scan["status"] in ("completed", "failed"):
                                anc_deps = _get_deps(ancestor, pipeline_type)
                                ancestor = anc_deps[0] if anc_deps else None
                                continue
                            elif not a_scan:
                                anc_deps = _get_deps(ancestor, pipeline_type)
                                ancestor = anc_deps[0] if anc_deps else None
                                if ancestor:
                                    continue
                                else:
                                    # Reached root — check if root is pending launch
                                    root = dep_root
                                    while _get_deps(root, pipeline_type):
                                        root = _get_deps(root, pipeline_type)[0]
                                    if root in launched_tools:
                                        chain_alive = True
                                    break
                            else:
                                chain_alive = True
                                break
                        if chain_alive:
                            break

                    if chain_alive:
                        any_truly_pending = True
                    else:
                        # Entire ancestor chain is terminal — deps done but tool never launched
                        all_deps_terminal = True
                        any_dep_missing = False
                        any_dep_completed = False
                        for dep in deps:
                            dep_scan = conn.execute("""
                                SELECT status FROM recon_scans
                                WHERE pipeline_run_id = ? AND tool = ?
                                ORDER BY id DESC LIMIT 1
                            """, (pipeline_id, dep)).fetchone()
                            if not dep_scan:
                                any_dep_missing = True
                            elif dep_scan["status"] not in ("completed", "failed"):
                                all_deps_terminal = False
                            elif dep_scan["status"] == "completed":
                                any_dep_completed = True

                        # Bug #4 fix: before marking skipped, attempt one final
                        # launch via _launch_phase_tools. This handles the race
                        # where the dep just completed (e.g. merge-subs → httpx-toolkit)
                        # but the inline _launch_intra_phase_deps trigger didn't
                        # fire (agent restart, race with another phase check, or
                        # the dep file wasn't yet visible to the agent /files
                        # endpoint at the time of the first launch attempt).
                        if all_deps_terminal and any_dep_completed and target:
                            _launch_phase_tools(conn, pipeline_id, target, phase)
                            retry_scan = conn.execute("""
                                SELECT status FROM recon_scans
                                WHERE pipeline_run_id = ? AND tool = ?
                                ORDER BY id DESC LIMIT 1
                            """, (pipeline_id, tool)).fetchone()
                            if retry_scan and retry_scan["status"] in ("running", "pending", "completed"):
                                # Successfully launched (or already finished). Skip the
                                # dependency-chain-missed insert below.
                                if retry_scan["status"] in ("running", "pending"):
                                    any_truly_pending = True
                                continue

                        if all_deps_terminal and target:
                            skip_reason = 'skipped: dependency chain missed' if not any_dep_missing else 'skipped: dependency not launched'
                            conn.execute("""
                                INSERT INTO recon_scans
                                (target_id, tool, status, result_count, error, started_at, finished_at,
                                 pipeline_run_id, pipeline_phase)
                                VALUES (?, ?, 'completed', 0, ?,
                                        datetime('now'), datetime('now'), ?, ?)
                            """, (target["id"], tool, skip_reason, pipeline_id, phase))
                        elif any_dep_missing and target:
                            conn.execute("""
                                INSERT INTO recon_scans
                                (target_id, tool, status, result_count, error, started_at, finished_at,
                                 pipeline_run_id, pipeline_phase)
                                    VALUES (?, ?, 'completed', 0, 'skipped: dependency not launched',
                                            datetime('now'), datetime('now'), ?, ?)
                                """, (target["id"], tool, pipeline_id, phase))
                else:
                    # Not an intra-phase dep tool — genuinely pending (concurrency limit)
                    any_truly_pending = True
            conn.commit()
            if any_truly_pending:
                return
            # Re-fetch scans after inserting skipped records
            scans = conn.execute("""
                SELECT status, tool FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
            """, (pipeline_id, phase)).fetchall()

    all_done = all(s["status"] in ("completed", "failed") for s in scans)
    if all_done:
        # Bail out early if a critical phase produced zero usable output. Without
        # this, a Phase 1 with no subdomains (e.g. modem outage during recon, or
        # bad scope expansion) marches through Phase 2-5 producing nothing — wastes
        # autopilot cycles and pollutes triage data with empty pipelines.
        if pipeline_type == "web" and _phase_is_dead(conn, pipeline_id, phase):
            conn.execute("""
                UPDATE pipeline_runs SET phase_status = 'failed', updated_at = datetime('now')
                WHERE id = ?
            """, (pipeline_id,))
            conn.commit()
            return

        auto_approve = pipeline["auto_approve"] if "auto_approve" in pipeline.keys() else 1
        if auto_approve and phase < max_phase:
            # Auto-advance to next phase
            next_phase = phase + 1
            while next_phase <= max_phase and not phases_dict.get(next_phase):
                next_phase += 1
            if next_phase <= max_phase:
                conn.execute("""
                    UPDATE pipeline_runs SET current_phase = ?, phase_status = 'running',
                    updated_at = datetime('now') WHERE id = ?
                """, (next_phase, pipeline_id))
                conn.commit()
                target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                                      (pipeline["target_id"],)).fetchone()
                _launch_phase_tools(conn, pipeline_id, target, next_phase)
            else:
                conn.execute("""
                    UPDATE pipeline_runs SET phase_status = 'completed', updated_at = datetime('now')
                    WHERE id = ?
                """, (pipeline_id,))
                conn.commit()
        elif phase >= max_phase:
            conn.execute("""
                UPDATE pipeline_runs SET phase_status = 'completed', updated_at = datetime('now')
                WHERE id = ?
            """, (pipeline_id,))
            conn.commit()
        else:
            conn.execute("""
                UPDATE pipeline_runs SET phase_status = 'awaiting_approval', updated_at = datetime('now')
                WHERE id = ?
            """, (pipeline_id,))
            conn.commit()

    # If we just transitioned to a terminal status, release the egress netns
    # so the next pipeline can claim it.
    final = conn.execute(
        "SELECT phase_status FROM pipeline_runs WHERE id = ?", (pipeline_id,)
    ).fetchone()
    if final and final["phase_status"] in ("completed", "failed"):
        _release_egress_netns(pipeline_id)


def _launch_intra_phase_deps(conn, pipeline_id, target_id, phase, completed_tool):
    """After a tool completes, check if any intra-phase dependents can now launch.

    If a dependent tool is unavailable, skip it and recursively trigger its own dependents.
    Pipeline-type aware: looks up the correct INTRA_PHASE_DEPS / PIPELINE_PHASES dicts.
    """
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        return

    # Look up pipeline_type from the pipeline row
    pipeline_row = conn.execute(
        "SELECT pipeline_type FROM pipeline_runs WHERE id = ?", (pipeline_id,)
    ).fetchone()
    pipeline_type = _pipeline_type(pipeline_row)
    intra_deps_dict = _intra_deps_for(pipeline_type)
    phases_dict = _phases_for(pipeline_type)
    builtin_tools = _builtin_tools_for(pipeline_type)

    # Check tool availability
    tools_resp, _ = _agent("get", "/tools")
    agent_reachable = isinstance(tools_resp, dict) and "error" not in tools_resp
    available = {}
    if agent_reachable:
        available = {k: v.get("available", False) for k, v in tools_resp.items()}

    for tool, raw_dep in intra_deps_dict.items():
        deps = raw_dep if isinstance(raw_dep, list) else [raw_dep]
        if completed_tool not in deps:
            continue
        # Check this tool is in the current phase and hasn't been launched
        if tool not in phases_dict.get(phase, []):
            continue
        existing = conn.execute("""
            SELECT id, status FROM recon_scans WHERE pipeline_run_id = ? AND tool = ?
            ORDER BY id DESC LIMIT 1
        """, (pipeline_id, tool)).fetchone()
        if existing and existing["status"] != "pending":
            continue
        if existing and existing["status"] == "pending":
            # Delete the pending placeholder so we can re-attempt
            conn.execute("DELETE FROM recon_scans WHERE id = ?", (existing["id"],))
        # For multi-dep tools, ALL deps must be done before launching
        all_deps_done = True
        for d in deps:
            d_scan = conn.execute("""
                SELECT status FROM recon_scans WHERE pipeline_run_id = ? AND tool = ?
                ORDER BY id DESC LIMIT 1
            """, (pipeline_id, d)).fetchone()
            if not d_scan or d_scan["status"] not in ("completed", "failed"):
                all_deps_done = False
                break
        if not all_deps_done:
            continue

        try:
            # Agent unreachable — leave unlaunched for recovery
            if not agent_reachable and tool not in builtin_tools:
                continue

            # If tool not available, skip and recursively trigger its dependents
            if not available.get(tool, False) and tool not in builtin_tools:
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, result_count, error, started_at, finished_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'completed', 0, 'skipped: tool not installed', datetime('now'),
                            datetime('now'), ?, ?)
                """, (target_id, tool, pipeline_id, phase))
                conn.commit()
                _launch_intra_phase_deps(conn, pipeline_id, target_id, phase, tool)
                continue

            # Launch it
            target_name = target["program_handle"]
            agent_data = {"tool": tool, "target_name": target_name,
                          "pipeline_id": pipeline_id}
            if tool in ("merge-subs", "merge-urls"):
                pass  # no input_file needed
            else:
                input_file = _resolve_input_file(conn, target_id, target_name, tool, pipeline_type)
                if input_file:
                    agent_data["input_file"] = input_file
                else:
                    conn.execute("""
                        INSERT INTO recon_scans
                        (target_id, tool, status, result_count, error, started_at, finished_at,
                         pipeline_run_id, pipeline_phase)
                        VALUES (?, ?, 'completed', 0, 'skipped: no input from dependency', datetime('now'),
                                datetime('now'), ?, ?)
                    """, (target_id, tool, pipeline_id, phase))
                    conn.commit()
                    _launch_intra_phase_deps(conn, pipeline_id, target_id, phase, tool)
                    continue

            agent_resp, status_code = _agent("post", "/scan/start", json=agent_data)
            if status_code == 201:
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, pid, output_file, json_output, started_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'running', ?, ?, ?, datetime('now'), ?, ?)
                """, (target_id, tool, agent_resp["pid"],
                      agent_resp.get("output_file"), agent_resp.get("json_output"),
                      pipeline_id, phase))
                conn.commit()
            elif status_code in (429, 502, 504):
                # 429 = concurrency limit, 502/504 = agent down/restarting
                # Record as 'pending' so _check_phase_completion can retry later
                error_msg = agent_resp.get("error", "agent error")
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, error, started_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'pending', ?, datetime('now'), ?, ?)
                """, (target_id, tool, f"queued: {error_msg}", pipeline_id, phase))
                conn.commit()
            else:
                error_msg = agent_resp.get("error", "agent error")
                conn.execute("""
                    INSERT INTO recon_scans
                    (target_id, tool, status, result_count, error, started_at, finished_at,
                     pipeline_run_id, pipeline_phase)
                    VALUES (?, ?, 'completed', 0, ?, datetime('now'),
                            datetime('now'), ?, ?)
                """, (target_id, tool, f"skipped: {error_msg}", pipeline_id, phase))
                conn.commit()
                _launch_intra_phase_deps(conn, pipeline_id, target_id, phase, tool)
        except Exception as e:
            conn.execute("""
                INSERT INTO recon_scans
                (target_id, tool, status, result_count, error, started_at, finished_at,
                 pipeline_run_id, pipeline_phase)
                VALUES (?, ?, 'completed', 0, ?, datetime('now'),
                        datetime('now'), ?, ?)
            """, (target_id, tool, f"skipped: {e}", pipeline_id, phase))
            conn.commit()


def _recover_stale_pipeline_scans(conn, pipeline_id, program_handle):
    """Recover all stale running scans for a pipeline run."""
    stale = conn.execute("""
        SELECT * FROM recon_scans WHERE pipeline_run_id = ? AND status = 'running'
    """, (pipeline_id,)).fetchall()
    if not stale:
        return

    for scan in stale:
        pid = scan["pid"]
        if not pid:
            continue
        agent_resp, status_code = _agent("get", f"/scan/{pid}/status")
        if status_code == 200:
            agent_status = agent_resp.get("status", "unknown")
            if agent_status in ("completed", "failed"):
                result_count = agent_resp.get("result_count", 0)
                if agent_status == "completed":
                    result_count = _ingest_results(conn, scan["id"], pid, scan["tool"])
                conn.execute("""
                    UPDATE recon_scans SET status = ?, result_count = ?, finished_at = datetime('now')
                    WHERE id = ?
                """, (agent_status, result_count, scan["id"]))
        else:
            output_file = scan["output_file"]
            json_output = scan["json_output"] if "json_output" in scan.keys() else None
            if output_file:
                files_resp, _ = _agent("get", f"/files/{program_handle}")
                file_names = {f["name"] for f in files_resp.get("files", [])}
                # Check for output_file OR gospider raw directory (json_output)
                file_exists = output_file in file_names or (json_output and json_output.split("/")[-1] in file_names)
                if file_exists:
                    count = _ingest_results(conn, scan["id"], pid, scan["tool"])
                    conn.execute("""
                        UPDATE recon_scans SET status = 'completed', result_count = ?,
                        finished_at = datetime('now') WHERE id = ?
                    """, (count, scan["id"]))
                else:
                    conn.execute("""
                        UPDATE recon_scans SET status = 'failed',
                        error = 'process lost (agent restarted)',
                        finished_at = datetime('now') WHERE id = ?
                    """, (scan["id"],))
            else:
                conn.execute("""
                    UPDATE recon_scans SET status = 'failed',
                    error = 'process lost (agent restarted)',
                    finished_at = datetime('now') WHERE id = ?
                """, (scan["id"],))
    conn.commit()

    # Check if phase is now complete
    pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()
    if pipeline and pipeline["phase_status"] == "running":
        pipeline_type = _pipeline_type(pipeline)
        phases_dict = _phases_for(pipeline_type)
        max_phase = _max_phase_for(pipeline_type)
        phase = pipeline["current_phase"]
        scans = conn.execute("""
            SELECT status FROM recon_scans WHERE pipeline_run_id = ? AND pipeline_phase = ?
        """, (pipeline_id, phase)).fetchall()
        if scans and all(s["status"] in ("completed", "failed") for s in scans):
            auto_approve = pipeline["auto_approve"] if "auto_approve" in pipeline.keys() else 1
            if auto_approve and phase < max_phase:
                # Auto-advance to next phase
                next_phase = phase + 1
                while next_phase <= max_phase and not phases_dict.get(next_phase):
                    next_phase += 1
                if next_phase <= max_phase:
                    conn.execute("""
                        UPDATE pipeline_runs SET current_phase = ?, phase_status = 'running',
                        updated_at = datetime('now') WHERE id = ?
                    """, (next_phase, pipeline_id))
                    conn.commit()
                    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                                          (pipeline["target_id"],)).fetchone()
                    _launch_phase_tools(conn, pipeline_id, target, next_phase)
                else:
                    conn.execute("""
                        UPDATE pipeline_runs SET phase_status = 'completed', updated_at = datetime('now')
                        WHERE id = ?
                    """, (pipeline_id,))
                    conn.commit()
            elif phase >= max_phase:
                conn.execute("""
                    UPDATE pipeline_runs SET phase_status = 'completed', updated_at = datetime('now')
                    WHERE id = ?
                """, (pipeline_id,))
                conn.commit()
            else:
                conn.execute("""
                    UPDATE pipeline_runs SET phase_status = 'awaiting_approval',
                    updated_at = datetime('now') WHERE id = ?
                """, (pipeline_id,))
                conn.commit()


def _recover_stale_scans(conn, target_id, program_handle):
    """Check all 'running' scans for a target and resolve any that have actually finished."""
    stale = conn.execute(
        "SELECT * FROM recon_scans WHERE target_id = ? AND status = 'running'",
        (target_id,),
    ).fetchall()
    if not stale:
        return

    for scan in stale:
        pid = scan["pid"]
        if not pid:
            continue

        # Ask the agent if it knows about this scan
        agent_resp, status_code = _agent("get", f"/scan/{pid}/status")

        if status_code == 200:
            agent_status = agent_resp.get("status", "unknown")
            if agent_status in ("completed", "failed"):
                result_count = agent_resp.get("result_count", 0)
                if agent_status == "completed":
                    result_count = _ingest_results(conn, scan["id"], pid, scan["tool"])
                conn.execute("""
                    UPDATE recon_scans SET status = ?, result_count = ?, finished_at = datetime('now')
                    WHERE id = ?
                """, (agent_status, result_count, scan["id"]))
            # If still running according to agent, leave it alone
        else:
            # Agent doesn't know about this scan — try to recover from disk
            output_file = scan["output_file"]
            json_output = scan["json_output"] if "json_output" in scan.keys() else None
            if output_file:
                files_resp, _ = _agent("get", f"/files/{program_handle}")
                file_names = {f["name"] for f in files_resp.get("files", [])}
                # Check for output_file OR gospider raw directory (json_output)
                file_exists = output_file in file_names or (json_output and json_output.split("/")[-1] in file_names)
                if file_exists:
                    count = _ingest_results(conn, scan["id"], pid, scan["tool"])
                    conn.execute("""
                        UPDATE recon_scans SET status = 'completed', result_count = ?, finished_at = datetime('now')
                        WHERE id = ?
                    """, (count, scan["id"]))
                else:
                    conn.execute("""
                        UPDATE recon_scans SET status = 'failed', error = 'process lost (agent restarted)',
                        finished_at = datetime('now') WHERE id = ?
                    """, (scan["id"],))
            else:
                conn.execute("""
                    UPDATE recon_scans SET status = 'failed', error = 'process lost (agent restarted)',
                    finished_at = datetime('now') WHERE id = ?
                """, (scan["id"],))

    conn.commit()


def _ingest_results(conn, scan_id, pid, tool):
    """Fetch results from agent and insert into recon_results (with deduplication)."""
    agent_resp, status_code = _agent("get", f"/scan/{pid}/results")

    # Fallback: if agent lost scan state, read results from disk via file endpoint
    if status_code != 200 or not agent_resp.get("results"):
        scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
        if scan:
            target = conn.execute("SELECT program_handle FROM recon_targets WHERE id = ?",
                                  (scan["target_id"],)).fetchone()
            # Determine which file to read
            filename = scan["json_output"] or scan["output_file"]
            if target and filename:
                agent_resp, status_code = _agent("post", "/results/from-file", json={
                    "target_name": target["program_handle"],
                    "filename": filename,
                    "tool": tool,
                })

    if status_code != 200:
        return 0

    results = agent_resp.get("results", [])
    count = 0

    # Build dedup set: existing (result_type, value) pairs for this target
    # so re-runs and injections don't create duplicate findings
    scan_row = conn.execute("SELECT target_id FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    existing_values = set()
    if scan_row:
        existing = conn.execute("""
            SELECT r.result_type, r.value FROM recon_results r
            JOIN recon_scans s ON s.id = r.scan_id
            WHERE s.target_id = ?
        """, (scan_row["target_id"],)).fetchall()
        existing_values = {(row["result_type"], row["value"]) for row in existing}

    def _dedup_insert(rtype, value, metadata=None):
        """Insert a result only if (result_type, value) doesn't already exist for this target."""
        if (rtype, value) in existing_values:
            return False
        existing_values.add((rtype, value))
        if metadata:
            conn.execute(
                "INSERT INTO recon_results (scan_id, result_type, value, metadata) VALUES (?, ?, ?, ?)",
                (scan_id, rtype, value, json.dumps(metadata)),
            )
        else:
            conn.execute(
                "INSERT INTO recon_results (scan_id, result_type, value) VALUES (?, ?, ?)",
                (scan_id, rtype, value),
            )
        return True

    if tool in ("subfinder", "dnsgen", "shuffledns", "merge-subs", "amass", "crt-sh"):
        for r in results:
            if _dedup_insert("subdomain", r["value"]):
                count += 1

    elif tool in ("katana", "getallurls", "merge-urls", "gospider"):
        for r in results:
            if _dedup_insert("url", r["value"]):
                count += 1

    elif tool == "httpx-toolkit":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("live_host", r["value"], meta):
                count += 1

    elif tool == "nuclei":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("vulnerability", r["value"], meta):
                count += 1

    elif tool == "nuclei-takeover":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("takeover", r["value"], meta):
                count += 1

    elif tool == "subzy":
        for r in results:
            status = (r.get("status") or "").upper()
            if status != "VULNERABLE":
                continue
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("takeover", r["value"], meta):
                count += 1

    elif tool in ("naabu", "nmap"):
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            # Use host:port as the dedup key so nmap (which produces per-port
            # records with rich service/version data) doesn't get fully
            # deduplicated against naabu's per-host entries.  Before this
            # fix, naabu would populate open_port=hostname for 941 hosts,
            # and nmap's 720 follow-up records on the same hosts would all
            # be silently dropped by dedup, hiding port/service/CVE data.
            port = r.get("port")
            host = r.get("hostname") or r.get("host") or r["value"]
            value = "%s:%s" % (host, port) if port else r["value"]
            if _dedup_insert("open_port", value, meta):
                count += 1

    elif tool == "linkfinder":
        for r in results:
            if _dedup_insert("endpoint", r["value"]):
                count += 1

    elif tool == "secret-scan":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("secret", r["value"], meta):
                count += 1

    elif tool == "arjun":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("parameter", r["value"], meta):
                count += 1

    elif tool == "cms-detect":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("cms_finding", r["value"], meta):
                count += 1

    elif tool == "cloud-buckets":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("cloud_bucket", r["value"], meta):
                count += 1

    elif tool == "s3-takeover":
        for r in results:
            if r.get("vulnerable"):
                meta = {k: v for k, v in r.items() if k != "value"}
                meta["source"] = tool
                if _dedup_insert("takeover", r["value"], meta):
                    count += 1

    elif tool == "panel-detect":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("exposed_panel", r["value"], meta):
                count += 1

    elif tool == "wpscan":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("vulnerability", r["value"], meta):
                count += 1

    elif tool == "ffuf":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("directory", r["value"], meta):
                count += 1

    elif tool == "dalfox":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("vulnerability", r["value"], meta):
                count += 1

    elif tool in ("joomscan", "sqlmap", "commix"):
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("vulnerability", r["value"], meta):
                count += 1

    elif tool == "hydra":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("default_cred", r["value"], meta):
                count += 1

    elif tool == "gitleaks":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("secret", r["value"], meta):
                count += 1

    elif tool == "eyewitness":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("screenshot", r["value"], meta):
                count += 1

    elif tool == "git-dumper":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            if _dedup_insert("secret", r["value"], meta):
                count += 1

    elif tool == "nomore403":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("bypass", r["value"], meta):
                count += 1

    elif tool == "kiterunner":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("api_endpoint", r["value"], meta):
                count += 1

    elif tool == "corscanner":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("cors_misconfiguration", r["value"], meta):
                count += 1

    elif tool == "trufflehog":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            meta["source"] = tool
            meta["verified"] = True
            if _dedup_insert("secret", r["value"], meta):
                count += 1

    elif tool == "paramspider":
        for r in results:
            if _dedup_insert("url", r["value"]):
                count += 1

    elif tool == "xhr-capture":
        # Each row from xhr_capture.py is a unique (method, url) discovered
        # by loading the SPA in headless Chrome. Cross-origin URLs are the
        # high-value signal — they reveal API hosts hidden behind the SPA
        # shell. Same-origin XHR is logged too (helps with route inventory)
        # but tagged.
        for r in results:
            url = r.get("url") or r.get("value")
            if not url:
                continue
            meta = {k: v for k, v in r.items() if k != "value"}
            meta.setdefault("url", url)
            if _dedup_insert("xhr_endpoint", url, meta):
                count += 1

    elif tool == "nextjs-check":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("vulnerability", r["value"], meta):
                count += 1

    elif tool == "spa-catchall-detect":
        # Each row marks a host whose server returns the same index.html for
        # every path including bogus ones — JS-extracted endpoints from that
        # host are React Router constants, not server URLs.  See memory
        # feedback_spa_catchall_endpoint_trap.md.
        # The triage prompts read this result_type at the top of every pass
        # and warn that endpoints from these hosts should be discounted.
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("spa_catchall", r["value"], meta):
                count += 1

    elif tool == "dnsx":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("subdomain", r["value"], meta):
                count += 1

    elif tool == "feroxbuster":
        for r in results:
            meta = {k: v for k, v in r.items() if k != "value"}
            if _dedup_insert("directory", r["value"], meta):
                count += 1

    # ===== ORACLE PIPELINE TOOLS =====
    # Each oracle parser already assigns a `result_type` per-result, so we
    # just pass it through directly. If missing, fall back to a per-tool default.
    elif tool in ("sslscan", "sslyze", "saml-fingerprint", "jwt-jwe-harvest",
                  "cookie-harvest", "roca-scan", "breach-candidate",
                  "tls-oracle-probe", "xmlenc-oracle-probe",
                  "cbc-padding-probe", "marvin-probe", "xsw-probe",
                  "viewstate-fingerprint", "jwe-invalid-curve-probe",
                  "manger-oaep-probe", "ssh-terrapin-scan",
                  "gcm-nonce-scan", "raccoon-probe"):
        _oracle_fallback_types = {
            "sslscan": "tls_info",
            "sslyze": "tls_info",
            "saml-fingerprint": "saml_endpoint",
            "jwt-jwe-harvest": "jwt_finding",
            "cookie-harvest": "encrypted_token_candidate",
            "roca-scan": "roca_vulnerable",
            "breach-candidate": "breach_candidate",
            "tls-oracle-probe": "tls_oracle_candidate",
            "xmlenc-oracle-probe": "xmlenc_probed",
            # Extended oracle pipeline fallback types
            "cbc-padding-probe": "cbc_padding_probed",
            "marvin-probe": "marvin_timing_candidate",
            "xsw-probe": "saml_xsw_candidate",
            "viewstate-fingerprint": "viewstate_candidate",
            "jwe-invalid-curve-probe": "jwe_invalid_curve_candidate",
            "manger-oaep-probe": "manger_oaep_candidate",
            "ssh-terrapin-scan": "ssh_terrapin_candidate",
            "gcm-nonce-scan": "gcm_nonce_candidate",
            "raccoon-probe": "raccoon_candidate",
        }
        # Bug #3 fix: cross-reference sslyze ROBOT result before flagging
        # tls_oracle_rsa_kex from sslscan. sslscan only sees TLS_RSA_* cipher
        # acceptance — that's necessary but not sufficient for ROBOT. The
        # authoritative test is sslyze's robot probe. Build a set of hosts
        # that already have positive "robot_clear" evidence from sslyze, AND
        # the converse — sslyze ingestion may also retroactively delete
        # earlier sslscan rsa_kex rows when robot_clear arrives later.
        target_id = scan_row["target_id"] if scan_row else None
        robot_clear_hosts = set()
        if target_id:
            for row in conn.execute("""
                SELECT r.value FROM recon_results r
                JOIN recon_scans s ON s.id = r.scan_id
                WHERE s.target_id = ? AND r.result_type = 'tls_oracle_robot_clear'
            """, (target_id,)).fetchall():
                robot_clear_hosts.add(row["value"])

        for r in results:
            rtype = r.get("result_type") or _oracle_fallback_types.get(tool, "oracle_finding")
            value = r.get("value", "")
            if not value:
                continue

            # sslscan: suppress rsa_kex if sslyze already proved this host
            # is not ROBOT-vulnerable.
            if tool == "sslscan" and rtype == "tls_oracle_rsa_kex":
                if value in robot_clear_hosts:
                    continue

            meta = {k: v for k, v in r.items() if k not in ("value", "result_type")}
            meta["source"] = tool
            inserted = _dedup_insert(rtype, value, meta)
            if inserted:
                count += 1

                # sslyze: when we record robot_clear, retroactively delete any
                # earlier sslscan-emitted tls_oracle_rsa_kex rows for the same
                # host on this target.
                if tool == "sslyze" and rtype == "tls_oracle_robot_clear" and target_id:
                    conn.execute("""
                        DELETE FROM recon_results
                        WHERE id IN (
                            SELECT r.id FROM recon_results r
                            JOIN recon_scans s ON s.id = r.scan_id
                            WHERE s.target_id = ?
                              AND r.result_type = 'tls_oracle_rsa_kex'
                              AND r.value = ?
                        )
                    """, (target_id, value))
                    existing_values.discard(("tls_oracle_rsa_kex", value))

    # Use total results seen as result_count (not just new inserts after dedup).
    # On re-runs the dedup-net count is often 0 because prior runs already
    # inserted the same rows, which would trip _phase_is_dead and bail the
    # pipeline incorrectly. The total reflects what the tool actually produced.
    seen = len(results)
    final_count = max(count, seen)
    conn.execute("UPDATE recon_scans SET result_count = ? WHERE id = ?", (final_count, scan_id))
    return final_count


@recon_bp.route("/api/recon/agent/health")
def agent_health():
    resp, status = _agent("get", "/health")
    if status != 200:
        return jsonify({"error": "agent unreachable"}), 502
    return jsonify(resp)


# --- Autopilot Dashboard ---

@recon_bp.route("/recon/autopilot")
def autopilot_dashboard():
    conn = get_connection()

    # Recover any stuck "running" pipelines before rendering. WEB pipelines only
    # — oracle pipelines have their own dashboard at /oracle-pipeline and should
    # not appear here.
    # Loop per pipeline because _check_phase_completion only advances one phase at a time.
    stuck = conn.execute("""
        SELECT p.id, t.program_handle FROM pipeline_runs p
        JOIN recon_targets t ON t.id = p.target_id
        WHERE p.phase_status = 'running'
          AND (p.pipeline_type = 'web' OR p.pipeline_type IS NULL)
    """).fetchall()
    for s in stuck:
        for _ in range(5):  # max 5 phases to catch up
            prev = conn.execute("SELECT current_phase, phase_status FROM pipeline_runs WHERE id = ?",
                                (s["id"],)).fetchone()
            if not prev or prev["phase_status"] != "running":
                break
            _check_phase_completion(conn, s["id"], s["program_handle"])
            after = conn.execute("SELECT current_phase, phase_status FROM pipeline_runs WHERE id = ?",
                                 (s["id"],)).fetchone()
            if after["current_phase"] == prev["current_phase"] and after["phase_status"] == prev["phase_status"]:
                break  # no progress, stop trying

    # Get all WEB pipeline runs with target info. Oracle pipelines have their
    # own dashboard — don't mix them in the autopilot view because clicking into
    # one would take you to /recon/targets/<id>/pipeline which renders against
    # PIPELINE_PHASES (the web pipeline layout), showing all the wrong tools.
    pipelines = conn.execute("""
        SELECT p.id, p.target_id, p.current_phase, p.phase_status, p.auto_approve,
               p.config, p.created_at, p.updated_at,
               t.program_handle, t.program_name, t.domains
        FROM pipeline_runs p
        JOIN recon_targets t ON t.id = p.target_id
        WHERE p.pipeline_type = 'web' OR p.pipeline_type IS NULL
        ORDER BY p.created_at DESC
        LIMIT 50
    """).fetchall()

    # Lightweight scan counts per pipeline (just total result_count from recon_scans, no JOIN on recon_results)
    pipeline_scan_counts = {}
    if pipelines:
        pipeline_ids = [pl["id"] for pl in pipelines]
        placeholders = ",".join("?" * len(pipeline_ids))
        counts = conn.execute(f"""
            SELECT pipeline_run_id, SUM(result_count) as total
            FROM recon_scans
            WHERE pipeline_run_id IN ({placeholders})
            GROUP BY pipeline_run_id
        """, pipeline_ids).fetchall()
        for row in counts:
            pipeline_scan_counts[row["pipeline_run_id"]] = row["total"] or 0

    conn.close()
    return render_template("autopilot.html",
        pipelines=[dict(p) for p in pipelines],
        pipeline_scan_counts=pipeline_scan_counts,
        phase_names=PHASE_NAMES,
    )


@recon_bp.route("/api/recon/autopilot/status")
def autopilot_api_status():
    """API endpoint for autopilot schedule and current state.

    Web pipelines only — oracle pipelines are surfaced via /api/oracle-pipeline/list.
    """
    conn = get_connection()

    running = conn.execute("""
        SELECT p.id, p.current_phase, p.phase_status, p.created_at, p.updated_at,
               t.program_handle
        FROM pipeline_runs p
        JOIN recon_targets t ON t.id = p.target_id
        WHERE p.phase_status IN ('running', 'awaiting_approval')
          AND (p.pipeline_type = 'web' OR p.pipeline_type IS NULL)
        ORDER BY p.created_at DESC LIMIT 1
    """).fetchone()

    last_completed = conn.execute("""
        SELECT p.id, p.created_at, p.updated_at, t.program_handle
        FROM pipeline_runs p
        JOIN recon_targets t ON t.id = p.target_id
        WHERE p.phase_status = 'completed'
          AND (p.pipeline_type = 'web' OR p.pipeline_type IS NULL)
        ORDER BY p.updated_at DESC LIMIT 1
    """).fetchone()

    conn.close()
    return jsonify({
        "schedule": {
            "mode": "continuous",
        },
        "running": dict(running) if running else None,
        "last_completed": dict(last_completed) if last_completed else None,
    })


# ============================================================
# ORACLE PIPELINE ROUTES
# ============================================================
#
# Separate dashboard + API surface for manually-started oracle pipelines.
# Autopilot does NOT touch these — they only run when the user clicks the
# "Start Oracle Pipeline" button in the UI (or curls /api/oracle-pipeline/start).

@recon_bp.route("/oracle-pipeline")
def oracle_pipeline_dashboard():
    """Main oracle pipeline dashboard: start a new run + list recent runs."""
    conn = get_connection()
    # Get programs list for the dropdown (same filter as recon_dashboard)
    programs = conn.execute("""
        SELECT p.handle, p.name, COUNT(s.id) as scope_count,
               p.bounty_min, p.bounty_max, p.signal_required
        FROM programs p
        LEFT JOIN scopes s ON s.program_id = p.id
            AND s.asset_type IN ('URL', 'WILDCARD', 'DOMAIN')
            AND s.eligible_for_submission = 1
        WHERE p.offers_bounties = 1 AND p.submission_state = 'open'
        GROUP BY p.id
        HAVING scope_count > 0
        ORDER BY (p.signal_required IS NULL OR p.signal_required = 0) DESC,
                 p.bounty_max DESC, p.handle ASC
        LIMIT 500
    """).fetchall()
    conn.close()
    return render_template("oracle_pipeline.html", programs=programs)


@recon_bp.route("/oracle-pipeline/<int:pipeline_id>")
def oracle_pipeline_detail_page(pipeline_id):
    """Detail view for a specific oracle pipeline run."""
    return render_template("oracle_pipeline_detail.html", pipeline_id=pipeline_id)


@recon_bp.route("/api/oracle-pipeline/start", methods=["POST"])
def oracle_pipeline_start():
    """Start a new oracle pipeline run.

    Body (one of):
      - {"program_handle": "some-program"} — creates a target from program's URL/WILDCARD scopes
      - {"domains": ["a.com","b.com"], "target_name": "custom-run"} — creates a target from custom list
    """
    data = request.get_json() or {}
    program_handle = data.get("program_handle")
    custom_domains = data.get("domains")
    custom_target_name = data.get("target_name")

    conn = get_connection()

    if program_handle:
        # Create target from the program's scopes
        program = conn.execute(
            "SELECT * FROM programs WHERE handle = ?", (program_handle,)
        ).fetchone()
        if not program:
            conn.close()
            return jsonify({"error": "program not found"}), 404
        scopes = conn.execute("""
            SELECT asset_identifier FROM scopes
            WHERE program_id = ?
              AND asset_type IN ('URL', 'WILDCARD', 'DOMAIN')
              AND eligible_for_submission = 1
        """, (program["id"],)).fetchall()
        domains = []
        for s in scopes:
            ident = s["asset_identifier"]
            if not ident:
                continue
            # Normalize: strip scheme + leading "*." wildcards
            ident = ident.strip().lower()
            if ident.startswith("https://"):
                ident = ident[len("https://"):]
            if ident.startswith("http://"):
                ident = ident[len("http://"):]
            if ident.startswith("*."):
                ident = ident[2:]
            # Strip trailing paths
            ident = ident.split("/")[0]
            if ident and ident not in domains:
                domains.append(ident)
        if not domains:
            conn.close()
            return jsonify({"error": "program has no URL/WILDCARD/DOMAIN scopes"}), 400
        target_name = program_handle
        program_name = program["name"] or program_handle
    elif custom_domains and custom_target_name:
        domains = [d.strip().lower() for d in custom_domains if d and d.strip()]
        if not domains:
            conn.close()
            return jsonify({"error": "domains list empty"}), 400
        target_name = custom_target_name.strip()
        if not target_name:
            conn.close()
            return jsonify({"error": "target_name required"}), 400
        program_name = target_name
    else:
        conn.close()
        return jsonify({"error": "provide either program_handle, or domains + target_name"}), 400

    # Create recon_target
    conn.execute("""
        INSERT INTO recon_targets (program_handle, program_name, domains)
        VALUES (?, ?, ?)
    """, (target_name, program_name, json.dumps(domains)))
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Check if we can skip Phase 1 by reusing existing httpx results.
    # If the same program_handle has a completed httpx-toolkit scan from
    # any pipeline (web or oracle), the recon/<target_name>/httpx_*.json
    # file is already on disk. We can mark Phase 1 tools as "completed
    # (reused from web pipeline)" and start directly at Phase 2. This
    # saves the 10-min subfinder + 3-hr httpx run on large targets.
    existing_httpx = conn.execute("""
        SELECT s.output_file, s.result_count, s.finished_at, s.json_output
        FROM recon_scans s
        JOIN recon_targets t ON t.id = s.target_id
        WHERE t.program_handle = ?
          AND s.tool = 'httpx-toolkit'
          AND s.status = 'completed'
          AND s.result_count > 0
        ORDER BY s.finished_at DESC LIMIT 1
    """, (target_name,)).fetchone()

    skip_phase1 = False
    reused_httpx_file = None
    if existing_httpx:
        # Verify the file still exists on disk via agent /files endpoint
        httpx_file = existing_httpx["json_output"] or existing_httpx["output_file"]
        if httpx_file:
            files_resp, files_status = _agent("get", f"/files/{target_name}")
            if files_status == 200:
                available = {f["name"] for f in files_resp.get("files", [])}
                if httpx_file in available:
                    skip_phase1 = True
                    reused_httpx_file = httpx_file

    if skip_phase1:
        # Start at Phase 2, mark Phase 1 tools as reused
        start_phase = 2
        conn.execute("""
            INSERT INTO pipeline_runs (target_id, current_phase, phase_status, config,
                                        auto_approve, pipeline_type)
            VALUES (?, 2, 'running', '{}', 1, 'oracle')
        """, (target_id,))
        pipeline_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Record Phase 1 tools as completed (reused)
        for tool in ORACLE_PIPELINE_PHASES.get(1, []):
            conn.execute("""
                INSERT INTO recon_scans
                (target_id, tool, status, result_count, error, started_at, finished_at,
                 pipeline_run_id, pipeline_phase, output_file, json_output)
                VALUES (?, ?, 'completed', ?, ?, datetime('now'), datetime('now'), ?, 1, ?, ?)
            """, (target_id, tool,
                  existing_httpx["result_count"] if tool == "httpx-toolkit" else 0,
                  "reused from existing scan (skipped Phase 1)",
                  pipeline_id,
                  reused_httpx_file if tool == "httpx-toolkit" else None,
                  reused_httpx_file if tool == "httpx-toolkit" else None))
        conn.commit()

        # Launch Phase 2
        target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
        errors = _launch_phase_tools(conn, pipeline_id, target, 2)
        conn.commit()
        conn.close()

        return jsonify({
            "pipeline_id": pipeline_id,
            "target_id": target_id,
            "target_name": target_name,
            "domains": domains,
            "phase": 2,
            "skipped_phase1": True,
            "reused_httpx": reused_httpx_file,
            "reused_httpx_results": existing_httpx["result_count"],
            "errors": errors,
        }), 201
    else:
        # No existing httpx — run full Phase 1
        conn.execute("""
            INSERT INTO pipeline_runs (target_id, current_phase, phase_status, config,
                                        auto_approve, pipeline_type)
            VALUES (?, 1, 'running', '{}', 1, 'oracle')
        """, (target_id,))
        pipeline_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        target = conn.execute("SELECT * FROM recon_targets WHERE id = ?", (target_id,)).fetchone()
        errors = _launch_phase_tools(conn, pipeline_id, target, 1)
        conn.commit()
        conn.close()

        return jsonify({
            "pipeline_id": pipeline_id,
            "target_id": target_id,
            "target_name": target_name,
            "domains": domains,
            "phase": 1,
            "skipped_phase1": False,
            "errors": errors,
        }), 201


@recon_bp.route("/api/oracle-pipeline/list")
def oracle_pipeline_list():
    """List all oracle pipelines with status summary."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT p.id, p.target_id, p.current_phase, p.phase_status, p.created_at, p.updated_at,
               t.program_handle, t.program_name, t.domains
        FROM pipeline_runs p
        JOIN recon_targets t ON t.id = p.target_id
        WHERE p.pipeline_type = 'oracle'
        ORDER BY p.created_at DESC
        LIMIT 50
    """).fetchall()
    runs = []
    for r in rows:
        pipeline_type = "oracle"
        max_phase = _max_phase_for(pipeline_type)
        phase_names_dict = _phase_names_for(pipeline_type)
        try:
            domains_count = len(json.loads(r["domains"]))
        except Exception:
            domains_count = 0
        total_results_row = conn.execute("""
            SELECT COUNT(*) as c FROM recon_results rr
            JOIN recon_scans s ON s.id = rr.scan_id
            WHERE s.pipeline_run_id = ?
        """, (r["id"],)).fetchone()
        total_results = total_results_row["c"] if total_results_row else 0
        runs.append({
            "pipeline_id": r["id"],
            "target_id": r["target_id"],
            "target_name": r["program_handle"],
            "program_handle": r["program_handle"],
            "program_name": r["program_name"],
            "current_phase": r["current_phase"],
            "max_phase": max_phase,
            "phase_name": phase_names_dict.get(r["current_phase"], ""),
            "phase_status": r["phase_status"],
            "domains_count": domains_count,
            "total_results": total_results,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    conn.close()
    return jsonify({"runs": runs})


@recon_bp.route("/api/oracle-pipeline/<int:pipeline_id>")
def oracle_pipeline_detail(pipeline_id):
    """Detail view: phase breakdown + findings grouped by result_type."""
    conn = get_connection()
    pipeline = conn.execute(
        "SELECT * FROM pipeline_runs WHERE id = ? AND pipeline_type = 'oracle'",
        (pipeline_id,)
    ).fetchone()
    if not pipeline:
        conn.close()
        return jsonify({"error": "oracle pipeline not found"}), 404

    target = conn.execute(
        "SELECT * FROM recon_targets WHERE id = ?", (pipeline["target_id"],)
    ).fetchone()

    # Kick the phase completion check so scans get ingested and phases advance
    if target:
        _check_phase_completion(conn, pipeline_id, target["program_handle"])
        # Re-read in case status changed
        pipeline = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)).fetchone()

    pipeline_type = "oracle"
    phases_dict = _phases_for(pipeline_type)
    phase_names_dict = _phase_names_for(pipeline_type)
    max_phase = _max_phase_for(pipeline_type)

    # Fetch all scans for this pipeline
    scans = conn.execute("""
        SELECT s.* FROM recon_scans s
        INNER JOIN (
            SELECT tool, pipeline_phase, MAX(id) as max_id
            FROM recon_scans WHERE pipeline_run_id = ?
            GROUP BY tool, pipeline_phase
        ) latest ON s.id = latest.max_id
        ORDER BY s.pipeline_phase, s.created_at
    """, (pipeline_id,)).fetchall()

    # Group scans by phase
    phase_rows = []
    for phase_num in sorted(phases_dict.keys()):
        phase_tools = phases_dict[phase_num]
        phase_scans = [dict(s) for s in scans if s["pipeline_phase"] == phase_num]
        # Include expected tools that haven't been scanned yet
        scanned_tools = {s["tool"] for s in phase_scans}
        for expected in phase_tools:
            if expected not in scanned_tools:
                phase_scans.append({"tool": expected, "status": "pending",
                                    "result_count": 0, "error": None})
        phase_status = "pending"
        if phase_num < pipeline["current_phase"]:
            phase_status = "completed"
        elif phase_num == pipeline["current_phase"]:
            phase_status = pipeline["phase_status"]
        phase_rows.append({
            "phase": phase_num,
            "phase_name": phase_names_dict.get(phase_num, ""),
            "tools": phase_scans,
            "status": phase_status,
        })

    # Findings grouped by result_type
    findings = {}
    rows = conn.execute("""
        SELECT r.result_type, r.value, r.metadata, r.created_at
        FROM recon_results r
        JOIN recon_scans s ON s.id = r.scan_id
        WHERE s.pipeline_run_id = ?
        ORDER BY r.created_at DESC
    """, (pipeline_id,)).fetchall()
    for r in rows:
        rtype = r["result_type"]
        if rtype not in findings:
            findings[rtype] = []
        meta = {}
        if r["metadata"]:
            try:
                meta = json.loads(r["metadata"])
            except Exception:
                meta = {}
        findings[rtype].append({
            "value": r["value"],
            "severity": meta.get("severity", "informational"),
            "reason": meta.get("reason", ""),
            "host": meta.get("host", ""),
        })

    try:
        domains_count = len(json.loads(target["domains"])) if target else 0
    except Exception:
        domains_count = 0

    conn.close()
    return jsonify({
        "pipeline_id": pipeline_id,
        "target_id": pipeline["target_id"],
        "target_name": target["program_handle"] if target else "",
        "program_handle": target["program_handle"] if target else "",
        "current_phase": pipeline["current_phase"],
        "max_phase": max_phase,
        "phase_name": phase_names_dict.get(pipeline["current_phase"], ""),
        "phase_status": pipeline["phase_status"],
        "domains_count": domains_count,
        "phases": phase_rows,
        "findings": findings,
    })


# ============================================================
# CUSTOM NUCLEI TEMPLATES — showcase + test runner
# ============================================================

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CUSTOM_TEMPLATES_DIR = os.path.join(_REPO_ROOT, "nuclei-templates", "custom")


def _parse_nuclei_yaml(filepath):
    """Parse a nuclei YAML template to extract id, name, severity, description, tags."""
    result = {"file": os.path.basename(filepath)}
    with open(filepath) as f:
        content = f.read()
    import re
    m = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["id"] = m.group(1).strip()
    m = re.search(r'name:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["name"] = m.group(1).strip()
    m = re.search(r'severity:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["severity"] = m.group(1).strip()
    m = re.search(r'tags:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["tags"] = [t.strip() for t in m.group(1).split(",")]
    # Extract description (multi-line block)
    m = re.search(r'description:\s*\|\s*\n((?:\s{4,}.+\n)+)', content)
    if m:
        desc_lines = m.group(1).strip().split("\n")
        result["description"] = "\n".join(l.strip() for l in desc_lines)
    m = re.search(r'author:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["author"] = m.group(1).strip()
    # Count HTTP requests / paths
    paths = re.findall(r'- "{{BaseURL}}[^"]*"', content)
    result["path_count"] = len(paths)
    # Count matchers
    matchers = re.findall(r'- type:\s*\w+', content)
    result["matcher_count"] = len(matchers)
    return result


@recon_bp.route("/custom-templates")
def custom_templates_page():
    """Showcase page for custom nuclei templates with test runner."""
    templates = []
    if os.path.isdir(CUSTOM_TEMPLATES_DIR):
        for fname in sorted(os.listdir(CUSTOM_TEMPLATES_DIR)):
            if fname.endswith(".yaml"):
                try:
                    info = _parse_nuclei_yaml(os.path.join(CUSTOM_TEMPLATES_DIR, fname))
                    templates.append(info)
                except Exception:
                    templates.append({"file": fname, "id": fname, "name": fname, "severity": "unknown"})

    # Get targets with completed pipelines (autopilot finished all 5 phases)
    conn = get_connection()
    targets = conn.execute("""
        SELECT DISTINCT t.id, t.program_handle,
               pr.updated_at as pipeline_completed,
               (SELECT COUNT(*) FROM recon_results r
                JOIN recon_scans s2 ON s2.id = r.scan_id
                WHERE s2.target_id = t.id) as total_results
        FROM recon_targets t
        JOIN pipeline_runs pr ON pr.target_id = t.id
        WHERE pr.phase_status = 'completed' AND pr.pipeline_type = 'web'
        GROUP BY t.id
        ORDER BY pr.updated_at DESC
        LIMIT 100
    """).fetchall()

    # Get recent test runs (nuclei scans using custom templates)
    # error field is repurposed to store which templates were selected
    test_runs = conn.execute("""
        SELECT s.id as scan_id, s.target_id, s.status, s.result_count,
               s.started_at, s.finished_at, t.program_handle,
               s.output_file, s.json_output, s.error as templates_used
        FROM recon_scans s
        JOIN recon_targets t ON t.id = s.target_id
        WHERE s.tool = 'nuclei-custom'
        ORDER BY s.created_at DESC
    """).fetchall()
    conn.close()

    return render_template("custom_templates.html",
                           templates=templates,
                           targets=[dict(t) for t in targets],
                           test_runs=[dict(r) for r in test_runs])


@recon_bp.route("/api/custom-templates")
def list_custom_templates():
    """JSON list of custom nuclei templates."""
    templates = []
    if os.path.isdir(CUSTOM_TEMPLATES_DIR):
        for fname in sorted(os.listdir(CUSTOM_TEMPLATES_DIR)):
            if fname.endswith(".yaml"):
                try:
                    templates.append(_parse_nuclei_yaml(
                        os.path.join(CUSTOM_TEMPLATES_DIR, fname)))
                except Exception:
                    pass
    return jsonify({"templates": templates, "count": len(templates)})


def _launch_custom_scan(conn, target_id, template_file=None):
    """Launch a custom nuclei template scan for a single target. Returns (scan_id, result_dict) or (None, error_dict)."""
    target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                          (target_id,)).fetchone()
    if not target:
        return None, {"error": "target %d not found" % target_id}

    httpx_scan = conn.execute("""
        SELECT * FROM recon_scans
        WHERE target_id = ? AND tool = 'httpx-toolkit' AND status = 'completed'
        ORDER BY finished_at DESC LIMIT 1
    """, (target_id,)).fetchone()
    if not httpx_scan:
        return None, {"error": "no completed httpx scan for target %d" % target_id}

    target_name = target["program_handle"]
    input_file = httpx_scan["json_output"] or httpx_scan["output_file"]
    if not input_file:
        return None, {"error": "no httpx output file for target %d" % target_id}

    template_dir = CUSTOM_TEMPLATES_DIR
    if template_file:
        template_path = os.path.join(CUSTOM_TEMPLATES_DIR, template_file)
        if not os.path.exists(template_path):
            return None, {"error": "template %s not found" % template_file}
        template_dir = template_path

    agent_data = {
        "tool": "nuclei",
        "target_name": target_name,
        "input_file": input_file,
        "options": {"custom_templates_only": template_dir},
    }

    agent_resp, status_code = _agent("post", "/scan/start", json=agent_data)
    if status_code != 201:
        return None, agent_resp

    pid = agent_resp["pid"]
    template_count = len([f for f in os.listdir(CUSTOM_TEMPLATES_DIR) if f.endswith(".yaml")]) if os.path.isdir(CUSTOM_TEMPLATES_DIR) else 0
    templates_meta = template_file if template_file else "All (%d)" % template_count

    conn.execute("""
        INSERT INTO recon_scans (target_id, tool, status, pid, output_file, json_output, error, started_at)
        VALUES (?, 'nuclei-custom', 'running', ?, ?, ?, ?, datetime('now'))
    """, (target_id, pid, agent_resp.get("output_file"), agent_resp.get("json_output"), templates_meta))
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    return scan_id, {
        "scan_id": scan_id, "pid": pid, "target": target_name,
        "templates": templates_meta, "status": "running",
    }


def _advance_custom_queue(conn):
    """Check for queued custom template scans and launch the next one if no heavy scan is running."""
    # Check if a nuclei-custom scan is already running
    running = conn.execute("""
        SELECT id FROM recon_scans WHERE tool = 'nuclei-custom' AND status = 'running' LIMIT 1
    """).fetchone()
    if running:
        return None  # already a scan in progress

    # Find next queued scan
    queued = conn.execute("""
        SELECT id, target_id, error as templates_meta FROM recon_scans
        WHERE tool = 'nuclei-custom' AND status = 'queued'
        ORDER BY id ASC LIMIT 1
    """).fetchone()
    if not queued:
        return None  # nothing queued

    scan_id = queued["id"]
    target_id = queued["target_id"]
    template_file = queued["templates_meta"] if queued["templates_meta"] and not queued["templates_meta"].startswith("All") else None

    launched_id, result = _launch_custom_scan(conn, target_id, template_file)
    if launched_id:
        # Delete the queued placeholder and use the newly created scan
        conn.execute("DELETE FROM recon_scans WHERE id = ?", (scan_id,))
        conn.commit()
        return result
    else:
        # Launch failed — mark queued scan as failed
        conn.execute("UPDATE recon_scans SET status = 'failed', finished_at = datetime('now') WHERE id = ?", (scan_id,))
        conn.commit()
        return result


@recon_bp.route("/api/custom-templates/test", methods=["POST"])
def run_custom_template_test():
    """Run custom nuclei templates against targets. Supports single or batch.

    Body: {"target_id": 123} or {"target_ids": [123, 456, 789]}
    Optional: "template": "specific-template.yaml"

    First target launches immediately. Remaining are queued and auto-advance
    when the previous scan completes (nuclei is a heavy tool, max 1 concurrent).
    """
    data = request.get_json()
    target_ids = data.get("target_ids", [])
    if not target_ids:
        single = data.get("target_id")
        if single:
            target_ids = [single]
    template_file = data.get("template")

    if not target_ids:
        return jsonify({"error": "target_id or target_ids required"}), 400

    conn = get_connection()
    template_count = len([f for f in os.listdir(CUSTOM_TEMPLATES_DIR) if f.endswith(".yaml")]) if os.path.isdir(CUSTOM_TEMPLATES_DIR) else 0
    templates_meta = template_file if template_file else "All (%d)" % template_count

    results = []
    first = True
    for tid in target_ids:
        if first:
            # Try to launch immediately
            scan_id, result = _launch_custom_scan(conn, tid, template_file)
            if scan_id:
                results.append(result)
                first = False
            elif "too many" in result.get("error", ""):
                # Heavy scan slot full — queue this one too
                conn.execute("""
                    INSERT INTO recon_scans (target_id, tool, status, error, created_at)
                    VALUES (?, 'nuclei-custom', 'queued', ?, datetime('now'))
                """, (tid, templates_meta))
                conn.commit()
                qid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                target = conn.execute("SELECT program_handle FROM recon_targets WHERE id = ?", (tid,)).fetchone()
                results.append({"scan_id": qid, "target": target["program_handle"] if target else str(tid),
                                "templates": templates_meta, "status": "queued"})
                first = False  # rest will also be queued
            else:
                results.append({"target_id": tid, "error": result.get("error", "launch failed")})
        else:
            # Queue remaining targets
            conn.execute("""
                INSERT INTO recon_scans (target_id, tool, status, error, created_at)
                VALUES (?, 'nuclei-custom', 'queued', ?, datetime('now'))
            """, (tid, templates_meta))
            conn.commit()
            qid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            target = conn.execute("SELECT program_handle FROM recon_targets WHERE id = ?", (tid,)).fetchone()
            results.append({"scan_id": qid, "target": target["program_handle"] if target else str(tid),
                            "templates": templates_meta, "status": "queued"})

    conn.close()

    if len(results) == 1:
        return jsonify(results[0]), 201
    return jsonify({"scans": results, "launched": 1, "queued": len(results) - 1}), 201


@recon_bp.route("/api/custom-templates/results/<int:scan_id>")
def custom_template_results(scan_id):
    """Get results from a custom template test run."""
    conn = get_connection()
    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ? AND tool = 'nuclei-custom'",
                        (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "scan not found"}), 404

    # If scan is still "running", check agent and try to recover
    if scan["status"] == "running" and scan["pid"]:
        agent_resp, agent_status = _agent("get", f"/scan/{scan['pid']}/status")
        agent_scan_status = agent_resp.get("status", "")

        if agent_scan_status == "completed" or agent_status == 404:
            # Scan finished (or agent lost it after restart) — ingest from disk
            target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                                  (scan["target_id"],)).fetchone()
            if target:
                target_name = target["program_handle"]
                json_file = scan["json_output"]
                if json_file:
                    file_resp, _ = _agent("post", "/results/from-file", json={
                        "target_name": target_name,
                        "filename": json_file,
                        "tool": "nuclei",
                    })
                    parsed = file_resp.get("results", [])
                    for r in parsed:
                        conn.execute("""
                            INSERT INTO recon_results (scan_id, result_type, value, metadata)
                            VALUES (?, ?, ?, ?)
                        """, (scan_id, "vulnerability",
                              r.get("value", r.get("matched-at", "")),
                              json.dumps(r)))
                    conn.execute("""
                        UPDATE recon_scans SET status = 'completed',
                               result_count = ?, finished_at = datetime('now')
                        WHERE id = ?
                    """, (len(parsed), scan_id))
                    conn.commit()
                    # Re-fetch updated scan
                    scan = conn.execute("SELECT * FROM recon_scans WHERE id = ?",
                                        (scan_id,)).fetchone()

    # If scan just completed, try to advance the queue
    if scan["status"] == "completed":
        _advance_custom_queue(conn)

    results = conn.execute("""
        SELECT * FROM recon_results WHERE scan_id = ?
        ORDER BY id
    """, (scan_id,)).fetchall()
    conn.close()

    status_data = {"status": scan["status"], "result_count": scan["result_count"] or 0}

    return jsonify({
        "scan_id": scan_id,
        "status": status_data,
        "target_id": scan["target_id"],
        "started_at": scan["started_at"],
        "finished_at": scan["finished_at"],
        "results": [dict(r) for r in results],
    })


# ---------------------------------------------------------------------------
# Background phase-advance reconciler
# ---------------------------------------------------------------------------
# Pre-existing bug discovered 2026-05-14: the dashboard route /recon/autopilot
# was the only place that ran "stuck pipeline" recovery, and it only handled
# web pipelines (not oracle).  Pipelines whose phase-N tools all finished but
# whose orchestrator never received the completion signal (agent restart,
# missed reaper tick, etc.) would freeze at phase_status='running' until a
# human opened the dashboard.  This blocks autopilot from starting new
# pipelines.  Run the same recovery from a background thread, every 60s,
# for BOTH pipeline types.

RECONCILER_INTERVAL_S = 60
_reconciler_started = False
_reconciler_lock = threading.Lock()


def _auto_approve_awaiting(conn, pipeline_id, program_handle):
    """If pipeline is in 'awaiting_approval' with auto_approve=1, advance it.

    Called by the reconciler so deploys/agent-restarts that kick pipelines
    into awaiting_approval don't require manual intervention. Mirrors the
    happy path of pipeline_approve() but without the request/response.
    """
    pipeline = conn.execute(
        "SELECT * FROM pipeline_runs WHERE id = ?", (pipeline_id,)
    ).fetchone()
    if not pipeline:
        return False
    if pipeline["phase_status"] != "awaiting_approval":
        return False
    auto = pipeline["auto_approve"] if "auto_approve" in pipeline.keys() else 1
    if not auto:
        return False  # paused intentionally; respect the user

    pipeline_type = _pipeline_type(pipeline)
    phases_dict = _phases_for(pipeline_type)
    max_phase = _max_phase_for(pipeline_type)

    next_phase = pipeline["current_phase"] + 1
    # Skip empty phases
    while next_phase <= max_phase and not phases_dict.get(next_phase):
        next_phase += 1

    if next_phase > max_phase:
        conn.execute("""
            UPDATE pipeline_runs SET phase_status = 'completed',
            current_phase = ?, updated_at = datetime('now') WHERE id = ?
        """, (max_phase, pipeline_id))
        conn.commit()
        # Release netns since pipeline is now terminal
        _release_egress_netns(pipeline_id)
        print("  [reconciler:auto-approve] P%d %s → completed (no more phases)" % (
            pipeline_id, program_handle))
        return True

    # Advance to next phase, launch its tools
    conn.execute("""
        UPDATE pipeline_runs SET current_phase = ?, phase_status = 'running',
        updated_at = datetime('now') WHERE id = ?
    """, (next_phase, pipeline_id))
    conn.commit()

    target = conn.execute(
        "SELECT * FROM recon_targets WHERE id = ?", (pipeline["target_id"],)
    ).fetchone()
    if target:
        _launch_phase_tools(conn, pipeline_id, target, next_phase)
    print("  [reconciler:auto-approve] P%d %s → phase %d" % (
        pipeline_id, program_handle, next_phase))
    return True


def _reconciler_tick():
    """One iteration:
       1. Auto-approve any pipelines stuck in 'awaiting_approval' with auto_approve=1
          (e.g. after agent restart kicked them out of 'running').
       2. Advance any pipelines in 'running' whose current phase is complete.
    """
    try:
        conn = get_connection()
        # 1. Auto-approve stragglers first so they re-enter 'running' for step 2.
        awaiting = conn.execute("""
            SELECT p.id, t.program_handle
            FROM pipeline_runs p
            JOIN recon_targets t ON t.id = p.target_id
            WHERE p.phase_status = 'awaiting_approval'
              AND (p.auto_approve IS NULL OR p.auto_approve = 1)
        """).fetchall()
        for a in awaiting:
            try:
                _auto_approve_awaiting(conn, a["id"], a["program_handle"])
            except Exception as e:
                print("  [reconciler:auto-approve] P%d failed: %s" % (a["id"], e))

        # 2. Standard phase advancement for 'running' pipelines.
        stuck = conn.execute("""
            SELECT p.id, t.program_handle
            FROM pipeline_runs p
            JOIN recon_targets t ON t.id = p.target_id
            WHERE p.phase_status = 'running'
        """).fetchall()
        for s in stuck:
            for _ in range(5):  # max 5 phases per tick
                prev = conn.execute(
                    "SELECT current_phase, phase_status FROM pipeline_runs WHERE id = ?",
                    (s["id"],)
                ).fetchone()
                if not prev or prev["phase_status"] != "running":
                    break
                _check_phase_completion(conn, s["id"], s["program_handle"])
                after = conn.execute(
                    "SELECT current_phase, phase_status FROM pipeline_runs WHERE id = ?",
                    (s["id"],)
                ).fetchone()
                if (after["current_phase"] == prev["current_phase"]
                        and after["phase_status"] == prev["phase_status"]):
                    break  # no progress, give up for this tick

        # 3. Cross-phase pending retry. _check_phase_completion only re-launches
        # pending scans in the pipeline's current_phase, but injections can
        # leave pending records in earlier or later phases (e.g. inject
        # phase-2 naabu into a pipeline that's already on phase 3, or inject
        # phase-4 arjun whose deps in phase 3 are still running). Walk each
        # phase that has pending records and call _launch_phase_tools with
        # that explicit phase number — its 429-retry path will pop the
        # pending row and re-attempt, idempotently.
        cross_phase = conn.execute("""
            SELECT DISTINCT s.pipeline_run_id, s.pipeline_phase, t.id as target_id
            FROM recon_scans s
            JOIN pipeline_runs p ON p.id = s.pipeline_run_id
            JOIN recon_targets t ON t.id = p.target_id
            WHERE s.status = 'pending'
              AND p.phase_status = 'running'
              AND s.pipeline_phase != p.current_phase
        """).fetchall()
        for row in cross_phase:
            try:
                target = conn.execute("SELECT * FROM recon_targets WHERE id = ?",
                                      (row["target_id"],)).fetchone()
                if target:
                    _launch_phase_tools(conn, row["pipeline_run_id"], target,
                                        row["pipeline_phase"])
            except Exception as e:
                print("  [reconciler:cross-phase] P%d phase=%d failed: %s" % (
                    row["pipeline_run_id"], row["pipeline_phase"], e))

        conn.close()
    except Exception as e:
        print("[reconciler] error: %s" % e)


def _reconciler_loop():
    print("[reconciler] background phase-advance thread started (interval=%ds)"
          % RECONCILER_INTERVAL_S)
    while True:
        time.sleep(RECONCILER_INTERVAL_S)
        _reconciler_tick()


def start_reconciler():
    """Idempotently start the reconciler thread.  Called by web.py at boot."""
    global _reconciler_started
    with _reconciler_lock:
        if _reconciler_started:
            return
        _reconciler_started = True
    t = threading.Thread(target=_reconciler_loop, daemon=True, name="reconciler")
    t.start()
