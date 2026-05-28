"""Hacktivity intelligence — browse and analyze disclosed HackerOne reports."""

import json
from flask import Blueprint, render_template, request, jsonify, abort
from app.db import get_connection

hacktivity_bp = Blueprint("hacktivity", __name__)
PER_PAGE = 50

CATEGORIES = [
    "xss", "sqli", "ssrf", "idor", "auth_bypass", "info_disclosure",
    "rce", "csrf", "open_redirect", "subdomain_takeover", "injection_other",
    "business_logic", "cryptography", "misconfiguration", "dos",
    "race_condition", "file_upload", "deserialization", "mobile", "other",
]

CATEGORY_LABELS = {
    "xss": "Cross-Site Scripting",
    "sqli": "SQL Injection",
    "ssrf": "Server-Side Request Forgery",
    "idor": "Insecure Direct Object Reference",
    "auth_bypass": "Authentication/Authorization Bypass",
    "info_disclosure": "Information Disclosure",
    "rce": "Remote Code Execution",
    "csrf": "Cross-Site Request Forgery",
    "open_redirect": "Open Redirect",
    "subdomain_takeover": "Subdomain Takeover",
    "injection_other": "Other Injection",
    "business_logic": "Business Logic",
    "cryptography": "Cryptography / TLS",
    "misconfiguration": "Misconfiguration",
    "dos": "Denial of Service",
    "race_condition": "Race Condition",
    "file_upload": "File Upload",
    "deserialization": "Insecure Deserialization",
    "mobile": "Mobile",
    "other": "Other",
}


@hacktivity_bp.route("/hacktivity")
def hacktivity_dashboard():
    conn = get_connection()

    # Check if table exists
    table_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='hacktivity_reports'"
    ).fetchone()
    if not table_exists:
        conn.close()
        return render_template("hacktivity.html", stats={}, categories=[], severities=[],
                               top_programs=[], top_bounties=[], recent=[], category_labels=CATEGORY_LABELS)

    total = conn.execute("SELECT COUNT(*) FROM hacktivity_reports").fetchone()[0]
    analyzed = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE analyzed_at IS NOT NULL").fetchone()[0]
    with_bounty = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]
    total_bounty = conn.execute("SELECT COALESCE(SUM(bounty_amount), 0) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]
    avg_bounty = conn.execute("SELECT COALESCE(AVG(bounty_amount), 0) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]

    stats = {
        "total": total,
        "analyzed": analyzed,
        "with_bounty": with_bounty,
        "total_bounty": total_bounty,
        "avg_bounty": avg_bounty,
    }

    categories = conn.execute("""
        SELECT category, COUNT(*) as cnt,
               COALESCE(SUM(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE 0 END), 0) as total_b,
               COALESCE(AVG(CASE WHEN bounty_amount > 0 THEN bounty_amount END), 0) as avg_b
        FROM hacktivity_reports WHERE category IS NOT NULL
        GROUP BY category ORDER BY cnt DESC
    """).fetchall()

    severities = conn.execute("""
        SELECT COALESCE(severity_rating, 'unknown') as sev, COUNT(*) as cnt,
               COALESCE(SUM(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE 0 END), 0) as total_b
        FROM hacktivity_reports GROUP BY severity_rating ORDER BY cnt DESC
    """).fetchall()

    top_programs = conn.execute("""
        SELECT team_handle, team_name, COUNT(*) as cnt,
               COALESCE(SUM(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE 0 END), 0) as total_b
        FROM hacktivity_reports GROUP BY team_handle ORDER BY cnt DESC LIMIT 15
    """).fetchall()

    top_bounties = conn.execute("""
        SELECT id, title, team_handle, severity_rating, bounty_amount, category
        FROM hacktivity_reports WHERE bounty_amount > 0
        ORDER BY bounty_amount DESC LIMIT 15
    """).fetchall()

    recent = conn.execute("""
        SELECT id, title, team_handle, severity_rating, bounty_amount, category, disclosed_at
        FROM hacktivity_reports ORDER BY disclosed_at DESC LIMIT 20
    """).fetchall()

    conn.close()
    return render_template("hacktivity.html", stats=stats, categories=categories,
                           severities=severities, top_programs=top_programs,
                           top_bounties=top_bounties, recent=recent,
                           category_labels=CATEGORY_LABELS)


@hacktivity_bp.route("/hacktivity/reports")
def hacktivity_reports():
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "all")
    category = request.args.get("category", "all")
    analyzed = request.args.get("analyzed", "all")
    page = max(1, request.args.get("page", 1, type=int))

    conn = get_connection()
    conditions = []
    params = []

    if q:
        conditions.append("(title LIKE ? OR team_handle LIKE ? OR team_name LIKE ?)")
        params.extend(["%" + q + "%"] * 3)
    if severity != "all":
        conditions.append("severity_rating = ?")
        params.append(severity)
    if category != "all":
        conditions.append("category = ?")
        params.append(category)
    if analyzed == "yes":
        conditions.append("analyzed_at IS NOT NULL")
    elif analyzed == "no":
        conditions.append("analyzed_at IS NULL")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    total = conn.execute("SELECT COUNT(*) FROM hacktivity_reports " + where, params).fetchone()[0]
    offset = (page - 1) * PER_PAGE
    reports = conn.execute("""
        SELECT id, title, team_handle, severity_rating, bounty_amount,
               category, disclosed_at, analyzed_at
        FROM hacktivity_reports %s
        ORDER BY disclosed_at DESC NULLS LAST
        LIMIT ? OFFSET ?
    """ % where, params + [PER_PAGE, offset]).fetchall()

    # Get distinct values for filter dropdowns
    all_categories = conn.execute("""
        SELECT DISTINCT category FROM hacktivity_reports
        WHERE category IS NOT NULL ORDER BY category
    """).fetchall()
    all_severities = conn.execute("""
        SELECT DISTINCT severity_rating FROM hacktivity_reports
        WHERE severity_rating IS NOT NULL ORDER BY severity_rating
    """).fetchall()

    conn.close()
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render_template("hacktivity_reports.html",
        reports=reports, q=q, severity=severity, category=category,
        analyzed=analyzed, page=page, total=total, total_pages=total_pages,
        all_categories=[r[0] for r in all_categories],
        all_severities=[r[0] for r in all_severities],
        category_labels=CATEGORY_LABELS)


@hacktivity_bp.route("/hacktivity/reports/<report_id>")
def hacktivity_report_detail(report_id):
    conn = get_connection()
    report = conn.execute("SELECT * FROM hacktivity_reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        conn.close()
        abort(404)

    tags = []
    if report["tags"]:
        try:
            tags = json.loads(report["tags"])
        except (json.JSONDecodeError, TypeError):
            pass

    conn.close()
    return render_template("hacktivity_report.html", report=report, tags=tags,
                           category_labels=CATEGORY_LABELS)


# --- JSON API ---

@hacktivity_bp.route("/api/hacktivity/stats")
def api_hacktivity_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM hacktivity_reports").fetchone()[0]
    analyzed = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE analyzed_at IS NOT NULL").fetchone()[0]
    with_bounty = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]
    total_bounty = conn.execute("SELECT COALESCE(SUM(bounty_amount), 0) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]

    conn.close()
    return jsonify({
        "total": total, "analyzed": analyzed,
        "with_bounty": with_bounty, "total_bounty": total_bounty,
    })


@hacktivity_bp.route("/api/hacktivity/categories")
def api_hacktivity_categories():
    conn = get_connection()
    rows = conn.execute("""
        SELECT category, COUNT(*) as count,
               COALESCE(AVG(CASE WHEN bounty_amount > 0 THEN bounty_amount END), 0) as avg_bounty,
               COALESCE(SUM(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE 0 END), 0) as total_bounty
        FROM hacktivity_reports WHERE category IS NOT NULL
        GROUP BY category ORDER BY count DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@hacktivity_bp.route("/api/hacktivity/reports/<report_id>/analyze", methods=["POST"])
def api_analyze_report(report_id):
    """API endpoint to save Claude's analysis for a report."""
    conn = get_connection()
    report = conn.execute("SELECT id FROM hacktivity_reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        conn.close()
        return jsonify({"error": "report not found"}), 404

    data = request.get_json()
    if not data:
        conn.close()
        return jsonify({"error": "JSON body required"}), 400

    cat = data.get("category", "").lower()
    if cat not in CATEGORIES:
        conn.close()
        return jsonify({"error": "invalid category", "valid": CATEGORIES}), 400

    conn.execute("""
        UPDATE hacktivity_reports
        SET category = ?, tags = ?, summary = ?, attack_vector = ?,
            impact = ?, complexity = ?, takeaways = ?,
            analyzed_at = datetime('now')
        WHERE id = ?
    """, (
        cat,
        json.dumps(data.get("tags", [])),
        data.get("summary", ""),
        data.get("attack_vector", ""),
        data.get("impact", ""),
        data.get("complexity", ""),
        data.get("takeaways", ""),
        report_id,
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "report_id": report_id, "category": cat})
