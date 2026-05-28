"""Fetch disclosed HackerOne hacktivity reports and store in local DB.

Two-step ingestion:
  1. List disclosed reports from HackerOne public GraphQL (no auth needed)
  2. Fetch individual report details (title, severity, weakness, team, reporter)

Stdlib-only so it can run on the Kali host alongside recon_agent.py.

Usage:
    python3 ingest_hacktivity.py                     # fetch ~500 new disclosed reports
    python3 ingest_hacktivity.py --limit 1000         # fetch up to 1000
    python3 ingest_hacktivity.py --analyze             # interactive Claude analysis mode
    python3 ingest_hacktivity.py --analyze --batch 20  # analyze 20 reports per session
    python3 ingest_hacktivity.py --stats               # show ingestion/analysis stats
"""

import json
import os
import sqlite3
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.environ.get("DB_PATH", os.path.join(_REPO_ROOT, "bounties.db"))
GRAPHQL_URL = "https://hackerone.com/graphql"

# Valid categories for Claude analysis
CATEGORIES = [
    "xss", "sqli", "ssrf", "idor", "auth_bypass", "info_disclosure",
    "rce", "csrf", "open_redirect", "subdomain_takeover", "injection_other",
    "business_logic", "cryptography", "misconfiguration", "dos",
    "race_condition", "file_upload", "deserialization", "mobile", "other",
]


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def graphql_query(query, retries=3):
    body = json.dumps({"query": query}).encode()
    req = Request(GRAPHQL_URL, data=body, headers={"Content-Type": "application/json"})
    for attempt in range(retries):
        try:
            resp = urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            if data.get("errors"):
                print("  GraphQL error: %s" % data["errors"][0].get("message", "unknown"))
                return None
            return data.get("data")
        except HTTPError as e:
            if e.code == 429:
                wait = min(30 * (attempt + 1), 120)
                print("  Rate limited, waiting %ds..." % wait)
                time.sleep(wait)
            else:
                print("  HTTP %d: %s" % (e.code, e.reason))
                if attempt < retries - 1:
                    time.sleep(5)
        except URLError as e:
            print("  Network error: %s" % e.reason)
            if attempt < retries - 1:
                time.sleep(5)
    return None


def fetch_hacktivity_page(offset=0, page_size=100):
    """Fetch a page of disclosed hacktivity items via GraphQL search."""
    query = """query {
        search(index: CompleteHacktivityReportIndex,
               query_string: "disclosed:true",
               size: %d,
               from: %d,
               sort: {field: "latest_disclosable_activity_at", direction: DESC}) {
            total_count
            edges {
                node {
                    ... on HacktivityDocument {
                        _id severity_rating cwe total_awarded_amount
                        latest_disclosable_activity_at
                    }
                }
            }
        }
    }""" % (page_size, offset)
    return graphql_query(query)


def fetch_report_detail(report_id):
    """Fetch individual report details via GraphQL."""
    query = """query {
        report(id: %s) {
            _id title substate
            severity { rating score }
            weakness { name }
            vulnerability_information
            team { handle name }
            disclosed_at
            created_at
            reporter { username }
            bounties(first: 1) { edges { node { amount } } }
        }
    }""" % report_id
    return graphql_query(query)


def upsert_report(conn, report_id, listing_data, detail_data):
    """Insert or update a hacktivity report. Never overwrites Claude analysis."""
    existing = conn.execute("SELECT id, analyzed_at FROM hacktivity_reports WHERE id = ?",
                            (report_id,)).fetchone()
    if existing:
        return False  # already have it

    report = detail_data.get("report", {}) if detail_data else {}
    severity = report.get("severity") or {}
    bounties = report.get("bounties", {}).get("edges", [])
    bounty_amount = bounties[0]["node"]["amount"] if bounties else listing_data.get("total_awarded_amount")
    reporter = report.get("reporter") or {}

    conn.execute("""
        INSERT OR IGNORE INTO hacktivity_reports
        (id, title, vulnerability_information, severity_rating, severity_score,
         cwe, weakness_name, team_handle, team_name, reporter_username,
         state, substate, bounty_amount, disclosed_at, created_at, url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_id,
        report.get("title", ""),
        report.get("vulnerability_information"),
        severity.get("rating") or (listing_data.get("severity_rating") or "").lower() or None,
        severity.get("score"),
        listing_data.get("cwe"),
        (report.get("weakness") or {}).get("name"),
        (report.get("team") or {}).get("handle"),
        (report.get("team") or {}).get("name"),
        reporter.get("username"),
        "disclosed",
        report.get("substate"),
        bounty_amount,
        report.get("disclosed_at") or listing_data.get("latest_disclosable_activity_at"),
        report.get("created_at"),
        "https://hackerone.com/reports/%s" % report_id,
    ))
    return True


def run_ingestion(limit=500):
    """Fetch disclosed reports from HackerOne hacktivity."""
    conn = get_connection()

    # Ensure table exists
    conn.execute("""CREATE TABLE IF NOT EXISTS hacktivity_reports (
        id TEXT PRIMARY KEY, title TEXT, vulnerability_information TEXT,
        severity_rating TEXT, severity_score REAL, cwe TEXT, weakness_name TEXT,
        team_handle TEXT, team_name TEXT, reporter_username TEXT, state TEXT,
        substate TEXT, bounty_amount REAL, currency TEXT DEFAULT 'USD',
        disclosed_at TEXT, created_at TEXT, url TEXT, category TEXT, tags TEXT,
        summary TEXT, attack_vector TEXT, impact TEXT, complexity TEXT,
        takeaways TEXT, analyzed_at TEXT,
        fetched_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()

    existing_ids = {row[0] for row in conn.execute("SELECT id FROM hacktivity_reports").fetchall()}
    print("Existing reports in DB: %d" % len(existing_ids))

    fetched = 0
    inserted = 0
    consecutive_known = 0
    # Start past known reports to avoid re-scanning the same window
    offset = len(existing_ids) if existing_ids else 0
    page_num = 0
    page_size = 100
    target_new = max(0, limit - len(existing_ids))
    if target_new == 0:
        print("Already have %d reports (limit=%d). Use a higher --limit." % (len(existing_ids), limit))
        conn.close()
        return
    print("Starting from offset %d — need %d more to reach %d total" % (offset, target_new, limit))

    while inserted < target_new:
        page_num += 1
        batch = min(page_size, target_new - inserted)
        print("\nPage %d (offset %d, batch %d)..." % (page_num, offset, batch))

        data = fetch_hacktivity_page(offset=offset, page_size=batch)
        if not data or "search" not in data:
            print("  Failed to fetch page, stopping.")
            break

        search = data["search"]
        edges = search.get("edges", [])
        if not edges:
            print("  No more results.")
            break

        total = search.get("total_count", "?")
        if page_num == 1:
            print("Total disclosed reports available: %s" % total)

        for edge in edges:
            node = edge.get("node", {})
            report_id = node.get("_id")
            if not report_id:
                continue

            fetched += 1

            if report_id in existing_ids:
                consecutive_known += 1
                if consecutive_known >= 50:
                    print("\n  50 consecutive known reports — caught up.")
                    break
                continue
            else:
                consecutive_known = 0

            # Fetch full report detail
            time.sleep(0.3)  # be nice to GraphQL
            detail = fetch_report_detail(report_id)

            if upsert_report(conn, report_id, node, detail):
                inserted += 1
                report = (detail or {}).get("report", {})
                title = report.get("title", "?")[:60]
                sev = node.get("severity_rating", "?")
                print("  [%d] #%s (%s) %s" % (inserted, report_id, sev, title))

            if inserted % 50 == 0 and inserted > 0:
                conn.commit()
                print("  --- committed %d reports ---" % inserted)

        if consecutive_known >= 50:
            break

        if len(edges) < batch:
            print("\nReached last page.")
            break

        offset += len(edges)
        time.sleep(1)  # rate limit between pages

    conn.commit()
    conn.close()
    print("\nDone. Fetched %d, inserted %d new reports." % (fetched, inserted))


def analyze_interactive(batch_size=10):
    """Interactive mode: print unanalyzed reports for Claude to categorize."""
    conn = get_connection()
    reports = conn.execute("""
        SELECT id, title, severity_rating, severity_score, cwe, weakness_name,
               team_handle, team_name, reporter_username, bounty_amount,
               vulnerability_information, disclosed_at
        FROM hacktivity_reports
        WHERE analyzed_at IS NULL
        ORDER BY bounty_amount DESC NULLS LAST, disclosed_at DESC
        LIMIT ?
    """, (batch_size,)).fetchall()

    if not reports:
        print("No unanalyzed reports. Run ingestion first or all reports are analyzed.")
        conn.close()
        return

    total_unanalyzed = conn.execute(
        "SELECT COUNT(*) FROM hacktivity_reports WHERE analyzed_at IS NULL"
    ).fetchone()[0]
    print("Unanalyzed reports: %d (showing batch of %d)\n" % (total_unanalyzed, len(reports)))
    print("Valid categories: %s\n" % ", ".join(CATEGORIES))

    for i, r in enumerate(reports):
        print("=" * 80)
        print("Report %d/%d  |  ID: %s  |  %s" % (i + 1, len(reports), r["id"],
              r["url"] if r.get("url") else "https://hackerone.com/reports/%s" % r["id"]))
        print("=" * 80)
        print("Title:    %s" % r["title"])
        print("Program:  %s (%s)" % (r["team_name"] or "?", r["team_handle"] or "?"))
        print("Severity: %s (CVSS: %s)" % (r["severity_rating"] or "?", r["severity_score"] or "?"))
        print("CWE:      %s" % (r["cwe"] or r["weakness_name"] or "?"))
        print("Bounty:   $%s" % r["bounty_amount"] if r["bounty_amount"] else "Bounty:   none")
        print("Reporter: %s" % (r["reporter_username"] or "?"))
        print("Disclosed: %s" % (r["disclosed_at"] or "?"))
        if r["vulnerability_information"]:
            print("\n--- Vulnerability Details ---")
            # Truncate very long reports
            vi = r["vulnerability_information"]
            if len(vi) > 3000:
                print(vi[:3000])
                print("\n... [truncated, %d chars total]" % len(vi))
            else:
                print(vi)
        print("\n--- Provide analysis JSON (or 'skip' / 'quit') ---")

        try:
            lines = []
            while True:
                line = input()
                stripped = line.strip()
                if stripped.lower() == "skip":
                    print("Skipped.\n")
                    break
                if stripped.lower() == "quit":
                    conn.commit()
                    conn.close()
                    print("Saved and quit.")
                    return
                lines.append(line)
                # Try to parse accumulated input as JSON
                text = "\n".join(lines)
                try:
                    analysis = json.loads(text)
                    # Validate
                    cat = analysis.get("category", "").lower()
                    if cat not in CATEGORIES:
                        print("Invalid category '%s'. Valid: %s" % (cat, ", ".join(CATEGORIES)))
                        lines = []
                        continue
                    # Write to DB
                    conn.execute("""
                        UPDATE hacktivity_reports
                        SET category = ?, tags = ?, summary = ?, attack_vector = ?,
                            impact = ?, complexity = ?, takeaways = ?,
                            analyzed_at = datetime('now')
                        WHERE id = ?
                    """, (
                        cat,
                        json.dumps(analysis.get("tags", [])),
                        analysis.get("summary", ""),
                        analysis.get("attack_vector", ""),
                        analysis.get("impact", ""),
                        analysis.get("complexity", ""),
                        analysis.get("takeaways", ""),
                        r["id"],
                    ))
                    conn.commit()
                    print("Saved analysis for report #%s (%s)\n" % (r["id"], cat))
                    break
                except json.JSONDecodeError:
                    continue  # keep reading lines
        except EOFError:
            break

    conn.close()
    print("\nBatch complete.")


def print_stats():
    """Print ingestion and analysis statistics."""
    conn = get_connection()

    total = conn.execute("SELECT COUNT(*) FROM hacktivity_reports").fetchone()[0]
    if total == 0:
        print("No hacktivity reports in DB. Run: python3 ingest_hacktivity.py")
        conn.close()
        return

    analyzed = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE analyzed_at IS NOT NULL").fetchone()[0]
    with_bounty = conn.execute("SELECT COUNT(*) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]
    total_bounty = conn.execute("SELECT COALESCE(SUM(bounty_amount), 0) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]
    avg_bounty = conn.execute("SELECT COALESCE(AVG(bounty_amount), 0) FROM hacktivity_reports WHERE bounty_amount > 0").fetchone()[0]

    print("=== Hacktivity Report Stats ===")
    print("Total reports:    %d" % total)
    print("Analyzed:         %d / %d (%.0f%%)" % (analyzed, total, 100 * analyzed / total if total else 0))
    print("With bounty:      %d" % with_bounty)
    print("Total bounties:   $%s" % "{:,.0f}".format(total_bounty))
    print("Avg bounty:       $%s" % "{:,.0f}".format(avg_bounty))

    print("\n--- By Severity ---")
    for row in conn.execute("""
        SELECT COALESCE(severity_rating, 'unknown') as sev, COUNT(*) as cnt,
               COALESCE(SUM(bounty_amount), 0) as total_b
        FROM hacktivity_reports
        GROUP BY severity_rating ORDER BY cnt DESC
    """).fetchall():
        print("  %-10s %4d reports  $%s" % (row["sev"], row["cnt"], "{:,.0f}".format(row["total_b"])))

    if analyzed > 0:
        print("\n--- By Category (analyzed only) ---")
        for row in conn.execute("""
            SELECT category, COUNT(*) as cnt,
                   COALESCE(SUM(bounty_amount), 0) as total_b,
                   COALESCE(AVG(bounty_amount), 0) as avg_b
            FROM hacktivity_reports
            WHERE category IS NOT NULL
            GROUP BY category ORDER BY cnt DESC
        """).fetchall():
            print("  %-20s %4d reports  avg $%s  total $%s" % (
                row["category"], row["cnt"],
                "{:,.0f}".format(row["avg_b"]),
                "{:,.0f}".format(row["total_b"])))

    print("\n--- Top 10 Programs ---")
    for row in conn.execute("""
        SELECT team_handle, team_name, COUNT(*) as cnt,
               COALESCE(SUM(bounty_amount), 0) as total_b
        FROM hacktivity_reports
        GROUP BY team_handle ORDER BY cnt DESC LIMIT 10
    """).fetchall():
        print("  %-25s %4d reports  $%s" % (
            row["team_handle"] or "?", row["cnt"], "{:,.0f}".format(row["total_b"])))

    conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--stats" in args:
        print_stats()
    elif "--analyze" in args:
        batch = 10
        for i, a in enumerate(args):
            if a == "--batch" and i + 1 < len(args):
                batch = int(args[i + 1])
        analyze_interactive(batch)
    else:
        limit = 500
        for i, a in enumerate(args):
            if a == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
        run_ingestion(limit)
