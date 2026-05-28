"""Browse and query the local bounty database."""

import argparse
import json
from app.db import get_connection, init_db


def list_programs(bounty_only=True, limit=50):
    conn = get_connection()
    where = "WHERE offers_bounties = 1" if bounty_only else ""
    rows = conn.execute(f"""
        SELECT p.handle, p.name, p.submission_state, p.offers_bounties,
               COUNT(s.id) as scope_count,
               p.url
        FROM programs p
        LEFT JOIN scopes s ON s.program_id = p.id AND s.eligible_for_bounty = 1
        {where}
        GROUP BY p.id
        ORDER BY scope_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    print(f"{'Handle':<30} {'Name':<35} {'State':<12} {'Scopes':>6}  URL")
    print("-" * 120)
    for r in rows:
        print(f"{r['handle']:<30} {(r['name'] or '')[:34]:<35} "
              f"{r['submission_state']:<12} {r['scope_count']:>6}  {r['url']}")
    print(f"\nTotal: {len(rows)} programs")


def search_scopes(query, asset_type=None):
    conn = get_connection()
    params = [f"%{query}%"]
    type_filter = ""
    if asset_type:
        type_filter = "AND s.asset_type = ?"
        params.append(asset_type)

    rows = conn.execute(f"""
        SELECT p.handle, p.name, s.asset_type, s.asset_identifier,
               s.eligible_for_bounty, s.max_severity, s.instruction
        FROM scopes s
        JOIN programs p ON p.id = s.program_id
        WHERE s.asset_identifier LIKE ? {type_filter}
          AND s.eligible_for_bounty = 1
        ORDER BY p.handle
    """, params).fetchall()
    conn.close()

    print(f"{'Program':<25} {'Type':<12} {'Asset':<45} {'Severity':<10}")
    print("-" * 100)
    for r in rows:
        print(f"{r['handle']:<25} {r['asset_type']:<12} "
              f"{r['asset_identifier'][:44]:<45} {r['max_severity'] or '':<10}")
    print(f"\nFound: {len(rows)} in-scope assets")


def show_program(handle):
    conn = get_connection()
    prog = conn.execute(
        "SELECT * FROM programs WHERE handle = ?", (handle,)
    ).fetchone()
    if not prog:
        print(f"Program '{handle}' not found.")
        return

    scopes = conn.execute("""
        SELECT * FROM scopes WHERE program_id = ? AND eligible_for_bounty = 1
        ORDER BY asset_type
    """, (prog["id"],)).fetchall()
    conn.close()

    print(f"\n  Program: {prog['name']} ({prog['handle']})")
    print(f"  URL: {prog['url']}")
    print(f"  State: {prog['submission_state']}")
    print(f"  Bounties: {'Yes' if prog['offers_bounties'] else 'No'}")
    print(f"\n  Bounty-eligible scopes ({len(scopes)}):")
    print(f"  {'Type':<12} {'Asset':<50} {'Severity':<10}")
    print(f"  {'-'*75}")
    for s in scopes:
        print(f"  {s['asset_type']:<12} {s['asset_identifier'][:49]:<50} "
              f"{s['max_severity'] or '':<10}")
        if s["instruction"]:
            print(f"  {'':>12} Note: {s['instruction'][:70]}")


def export_for_agent(handle=None):
    """Export bounty data as JSON for AI agent consumption."""
    conn = get_connection()
    if handle:
        programs = conn.execute(
            "SELECT * FROM programs WHERE handle = ? AND offers_bounties = 1",
            (handle,)
        ).fetchall()
    else:
        programs = conn.execute(
            "SELECT * FROM programs WHERE offers_bounties = 1"
        ).fetchall()

    result = []
    for p in programs:
        scopes = conn.execute("""
            SELECT asset_type, asset_identifier, max_severity, instruction
            FROM scopes WHERE program_id = ? AND eligible_for_bounty = 1
        """, (p["id"],)).fetchall()
        result.append({
            "handle": p["handle"],
            "name": p["name"],
            "url": p["url"],
            "submission_state": p["submission_state"],
            "scopes": [dict(s) for s in scopes],
        })
    conn.close()
    print(json.dumps(result, indent=2))


def stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM programs").fetchone()["c"]
    bounty = conn.execute("SELECT COUNT(*) as c FROM programs WHERE offers_bounties = 1").fetchone()["c"]
    scopes = conn.execute("SELECT COUNT(*) as c FROM scopes WHERE eligible_for_bounty = 1").fetchone()["c"]
    types = conn.execute("""
        SELECT asset_type, COUNT(*) as c FROM scopes
        WHERE eligible_for_bounty = 1 GROUP BY asset_type ORDER BY c DESC
    """).fetchall()
    conn.close()

    print(f"\n  Database Stats")
    print(f"  {'='*40}")
    print(f"  Total programs:       {total}")
    print(f"  Bounty programs:      {bounty}")
    print(f"  Bounty-eligible scope items: {scopes}")
    print(f"\n  Scope types:")
    for t in types:
        print(f"    {t['asset_type']:<20} {t['c']:>6}")


if __name__ == "__main__":
    init_db()
    parser = argparse.ArgumentParser(description="Browse HackerOne bounty database")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("stats", help="Show database stats")

    lp = sub.add_parser("list", help="List programs")
    lp.add_argument("--all", action="store_true", help="Include non-bounty programs")
    lp.add_argument("--limit", type=int, default=50)

    sp = sub.add_parser("search", help="Search scopes by asset identifier")
    sp.add_argument("query", help="Search term")
    sp.add_argument("--type", help="Filter by asset type (URL, CIDR, etc.)")

    pp = sub.add_parser("show", help="Show details for a program")
    pp.add_argument("handle", help="Program handle")

    ep = sub.add_parser("export", help="Export as JSON for AI agents")
    ep.add_argument("--handle", help="Export single program")

    args = parser.parse_args()
    if args.command == "stats":
        stats()
    elif args.command == "list":
        list_programs(bounty_only=not args.all, limit=args.limit)
    elif args.command == "search":
        search_scopes(args.query, asset_type=args.type)
    elif args.command == "show":
        show_program(args.handle)
    elif args.command == "export":
        export_for_agent(handle=args.handle)
    else:
        parser.print_help()
