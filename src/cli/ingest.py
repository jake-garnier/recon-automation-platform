"""Fetch programs and scopes from HackerOne and store them in the local SQLite DB."""

from datetime import datetime, timezone
from app.db import get_connection, init_db
from app.h1_client import fetch_programs, fetch_structured_scopes


def upsert_program(conn, program):
    attrs = program.get("attributes", {})
    conn.execute("""
        INSERT INTO programs (id, handle, name, url, offers_bounties, submission_state,
                              started_accepting_at, response_efficiency, policy, updated_at, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            handle=excluded.handle, name=excluded.name, url=excluded.url,
            offers_bounties=excluded.offers_bounties, submission_state=excluded.submission_state,
            started_accepting_at=excluded.started_accepting_at,
            response_efficiency=excluded.response_efficiency, policy=excluded.policy,
            updated_at=excluded.updated_at, fetched_at=excluded.fetched_at
    """, (
        program["id"],
        attrs.get("handle", ""),
        attrs.get("name", ""),
        f"https://hackerone.com/{attrs.get('handle', '')}",
        1 if attrs.get("offers_bounties") else 0,
        attrs.get("submission_state", ""),
        attrs.get("started_accepting_at", ""),
        attrs.get("average_time_to_bounty_awarded"),
        attrs.get("policy", ""),
        attrs.get("updated_at", ""),
        datetime.now(timezone.utc).isoformat(),
    ))


def upsert_scope(conn, scope, program_id):
    attrs = scope.get("attributes", {})
    conn.execute("""
        INSERT INTO scopes (id, program_id, asset_type, asset_identifier, eligible_for_bounty,
                            eligible_for_submission, instruction, max_severity, created_at, updated_at, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            asset_type=excluded.asset_type, asset_identifier=excluded.asset_identifier,
            eligible_for_bounty=excluded.eligible_for_bounty,
            eligible_for_submission=excluded.eligible_for_submission,
            instruction=excluded.instruction, max_severity=excluded.max_severity,
            updated_at=excluded.updated_at, fetched_at=excluded.fetched_at
    """, (
        scope["id"],
        program_id,
        attrs.get("asset_type", ""),
        attrs.get("asset_identifier", ""),
        1 if attrs.get("eligible_for_bounty") else 0,
        1 if attrs.get("eligible_for_submission") else 0,
        attrs.get("instruction", ""),
        attrs.get("max_severity", ""),
        attrs.get("created_at", ""),
        attrs.get("updated_at", ""),
        datetime.now(timezone.utc).isoformat(),
    ))


def run_ingestion(fetch_scopes=True):
    init_db()
    conn = get_connection()

    print("Fetching programs from HackerOne...")
    programs = fetch_programs()
    print(f"  Got {len(programs)} programs")

    bounty_count = 0
    for program in programs:
        upsert_program(conn, program)
        if program.get("attributes", {}).get("offers_bounties"):
            bounty_count += 1
    conn.commit()
    print(f"  {bounty_count} programs offer bounties")

    if fetch_scopes:
        bounty_programs = conn.execute(
            "SELECT id, handle FROM programs WHERE offers_bounties = 1"
        ).fetchall()
        print(f"\nFetching scopes for {len(bounty_programs)} bounty programs...")
        for i, row in enumerate(bounty_programs):
            handle = row["handle"]
            print(f"  [{i+1}/{len(bounty_programs)}] {handle}...")
            try:
                scopes = fetch_structured_scopes(handle)
                for scope in scopes:
                    upsert_scope(conn, scope, row["id"])
                conn.commit()
            except Exception as e:
                print(f"    Error fetching scopes for {handle}: {e}")

    conn.close()
    print("\nIngestion complete.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest HackerOne bounty data")
    parser.add_argument("--no-scopes", action="store_true", help="Skip fetching scopes")
    args = parser.parse_args()
    run_ingestion(fetch_scopes=not args.no_scopes)
