import sqlite3
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.environ.get("DB_PATH", os.path.join(_REPO_ROOT, "bounties.db"))


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            handle TEXT UNIQUE NOT NULL,
            name TEXT,
            url TEXT,
            offers_bounties INTEGER,
            submission_state TEXT,
            started_accepting_at TEXT,
            bounty_min REAL,
            bounty_max REAL,
            response_efficiency REAL,
            policy TEXT,
            updated_at TEXT,
            fetched_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL,
            asset_type TEXT,
            asset_identifier TEXT,
            eligible_for_bounty INTEGER,
            eligible_for_submission INTEGER,
            instruction TEXT,
            max_severity TEXT,
            created_at TEXT,
            updated_at TEXT,
            fetched_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );

        CREATE TABLE IF NOT EXISTS bounty_table (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL,
            low_label TEXT,
            low_amount REAL,
            medium_label TEXT,
            medium_amount REAL,
            high_label TEXT,
            high_amount REAL,
            critical_label TEXT,
            critical_amount REAL,
            fetched_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_id);
        CREATE INDEX IF NOT EXISTS idx_scopes_asset ON scopes(asset_type, asset_identifier);
        CREATE INDEX IF NOT EXISTS idx_programs_bounty ON programs(offers_bounties);

        CREATE TABLE IF NOT EXISTS recon_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_handle TEXT NOT NULL,
            program_name TEXT,
            domains TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS recon_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            tool TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            pid INTEGER,
            result_count INTEGER DEFAULT 0,
            output_file TEXT,
            json_output TEXT,
            error TEXT,
            pipeline_run_id INTEGER,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES recon_targets(id)
        );

        CREATE TABLE IF NOT EXISTS recon_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            result_type TEXT NOT NULL,
            value TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES recon_scans(id)
        );

        CREATE TABLE IF NOT EXISTS pipeline_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            current_phase INTEGER DEFAULT 1,
            phase_status TEXT DEFAULT 'pending',
            config TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES recon_targets(id)
        );

        CREATE INDEX IF NOT EXISTS idx_recon_scans_target ON recon_scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_recon_scans_pipeline ON recon_scans(pipeline_run_id);
        CREATE INDEX IF NOT EXISTS idx_recon_results_scan ON recon_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_recon_results_type ON recon_results(result_type);
        CREATE INDEX IF NOT EXISTS idx_pipeline_runs_target ON pipeline_runs(target_id);

        CREATE TABLE IF NOT EXISTS hacktivity_reports (
            id TEXT PRIMARY KEY,
            title TEXT,
            vulnerability_information TEXT,
            severity_rating TEXT,
            severity_score REAL,
            cwe TEXT,
            weakness_name TEXT,
            team_handle TEXT,
            team_name TEXT,
            reporter_username TEXT,
            state TEXT,
            substate TEXT,
            bounty_amount REAL,
            currency TEXT DEFAULT 'USD',
            disclosed_at TEXT,
            created_at TEXT,
            url TEXT,
            category TEXT,
            tags TEXT,
            summary TEXT,
            attack_vector TEXT,
            impact TEXT,
            complexity TEXT,
            takeaways TEXT,
            analyzed_at TEXT,
            fetched_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_hacktivity_category ON hacktivity_reports(category);
        CREATE INDEX IF NOT EXISTS idx_hacktivity_severity ON hacktivity_reports(severity_rating);
        CREATE INDEX IF NOT EXISTS idx_hacktivity_team ON hacktivity_reports(team_handle);
        CREATE INDEX IF NOT EXISTS idx_hacktivity_analyzed ON hacktivity_reports(analyzed_at);
        CREATE INDEX IF NOT EXISTS idx_hacktivity_bounty ON hacktivity_reports(bounty_amount);

        -- Per-program authentication credentials. The pipeline + Caido use
        -- these to perform authenticated XHR capture and replay.
        --
        -- value_ct is age-encrypted (pyrage) JSON. Decryption key lives at
        -- /home/kali/.age/key.txt mode 600 on the Kali host. See
        -- credential_store.py for the wrapper.
        --
        -- auth_type: 'storage_state' (Playwright JSON with cookies+localStorage),
        --            'cookie_jar'    (raw cookies, less common),
        --            'api_key'       (Bearer / X-API-Key header value),
        --            'oauth_bearer'  (short-lived OAuth access_token).
        --
        -- probe_url + expected_status + expected_body_contains are the
        -- liveness check executed at pipeline start (and any time
        -- last_validated_at is stale) to detect expired sessions before
        -- a 30-min pipeline burns time on a dead session.
        CREATE TABLE IF NOT EXISTS program_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_handle TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            value_ct BLOB NOT NULL,
            notes TEXT,
            account_email TEXT,
            tier TEXT,
            probe_url TEXT,
            probe_method TEXT DEFAULT 'GET',
            expected_status INTEGER,
            expected_body_contains TEXT,
            status TEXT DEFAULT 'active',
            captured_at TEXT DEFAULT (datetime('now')),
            last_validated_at TEXT,
            last_used_at TEXT,
            expires_at TEXT
            -- No FK to programs(handle): credentials may exist for a
            -- program we haven't ingested into the programs table yet
            -- (sub-products, related domains, etc.).
        );

        CREATE INDEX IF NOT EXISTS idx_credentials_program
            ON program_credentials(program_handle);
        CREATE INDEX IF NOT EXISTS idx_credentials_status
            ON program_credentials(status);
    """)
    conn.commit()

    # Migrations for existing DBs
    cols = {row[1] for row in conn.execute("PRAGMA table_info(recon_scans)").fetchall()}
    if "output_file" not in cols:
        conn.execute("ALTER TABLE recon_scans ADD COLUMN output_file TEXT")
    if "json_output" not in cols:
        conn.execute("ALTER TABLE recon_scans ADD COLUMN json_output TEXT")
    if "pipeline_run_id" not in cols:
        conn.execute("ALTER TABLE recon_scans ADD COLUMN pipeline_run_id INTEGER")
    if "pipeline_phase" not in cols:
        conn.execute("ALTER TABLE recon_scans ADD COLUMN pipeline_phase INTEGER")

    # Add scope_exclusions to recon_targets
    target_cols = {row[1] for row in conn.execute("PRAGMA table_info(recon_targets)").fetchall()}
    if "scope_exclusions" not in target_cols:
        conn.execute("ALTER TABLE recon_targets ADD COLUMN scope_exclusions TEXT DEFAULT '[]'")
    # Cache of wildcard-DNS parents detected at target creation.  JSON array
    # of strings (parent domains that resolve every subdomain to the same IP).
    # When set, the pipeline skips DNS brute-force tools (shuffledns, dnsgen,
    # active amass) for these parents — they only burn bandwidth without
    # producing real hosts.  Discovered Apr-2026 after the varonis incident
    # where shuffledns flooded the modem with 300K queries against wildcard
    # domains.  detected_at lets us re-detect after N days (DNS changes).
    if "wildcard_parents" not in target_cols:
        conn.execute("ALTER TABLE recon_targets ADD COLUMN wildcard_parents TEXT")
    if "wildcard_detected_at" not in target_cols:
        conn.execute("ALTER TABLE recon_targets ADD COLUMN wildcard_detected_at TEXT")

    # Add auto_approve to pipeline_runs
    pipeline_cols = {row[1] for row in conn.execute("PRAGMA table_info(pipeline_runs)").fetchall()}
    if "auto_approve" not in pipeline_cols:
        conn.execute("ALTER TABLE pipeline_runs ADD COLUMN auto_approve INTEGER DEFAULT 1")
    # pipeline_type distinguishes 'web' (the original broad recon pipeline) from 'oracle'
    # (the cryptographic-oracle-candidate pipeline). Default 'web' for backward compat with
    # rows written before this column existed.
    if "pipeline_type" not in pipeline_cols:
        conn.execute("ALTER TABLE pipeline_runs ADD COLUMN pipeline_type TEXT DEFAULT 'web'")
    # egress_netns: which scanN slot this pipeline owns. NULL for older runs that
    # predate the multi-egress pool; new runs always allocate via /netns/allocate.
    if "egress_netns" not in pipeline_cols:
        conn.execute("ALTER TABLE pipeline_runs ADD COLUMN egress_netns TEXT")

    # Add signal_required to programs (NULL=unknown, 0=no signal, 1=signal required)
    prog_cols = {row[1] for row in conn.execute("PRAGMA table_info(programs)").fetchall()}
    if "signal_required" not in prog_cols:
        conn.execute("ALTER TABLE programs ADD COLUMN signal_required INTEGER")

    conn.commit()
    conn.close()
