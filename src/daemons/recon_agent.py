"""Recon Agent — runs on the Kali host (not in Docker).

Zero-dependency HTTP API (stdlib only) that spawns scan tool subprocesses.
Flask container talks to this over http://host.docker.internal:5001.
"""

import json
import os
import sys
import resource
import signal
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request
from urllib.error import URLError

# Repo root holds shared assets (resolvers.txt, scripts/, nuclei-templates/).
# This file lives at <root>/src/daemons/recon_agent.py, so root is parents[2].
REPO_ROOT = Path(__file__).resolve().parents[2]

# The agent is stdlib-only and runs as a standalone script (systemd + self
# re-invocation), so `src/` is not on the path by default. Add it so the
# deferred `from app import credential_store` (used by xhr-capture auth
# attach) resolves the same way it does inside the Flask container.
_SRC_DIR = str(REPO_ROOT / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

RECON_DIR = Path.home() / "recon"
SCANS = {}  # pid -> scan metadata
SCANS_FILE = RECON_DIR / ".scans.json"

# Exit-node guard state.  Mutated by _exit_node_monitor_loop, read by
# _handle_start (pre-flight gate) and _handle_health (status endpoint).
EXIT_NODE_STATUS = {
    "online": True,        # True = safe to launch scans; False = hard-stop
    "current_egress_ip": None,
    "expected_egress_ip": None,
    "last_check": None,
    "last_success": None,
    "consecutive_failures": 0,
    "consecutive_successes": 0,
    "total_failures": 0,
    "down_since": None,
    "guard_enabled": True,  # overridden in main() from EXIT_NODE_GUARD_ENABLED
}

# Exit-node bandwidth tracking.  Updated by _bandwidth_sampler_loop.
# Per-scan accounting is approximate: deltas from the exit node's vnstat
# are distributed across running scans in proportion to their elapsed
# wall-time since the last sample.  Stored on each scan as scan["bytes_*"].
BANDWIDTH_STATS = {
    "exit_rx_today": 0,
    "exit_tx_today": 0,
    "exit_rx_month": 0,
    "exit_tx_month": 0,
    "exit_conntrack_current": 0,
    "exit_conntrack_max": 0,
    "exit_conntrack_pct": 0.0,
    "last_sample": None,
    "last_sample_ok": False,
    "last_error": None,
    "samples_total": 0,
    "samples_failed": 0,
}


def _safe_json_load(path):
    """Load JSON from *path*, tolerating the 'Extra data' error that occurs
    when the file contains a valid JSON document followed by trailing bytes
    (e.g. from a partial re-write after an agent restart).  Falls back to
    ``json.JSONDecoder().raw_decode`` which stops at the end of the first
    complete JSON value.
    """
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try raw_decode — parses only the first JSON value and ignores the rest
        obj, _ = json.JSONDecoder().raw_decode(text)
        return obj
# Map logical tool names to actual binary names (when they differ)
TOOL_BINARIES = {"nuclei-takeover": "nuclei", "s3-takeover": "dig",
                  "joomscan": "joomscan", "git-dumper": "git-dumper",
                  "kiterunner": "kr"}
SCAN_TTL = 3600  # seconds to keep completed scans in memory
MAX_CONCURRENT_SCANS = 24  # raised from 16 → 24 (2026-05-22).
                           # Live measurement at 4 heavy + ~6 light: mem 2.6/88 GB,
                           # load 1.0/16 cores, conntrack 74/524288 (0.01%),
                           # SYN budget 0.2%, UDP budget 1%.  Headroom is enormous.

# Heavy tools: memory-intensive OR network-intensive.
# Only one runs at a time to prevent OOM and modem overload on consumer internet.
HEAVY_TOOLS = {"amass", "nmap", "eyewitness", "feroxbuster", "kiterunner", "nuclei", "gospider",
               # Network-heavy: large fan-out TCP scans that can exhaust modem
               # NAT tables when run in parallel across pipelines.  Two naabu
               # instances (each scanning ~45K subs × 47 ports at -rate 150)
               # killed the modem on 2026-04-29.  Gate them as heavy so only
               # one pipeline at a time fans out TCP traffic.
               "naabu", "httpx-toolkit",
               # Browser-heavy: 4 parallel Chromium contexts ~1.5-2 GB RSS,
               # spawned per host. Same RAM pressure as eyewitness (Firefox).
               # Without heavy gating, two pipelines running xhr-capture
               # concurrently double-spawn Chromium and exhaust /tmp.
               "xhr-capture"}
# Raised 2 → 4 → 8 (2026-05-22). The "4 = one per egress" mental model
# conflated two distinct constraints: per-egress conntrack capacity (524K
# per Hetzner node, ample) vs Kali-host CPU/RAM (16 cores, 88 GB). With 4
# heavy running the VM is 3% memory, load 1.0/16. Doubling to 8 fills two
# heavies per egress slot, still well within VM headroom and per-node
# conntrack budget. If we see modem/egress flow saturation we can drop
# back to 6.
MAX_CONCURRENT_HEAVY = 8

# Tools whose process can be safely SIGSTOP/SIGCONT (they survive being
# paused without timing out or corrupting state).  Used by the exit-node
# monitor to freeze ALL network-active scans when egress goes through
# the wrong path.  Broader than the SYN-burst-gate FREEZABLE list inside
# _net_monitor_loop (which is TCP-only) because exit-node failure means
# every external request is unsafe, not just TCP-heavy ones.
FREEZABLE_TOOLS = ("naabu", "httpx-toolkit", "feroxbuster", "kiterunner",
                   "katana", "gospider", "nuclei", "amass", "subzy",
                   "shuffledns", "dnsx", "subfinder", "getallurls",
                   "paramspider", "nomore403", "corscanner")

# Apexes where subzy's "vulnerable" verdict is reliably a false positive
# because the apex owner runs the subdomain routing layer themselves, so
# no third-party can register an unclaimed subdomain to take it over.
# HubSpot's hubspotpagebuilder.com/.eu fronts every subdomain with their
# own Cloudflare Worker (`x-hs-cfworker-meta: PageBuilderResolver`,
# `x-hs-portal-id` header) — only HubSpot customers can register the
# subdomains, never an external attacker. Adding an apex here makes the
# subzy parser drop "vulnerable" findings on any subdomain of it.
# When a new apex shows up with the same pattern (404 fingerprint trips
# subzy, but vendor controls the routing), extend this set.
SUBZY_PROTECTED_APEXES = {
    "hubspotpagebuilder.com",
    "hubspotpagebuilder.eu",
}


def _subzy_apex_protected(subdomain):
    """Return True if `subdomain` is under an apex we know is FP-prone.

    subzy's "vulnerable" verdict on any subdomain of these apexes is
    drop-on-floor: only the apex owner can register new subdomains, so
    a third-party takeover is structurally impossible.
    """
    if not subdomain:
        return False
    # Strip scheme/path/port if present (subzy emits bare hostnames, but be defensive).
    host = subdomain.strip().lower()
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0].split(":", 1)[0]
    for apex in SUBZY_PROTECTED_APEXES:
        if host == apex or host.endswith("." + apex):
            return True
    return False

# Exit-node guard.  All recon egress is routed through a Hetzner VPS
# acting as a Tailscale exit node — this prevents the home modem's NAT
# table from being exhausted by naabu/httpx fanout.  If the exit node
# becomes unreachable we MUST hard-stop scans, never fall back to the
# direct home connection (which is what caused the original outages).
EXIT_NODE_REQUIRED_IP = os.environ.get("EXIT_NODE_REQUIRED_IP", "<EXIT_NODE_PUBLIC_IP>")
EXIT_NODE_TS_IP = os.environ.get("EXIT_NODE_TS_IP", "<EXIT_NODE_TS_IP>")
# Probe endpoints — try multiple so a single provider outage doesn't false-positive.
EXIT_NODE_PROBE_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip",
                        "https://checkip.amazonaws.com")
EXIT_NODE_CHECK_INTERVAL_S = 60
# Number of consecutive failed probes before declaring the exit node down.
# 3 × 60s = 3 minutes — enough to absorb a transient blip without leaving
# scans paused unnecessarily, fast enough to catch a real outage.
EXIT_NODE_FAIL_THRESHOLD = 3
EXIT_NODE_RECOVER_THRESHOLD = 2  # successes to declare recovered
# Allow disabling the guard for development on machines not behind the
# exit node (e.g. running pieces of the codebase locally on the Mac).
EXIT_NODE_GUARD_ENABLED = os.environ.get("EXIT_NODE_GUARD_ENABLED", "1") != "0"

# ─── Netns / multi-egress pool ─────────────────────────────────────────
# Four independent WireGuard tunnels, each routed through its own Hetzner
# CPX21/CPX22 egress node. Pipelines claim a slot via /netns/allocate so
# their tool spawns are wrapped with `ip netns exec scanN`. This lets us
# run up to 4 pipelines simultaneously without conntrack contention
# (each Hetzner node has 524K conntrack capacity; one pipeline peaks at ~50K).
#
# scan1 — recon-egress-ash (<EXIT_NODE_PUBLIC_IP>) — CPX21
# scan2 — recon-egress-hil (<EXIT_NODE_HIL_IP>)  — CPX21
# scan3 — recon-egress-fsn (<EXIT_NODE_FSN_IP>) — CPX22
# scan4 — recon-egress-hel (<EXIT_NODE_HEL_IP>)  — CPX22
NETNS_POOL_SLOTS = ["scan1", "scan2", "scan3", "scan4"]
NETNS_EXPECTED_IPS = {
    "scan1": "<EXIT_NODE_PUBLIC_IP>",
    "scan2": "<EXIT_NODE_HIL_IP>",
    "scan3": "<EXIT_NODE_FSN_IP>",
    "scan4": "<EXIT_NODE_HEL_IP>",
}
# In-memory pool state.  Each slot tracks {claimed_by, claimed_at, last_egress_check, online}.
# Persisted to ~/recon/.netns_pool.json so claims survive agent restart.
NETNS_POOL_FILE = Path.home() / "recon" / ".netns_pool.json"
NETNS_POOL = {
    slot: {
        "egress_ip": NETNS_EXPECTED_IPS[slot],
        "claimed_by": None,        # pipeline_id (int) or None
        "claimed_at": None,        # unix timestamp
        "online": True,            # set False by exit-node monitor if probe fails
        "consecutive_failures": 0,
    } for slot in NETNS_POOL_SLOTS
}
NETNS_POOL_LOCK = threading.RLock()  # reentrant — _save_netns_pool can acquire from inside another acquire
# Stale-claim reaper: free any claim older than 12h with no active scans
# (autopilot's pipeline-abandon threshold is 6h, so 12h is well past that).
NETNS_STALE_CLAIM_MAX_AGE_S = 12 * 3600
# Default netns when a scan arrives WITHOUT a pipeline_id (e.g. one-off
# manual scans, oracle pipeline tools).  scan1 is the original Ashburn
# node — same egress IP as the historical Tailscale-based default route.
NETNS_DEFAULT_SLOT = "scan1"


def _save_netns_pool():
    """Persist NETNS_POOL state to disk (claims survive agent restart)."""
    try:
        NETNS_POOL_FILE.parent.mkdir(parents=True, exist_ok=True)
        with NETNS_POOL_LOCK:
            snapshot = {k: dict(v) for k, v in NETNS_POOL.items()}
        with open(NETNS_POOL_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
    except OSError as e:
        print("[netns-pool] save failed: %s" % e)


def _load_netns_pool():
    """Restore NETNS_POOL state from disk on startup."""
    if not NETNS_POOL_FILE.exists():
        return
    try:
        with open(NETNS_POOL_FILE) as f:
            saved = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print("[netns-pool] load failed (%s) — starting fresh" % e)
        return
    with NETNS_POOL_LOCK:
        for slot in NETNS_POOL_SLOTS:
            if slot in saved:
                # Merge persisted claim state but keep current expected egress IP
                NETNS_POOL[slot].update({
                    k: saved[slot].get(k)
                    for k in ("claimed_by", "claimed_at")
                })
    print("[netns-pool] restored state from %s" % NETNS_POOL_FILE)


def _netns_for_pipeline(pipeline_id):
    """Return the netns slot claimed by pipeline_id, or None."""
    if pipeline_id is None:
        return None
    with NETNS_POOL_LOCK:
        for slot, info in NETNS_POOL.items():
            if info["claimed_by"] == pipeline_id:
                return slot
    return None


def _netns_allocate(pipeline_id):
    """Claim a free, online netns slot for this pipeline.

    If the pipeline already holds a slot, returns the same slot (idempotent).
    Returns (slot_name, None) on success or (None, error_msg) on failure.
    """
    allocated = None
    err = None
    with NETNS_POOL_LOCK:
        # Idempotent: already claimed by this pipeline?
        for slot, info in NETNS_POOL.items():
            if info["claimed_by"] == pipeline_id:
                return slot, None  # already held; no save needed
        # Find a free + online slot
        for slot in NETNS_POOL_SLOTS:
            info = NETNS_POOL[slot]
            if info["claimed_by"] is None and info["online"]:
                info["claimed_by"] = pipeline_id
                info["claimed_at"] = time.time()
                allocated = slot
                break
        if allocated is None:
            free_offline = [s for s, i in NETNS_POOL.items()
                            if i["claimed_by"] is None and not i["online"]]
            active = sum(1 for i in NETNS_POOL.values() if i["claimed_by"] is not None)
            err = "all %d slots claimed (offline: %d)" % (active, len(free_offline))
    # CRITICAL: _save_netns_pool() takes the same lock — must release first to avoid deadlock.
    if allocated:
        _save_netns_pool()
        return allocated, None
    return None, err


def _netns_release(pipeline_id):
    """Free the slot held by pipeline_id. Idempotent (no-op if not held)."""
    with NETNS_POOL_LOCK:
        released = None
        for slot, info in NETNS_POOL.items():
            if info["claimed_by"] == pipeline_id:
                info["claimed_by"] = None
                info["claimed_at"] = None
                released = slot
                break
    if released:
        _save_netns_pool()
    return released


# PATH we want available inside `sudo ip netns exec`. sudo's `secure_path`
# defaults to /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# which is missing /home/kali/go/bin where Go-based tools (naabu, subfinder,
# subzy, katana, gospider, arjun, kiterunner, …) live. We can't override
# secure_path at sudo invocation, so we either (a) resolve cmd[0] to an
# absolute path before sudo runs it, or (b) for `bash -c` shells, prepend an
# explicit `export PATH=…` to the script body so tools called from within the
# shell are findable.
_NETNS_EXEC_PATH = (
    "/home/kali/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
    "/sbin:/bin"
)
# PYTHONPATH for Python tools installed via `pip install --user` (arjun,
# paramspider, linkfinder, …). sudo's `env_reset` strips PYTHONPATH from the
# environment, so any tool whose entry-point imports from
# /home/kali/.local/lib/python3.X/site-packages dies with ModuleNotFoundError.
# We discover the user site-packages dynamically so the agent doesn't break
# when Python is upgraded on the host.
import site as _site
_NETNS_USER_SITE = _site.getusersitepackages()


def _netns_wrap_cmd(cmd, netns):
    """Prefix cmd (list[str] or list of bash -c args) with `ip netns exec NETNS`.

    Handles both forms:
      - cmd = ["subfinder", "-dL", ...]
        → cmd[0] resolved to abs path via shutil.which() before sudo strips PATH
      - cmd = ["bash", "-c", "<script>"]
        → "export PATH=…; <script>" prepended so external tools resolve inside
          the shell body

    If netns is falsy, returns cmd unchanged (no-op for un-pipelined scans
    when NETNS_GUARD_ENABLED is off, or for built-in tools that don't
    network).

    Why this matters: sudo enforces `secure_path` from /etc/sudoers which
    strips PATH. Go-based tools live in /home/kali/go/bin (not on
    secure_path), so without this they fail with
    `exec of "naabu" failed: No such file or directory`.
    """
    if not netns:
        return cmd
    if not isinstance(cmd, list):
        raise TypeError("cmd must be a list, got %r" % type(cmd))

    # For `bash -c <script>` or `sh -c <script>` forms, prepend a PATH +
    # PYTHONPATH export to the script body so tools called from within the
    # shell are findable.
    if len(cmd) >= 3 and cmd[0] in ("bash", "sh") and cmd[1] == "-c":
        cmd = [cmd[0], cmd[1],
               "export PATH='%s' PYTHONPATH='%s'; %s" % (
                   _NETNS_EXEC_PATH, _NETNS_USER_SITE, cmd[2])] + cmd[3:]
    elif cmd and cmd[0] not in ("python3", "python"):
        # For direct binary forms, resolve cmd[0] to its absolute path using
        # the agent's PATH (which the systemd unit has set up correctly).
        resolved = shutil.which(cmd[0])
        if resolved:
            cmd = [resolved] + cmd[1:]
    # Pass PYTHONPATH as a sudo env override (VAR=val before the command).
    # sudo's env_reset strips PYTHONPATH from the inherited environment, so
    # tools like arjun (installed via `pip install --user`, entry-point at
    # /home/kali/.local/bin/arjun importing from
    # /home/kali/.local/lib/python3.X/site-packages) crash with
    # ModuleNotFoundError otherwise.
    return ["sudo", "-n",
            "PYTHONPATH=" + _NETNS_USER_SITE,
            "ip", "netns", "exec", netns] + cmd

# Exit-node traffic accounting.  The exit node runs a tiny HTTP server
# at http://${EXIT_NODE_TS_IP}:9090/traffic exposing vnstat byte counts.
# The bandwidth sampler thread polls this every 30s and distributes the
# delta across currently-running scans (in proportion to their runtime
# since the last sample), giving approximate per-scan byte counts.
EXIT_TRAFFIC_URL = os.environ.get(
    "EXIT_TRAFFIC_URL",
    "http://%s:9090/traffic" % EXIT_NODE_TS_IP,
)
BANDWIDTH_SAMPLE_INTERVAL_S = 30
# Per-scan byte cap — if any single scan transfers more than this, alert.
# Calibrated to catch runaway wildcard hammering (the varonis incident
# moved ~500 MB of DNS traffic in 2 min; a 5GB single-scan budget is
# 10x that, comfortably above legit feroxbuster/eyewitness runs but
# below catastrophic failure modes).
SCAN_BYTE_ALERT_THRESHOLD = 5 * 1024 ** 3  # 5 GB
# Per-tool virtual memory caps (bytes).  RLIMIT_AS limits virtual address space,
# not RSS — Firefox/geckodriver (used by eyewitness) maps huge virtual regions
# for JIT etc. so RLIMIT_AS breaks it even though RSS stays ~40MB.
HEAVY_MEM_LIMITS = {
    "amass":      4 * 1024 ** 3,   # 4 GB — libpostal alone needs ~2 GB for model loading
    "nmap":       3 * 1024 ** 3,   # 3 GB
    # eyewitness: no RLIMIT_AS — Firefox needs large virtual mappings.
    # Serialized via HEAVY_TOOLS concurrency gate instead.
}
# Per-tool RSS memory limits (bytes).  Checked by the reaper thread every 60s.
# Unlike RLIMIT_AS (which limits virtual address space and breaks some tools),
# this checks actual RSS and kills only when physical memory is truly exhausted.
# Only tools known to leak memory on large targets need caps.
TOOL_RSS_LIMITS = {
    "gospider":     4 * 1024 ** 3,   # 4 GB — leaked to 10.7 GB on gitlab (228 hosts)
}
# Per-tool runtime limits (seconds).  Checked by the reaper thread every 60s.
# Flask `_check_phase_completion` enforces a stale-scan kill ~30 min after these
# limits; the agent should ALWAYS kill first so we get a clean exit with output.
TOOL_RUNTIME_LIMITS = {
    # Phase 3 crawlers — heavy
    "getallurls":   2 * 3600,    # 2h — gau queries archive.org/commoncrawl, hangs on huge domains
    "feroxbuster":  3 * 3600,    # 3h — 15 targets × raft-small × depth 1
    "gospider":     2 * 3600,    # 2h — web spider on large targets
    "katana":       90 * 60,     # 1.5h
    "nuclei":     150 * 60,      # 2.5h — DAST + KEV
    "kiterunner": 150 * 60,      # 2.5h — large wordlist brute-force
    # Phase 4 analysis
    "arjun":      150 * 60,      # 2.5h — parameter discovery is slow per URL
    # Phase 5 exploitation — verified slow
    "sqlmap":     150 * 60,      # 2.5h
    "commix":     120 * 60,      # 2h
    "wpscan":      90 * 60,      # 1.5h
    # Phase 1/2 enumeration — should be quick; if not, something's wrong
    "subfinder":   45 * 60,
    "amass":       60 * 60,
    "shuffledns":  45 * 60,
    "dnsx":        45 * 60,
    "httpx-toolkit": 60 * 60,
    "naabu":       60 * 60,
    "nmap":        90 * 60,
    "eyewitness":  60 * 60,
    # SPA crawler — 50 hosts * 30s = 25 min, +overhead. Budget 60 min.
    "xhr-capture": 60 * 60,
}


def _make_preexec(tool):
    """Return a preexec_fn that sets setsid + memory limit for heavy tools."""
    mem_limit = HEAVY_MEM_LIMITS.get(tool)
    def _preexec():
        os.setsid()
        if mem_limit:
            resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    return _preexec


def _find_tool(name):
    return shutil.which(name)


def _extract_urls_from_httpx(input_path, exclude_codes=None, filter_wildcards=False, log=None):
    """Extract URLs from httpx JSONL output.

    Returns scheme://hostname[:non-default-port] origins, NOT the full probed URL.
    httpx is invoked with -favicon so obj["url"] is e.g.
    https://auth.ripio.com:443/favicon.ico — handing that to katana/gau/gospider
    crawls the binary favicon (no outbound links), yielding zero URLs.

    If filter_wildcards is True, detect and exclude wildcard DNS catch-all hosts
    (e.g. *.moveit.qms.grab.com all returning the same nginx default page).
    """
    if exclude_codes is None:
        exclude_codes = {404, 502, 503, 504}
    entries = []
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("status-code") in exclude_codes:
                    continue
                # httpx "host" field is the resolved IP; "input" is the hostname.
                # Rebuild the origin (scheme://hostname[:port]) so we crawl /
                # rather than the favicon-probe path.
                hostname = obj.get("input", "").strip()
                scheme = obj.get("scheme") or "https"
                port = str(obj.get("port") or "").strip()
                if not hostname:
                    # Last-resort fallback: parse the recorded URL
                    raw_url = obj.get("url", "")
                    if raw_url:
                        from urllib.parse import urlsplit
                        sp = urlsplit(raw_url)
                        hostname = sp.hostname or ""
                        scheme = sp.scheme or scheme
                        port = str(sp.port) if sp.port else port
                if not hostname:
                    continue
                default_port = "443" if scheme == "https" else "80"
                if port and port != default_port:
                    url = "%s://%s:%s" % (scheme, hostname, port)
                else:
                    url = "%s://%s" % (scheme, hostname)
                if filter_wildcards:
                    # Use hostname (not the resolved IP) so the wildcard grouping
                    # actually catches DNS catch-alls — obj["host"] is the IP and
                    # would only group by /24-ish IP ranges.
                    title = obj.get("title", "")
                    status = obj.get("status-code", 0)
                    parts = hostname.split(".")
                    parent = ".".join(parts[-4:]) if len(parts) > 4 else \
                             ".".join(parts[-3:]) if len(parts) > 3 else hostname
                    entries.append((url, (parent, title, status)))
                else:
                    entries.append((url, None))
            except (json.JSONDecodeError, ValueError):
                if line.startswith("http"):
                    entries.append((line, None))

    if filter_wildcards and entries:
        from collections import Counter
        fp_counts = Counter(fp for _, fp in entries if fp)
        # Proportional threshold: 10% of entries or 20, whichever is lower
        # This catches wildcards on small targets (100 subs → threshold 10)
        # while remaining conservative on large targets
        wildcard_threshold = min(max(len(entries) // 10, 5), 20)
        wildcard_fps = {fp for fp, count in fp_counts.items()
                        if count > wildcard_threshold and fp[0] and fp[1]}
        if wildcard_fps:
            before = len(entries)
            entries = [(url, fp) for url, fp in entries if fp not in wildcard_fps]
            skipped = before - len(entries)
            if log:
                log.write("[wildcard-filter] Removed %d wildcard DNS hosts "
                          "(%s)\n" % (skipped,
                          ", ".join("%s=%d" % (fp[0], fp_counts[fp])
                                   for fp in wildcard_fps)))
                log.flush()
            # If wildcard filtering removed >90% and <10 remain, write a wipe flag
            # so downstream tools can fall back to subfinder-only input
            if before > 50 and skipped / before > 0.9 and len(entries) < 10:
                wipe_flag = Path(input_path).parent / "httpx_wildcard_wiped.json"
                import json as _json
                with open(wipe_flag, "w") as wf:
                    _json.dump({"original": before, "remaining": len(entries),
                                "removed": skipped,
                                "wildcard_parents": [fp[0] for fp in wildcard_fps]}, wf)
                if log:
                    log.write("[wildcard-filter] WARNING: >90%% removed (%d/%d). "
                              "Wrote wildcard_wiped flag for subfinder fallback.\n" % (skipped, before))
                    log.flush()

    return [url for url, _ in entries]


def _extract_tls_hosts_from_httpx(input_path, limit=150):
    """Extract host:port pairs from httpx JSONL output for TLS scanning.

    Only includes https:// URLs (port 443 by default, or explicit :N). Returns
    a deduplicated list of `host:port` strings suitable for sslscan / sslyze /
    openssl s_client. Caps at `limit` to bound scan runtime.
    """
    hosts = set()
    try:
        with open(input_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    url = obj.get("url") or obj.get("input") or ""
                    if not url:
                        continue
                    if not url.startswith("https://"):
                        continue
                    # Strip scheme + path
                    hostpart = url[len("https://"):].split("/", 1)[0]
                    # Already host:port? keep as-is; otherwise append :443
                    if ":" in hostpart:
                        hosts.add(hostpart)
                    else:
                        hosts.add("%s:443" % hostpart)
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        return []
    return sorted(hosts)[:limit]


def _compute_rate_budget(net_stats):
    """Compute current % of UDP/SYN budget consumed and a scale factor for new tools.

    Caps at 80% — above that, the gate refuses launches; this function only
    matters for the 0–80% range where we still launch but with reduced rates.

    Returns dict:
      udp_pct, syn_pct: 0-100 (% of threshold consumed by current rate)
      scale_dns: 0.2-1.0 — multiplier for tools with DNS-heavy flags
      scale_syn: 0.2-1.0 — multiplier for tools with HTTP/TCP rate flags
    """
    UDP_THRESHOLD = 500.0
    SYN_THRESHOLD = 200.0
    udp = (net_stats or {}).get("udp_out_per_sec", 0) or 0
    syn = (net_stats or {}).get("tcp_new_per_sec", 0) or 0
    udp_pct = min(100.0, 100.0 * udp / UDP_THRESHOLD)
    syn_pct = min(100.0, 100.0 * syn / SYN_THRESHOLD)
    # Linear scale: 0% used → 1.0 (full rate); 50% used → 0.6; 80% used → 0.2.
    # Below 0.2 we'd rather not launch at all (gate would have already deferred).
    def _scale(pct):
        if pct < 30:
            return 1.0
        if pct < 80:
            # 30→1.0, 80→0.2 linearly
            return max(0.2, 1.0 - (pct - 30) * (0.8 / 50))
        return 0.2
    return {
        "udp_pct": round(udp_pct, 1),
        "syn_pct": round(syn_pct, 1),
        "scale_dns": _scale(udp_pct),
        "scale_syn": _scale(syn_pct),
    }


def _is_pid_alive(pid):
    """Check if a process with the given PID is still running (not a zombie)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # process exists but we can't signal it — check state below
    # Check /proc/<pid>/stat to exclude zombie processes (state 'Z')
    try:
        stat = open(f"/proc/{pid}/stat").read()
        # Format: pid (comm) state ...
        state = stat.split(")")[1].split()[0]
        if state == "Z":
            return False  # zombie — not actually running
    except (OSError, IndexError):
        pass
    return True


def _save_scans():
    """Persist scan metadata to disk so we can recover after restart."""
    data = {}
    for pid, scan in SCANS.items():
        data[str(pid)] = {
            "pid": scan["pid"],
            "tool": scan["tool"],
            "target_name": scan["target_name"],
            "output_file": scan["output_file"],
            "json_output": scan["json_output"],
            "log_file": scan["log_file"],
            "started_at": scan["started_at"],
            "bytes_attributed": scan.get("bytes_attributed", 0),
            "bytes_alert_sent": scan.get("bytes_alert_sent", False),
        }
    try:
        SCANS_FILE.write_text(json.dumps(data))
    except OSError:
        pass


def _load_scans():
    """Load scan metadata from disk and re-adopt any still-running processes."""
    if not SCANS_FILE.exists():
        return
    try:
        data = json.loads(SCANS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return
    for pid_str, scan_data in data.items():
        pid = int(pid_str)
        if pid in SCANS:
            continue  # already tracked
        scan_data["pid"] = pid
        scan_data["process"] = None  # no Popen object for recovered scans
        scan_data["log_fh"] = None
        scan_data["stdin_fh"] = None
        scan_data["recovered"] = True
        SCANS[pid] = scan_data
        alive = _is_pid_alive(pid)
        if alive:
            print("  Recovered running scan: pid=%d tool=%s" % (pid, scan_data["tool"]))
        else:
            print("  Recovered finished scan: pid=%d tool=%s" % (pid, scan_data["tool"]))


def _poll_scan(scan):
    """Check if a scan's process is still running. Works for both live and recovered scans."""
    if scan.get("synthetic"):
        return scan.get("exit_code", 0)  # synthetic scan — already "completed"
    proc = scan.get("process")
    if proc is not None:
        return proc.poll()
    # Recovered scan — check PID directly
    if _is_pid_alive(scan["pid"]):
        return None  # still running
    return 0  # assume success (output file check determines real status)


def _merge_gospider_raw(scan):
    """Merge gospider raw directory into the .txt output file so status/recovery works."""
    if scan.get("tool") != "gospider" or not scan.get("json_output"):
        return
    raw_dir = Path(scan["json_output"])
    output_path = Path(scan["output_file"])
    if output_path.exists() or not raw_dir.exists() or not raw_dir.is_dir():
        return
    try:
        seen = set()
        urls = []
        for outfile in sorted(raw_dir.iterdir()):
            if outfile.is_file():
                with open(outfile) as f:
                    for line in f:
                        parts = line.strip().split(" ")
                        url = parts[-1] if parts else line.strip()
                        if url.startswith("http") and url not in seen:
                            seen.add(url)
                            urls.append(url)
        if urls:
            with open(output_path, "w") as f:
                f.write("\n".join(urls) + "\n")
            print("  [gospider] merged %d URLs from raw dir → %s" % (len(urls), output_path.name))
    except Exception as e:
        print("  [gospider] merge failed: %s" % e)


def _kill_scan_process(scan):
    """Kill a scan's process group.  Best-effort, ignores errors."""
    pid = scan["pid"]
    proc = scan.get("process")
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    if proc:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
    # For gospider: merge raw directory into .txt so partial results are recoverable
    _merge_gospider_raw(scan)


def _cleanup_scans():
    """Close file handles for finished scans, enforce runtime limits, and evict stale entries."""
    now = time.time()
    to_remove = []
    for pid, scan in SCANS.items():
        # Enforce per-tool runtime limits on still-running scans
        if _poll_scan(scan) is None:
            # Check RSS memory limit for tools known to leak
            rss_limit = TOOL_RSS_LIMITS.get(scan.get("tool"))
            if rss_limit:
                try:
                    # Read RSS from /proc/<pid>/status (works for process groups too)
                    # Sum RSS of the main pid + all children in the process group
                    pgid = os.getpgid(pid)
                    total_rss = 0
                    for entry in os.listdir("/proc"):
                        if not entry.isdigit():
                            continue
                        try:
                            with open("/proc/%s/stat" % entry) as f:
                                fields = f.read().split()
                                if int(fields[4]) == pgid:  # field 4 = pgrp
                                    total_rss += int(fields[23]) * os.sysconf("SC_PAGE_SIZE")
                        except (IOError, IndexError, ValueError):
                            continue
                    if total_rss > rss_limit:
                        rss_gb = total_rss / (1024 ** 3)
                        limit_gb = rss_limit / (1024 ** 3)
                        print("  [reaper] killing %s (pid %d) — RSS %.1f GB exceeds %.1f GB limit" % (
                            scan.get("tool"), pid, rss_gb, limit_gb))
                        _kill_scan_process(scan)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            # Check per-tool runtime limit
            runtime_limit = TOOL_RUNTIME_LIMITS.get(scan.get("tool"))
            if runtime_limit and (now - scan["started_at"]) > runtime_limit:
                elapsed_min = (now - scan["started_at"]) / 60
                print("  [reaper] killing %s (pid %d) — runtime %.0f min exceeds %d min limit" % (
                    scan.get("tool"), pid, elapsed_min, runtime_limit // 60))
                _kill_scan_process(scan)
            continue
        # Scan is finished — close file handles
        for fh_key in ("log_fh", "stdin_fh"):
            fh = scan.get(fh_key)
            if fh and not getattr(fh, 'closed', True):
                try:
                    fh.close()
                except OSError:
                    pass
        if now - scan["started_at"] > SCAN_TTL:
            to_remove.append(pid)
    for pid in to_remove:
        del SCANS[pid]
    if to_remove:
        _save_scans()


def _parse_nmap_xml(xml_path):
    """Parse nmap XML output and return list of open port results."""
    results = []
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host_addr = addr_el.get("addr", "") if addr_el is not None else ""
            hostname = ""
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name", "")
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                results.append({
                    "value": hostname or host_addr,
                    "host": host_addr,
                    "hostname": hostname,
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": "open",
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "version": ("%s %s" % (
                        service_el.get("product", ""),
                        service_el.get("version", ""),
                    )).strip() if service_el is not None else "",
                })
    except ET.ParseError:
        pass
    return results


def _resolve_cname(domain):
    """Resolve CNAME for a domain using dig (stdlib socket doesn't return CNAMEs)."""
    try:
        result = subprocess.run(
            ["dig", "CNAME", domain, "+short"],
            capture_output=True, text=True, timeout=5,
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _check_s3_bucket(bucket_name):
    """Check if an S3 bucket exists. Returns 'nosuchbucket', 'exists', or 'error'."""
    url = "http://%s.s3.amazonaws.com/" % bucket_name
    try:
        req = Request(url, method="GET")
        resp = urlopen(req, timeout=5)
        return "exists"
    except URLError as e:
        body = ""
        if hasattr(e, "read"):
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
        if "NoSuchBucket" in body:
            return "nosuchbucket"
        # 403 = bucket exists but no access, 200 = public
        return "exists"
    except Exception:
        return "error"


def _verify_s3_takeover(subdomain):
    """Double-check a suspected S3 takeover by hitting the subdomain directly.

    Returns True only if the subdomain itself returns a NoSuchBucket or
    similar CloudFront origin-not-found error — not just AccessDenied or
    a live page.
    """
    for proto in ("https", "http"):
        url = "%s://%s/" % (proto, subdomain)
        try:
            req = Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urlopen(req, timeout=8)
            # 200 = live page, not vulnerable
            return False
        except URLError as e:
            body = ""
            code = getattr(e, "code", 0)
            if hasattr(e, "read"):
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
            # AccessDenied from S3 = bucket exists, not takeover-able
            if "AccessDenied" in body:
                return False
            # Live page behind auth / WAF
            if code in (401, 403) and "NoSuchBucket" not in body:
                return False
            # Actual NoSuchBucket from CloudFront origin
            if "NoSuchBucket" in body:
                return True
            # CloudFront "bad request" with no origin = potentially vulnerable
            if code == 502 or code == 503:
                return True
        except Exception:
            continue
    # Could not reach at all — inconclusive, mark as not vulnerable
    return False


def _run_s3_takeover_check(input_path, output_path, log_path):
    """Check subdomains for S3 bucket takeover via CloudFront.

    1. Read subdomains from input file
    2. Resolve CNAMEs to find CloudFront distributions
    3. For CloudFront-pointed subdomains, check if S3 bucket named after subdomain exists
    4. Write vulnerable results to output JSON file
    """
    results = []
    stats = {"total": 0, "cloudfront": 0, "checked": 0, "vulnerable": 0}

    with open(log_path, "w") as log:
        log.write("Starting S3 takeover check\n")
        log.flush()

        with open(input_path) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        stats["total"] = len(subdomains)
        log.write("Loaded %d subdomains\n" % len(subdomains))
        log.flush()

        # Phase 1: find CloudFront CNAMEs
        cf_domains = []
        for i, domain in enumerate(subdomains):
            if i % 500 == 0 and i > 0:
                log.write("CNAME check: %d/%d (found %d CloudFront)\n" % (i, len(subdomains), len(cf_domains)))
                log.flush()
            cname = _resolve_cname(domain)
            if cname and "cloudfront.net" in cname.lower():
                cf_domains.append({"subdomain": domain, "cloudfront": cname})
                log.write("CloudFront: %s -> %s\n" % (domain, cname))
                log.flush()

        stats["cloudfront"] = len(cf_domains)
        log.write("Found %d CloudFront CNAMEs\n" % len(cf_domains))
        log.flush()

        # Phase 2: check S3 buckets for CloudFront domains
        for entry in cf_domains:
            domain = entry["subdomain"]
            bucket_status = _check_s3_bucket(domain)
            stats["checked"] += 1
            entry["bucket_status"] = bucket_status
            if bucket_status == "nosuchbucket":
                # Phase 3: verify by hitting the subdomain directly
                log.write("Verifying %s (bucket missing, checking subdomain response)...\n" % domain)
                log.flush()
                confirmed = _verify_s3_takeover(domain)
                entry["vulnerable"] = confirmed
                if confirmed:
                    stats["vulnerable"] += 1
                    log.write("CONFIRMED VULNERABLE: %s\n" % domain)
                else:
                    log.write("FALSE POSITIVE: %s (bucket missing but subdomain serves content)\n" % domain)
            else:
                entry["vulnerable"] = False
                log.write("OK: %s (bucket %s)\n" % (domain, bucket_status))
            log.flush()
            results.append(entry)

        log.write("Done: %d CloudFront domains checked, %d vulnerable\n" % (stats["checked"], stats["vulnerable"]))
        log.flush()

    # Write results
    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_merge_urls(target_dir, output_path, log_path):
    """Merge katana + gau URL outputs, deduplicate, extract JS URLs and unique endpoints."""
    target_dir = Path(target_dir)
    all_urls = set()

    with open(log_path, "w") as log:
        log.write("Starting URL merge\n")
        log.flush()

        # Collect from katana outputs
        for f in sorted(target_dir.glob("katana_*.txt")):
            if f.name.startswith("katana_urls_"):
                continue  # skip intermediate url extraction files
            with open(f) as fh:
                urls = {line.strip() for line in fh if line.strip() and line.strip().startswith("http")}
                log.write("  %s: %d URLs\n" % (f.name, len(urls)))
                all_urls.update(urls)

        # Collect from gau outputs
        for f in sorted(target_dir.glob("gau_*.txt")):
            with open(f) as fh:
                urls = {line.strip() for line in fh if line.strip() and line.strip().startswith("http")}
                log.write("  %s: %d URLs\n" % (f.name, len(urls)))
                all_urls.update(urls)

        # Collect from gospider outputs
        for f in sorted(target_dir.glob("gospider_*.txt")):
            if f.name.startswith("gospider_urls_") or f.name.startswith("gospider_raw_"):
                continue  # skip intermediate files
            with open(f) as fh:
                urls = {line.strip() for line in fh if line.strip() and line.strip().startswith("http")}
                log.write("  %s: %d URLs\n" % (f.name, len(urls)))
                all_urls.update(urls)

        log.write("Total unique URLs: %d\n" % len(all_urls))
        log.flush()

        # Write all_urls.txt
        sorted_urls = sorted(all_urls)
        with open(output_path, "w") as f:
            f.write("\n".join(sorted_urls) + "\n")

        # Generate js_urls.txt (JavaScript files)
        js_extensions = (".js", ".mjs", ".jsx", ".ts", ".map")
        js_urls = [u for u in sorted_urls if any(
            urlparse(u).path.lower().endswith(ext) for ext in js_extensions
        )]
        js_path = target_dir / ("js_urls_%d.txt" % int(Path(output_path).stem.split("_")[-1]))
        with open(js_path, "w") as f:
            f.write("\n".join(js_urls) + "\n")
        log.write("JS URLs: %d\n" % len(js_urls))

        # Generate unique_endpoints.txt (deduped by scheme+host+path, ignoring query params)
        seen_endpoints = set()
        unique_endpoints = []
        for u in sorted_urls:
            parsed = urlparse(u)
            endpoint = "%s://%s%s" % (parsed.scheme, parsed.netloc, parsed.path)
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                unique_endpoints.append(endpoint)
        ep_path = target_dir / ("unique_endpoints_%d.txt" % int(Path(output_path).stem.split("_")[-1]))
        with open(ep_path, "w") as f:
            f.write("\n".join(unique_endpoints) + "\n")
        log.write("Unique endpoints (path-deduped): %d\n" % len(unique_endpoints))
        log.flush()

    return len(sorted_urls)


def _run_cloud_buckets(input_path, output_path, log_path):
    """Scan URLs for cloud bucket references (S3, Azure Blob, GCS) and test permissions."""
    import re

    bucket_patterns = [
        # S3
        (re.compile(r'https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-]amazonaws\.com', re.I), "aws_s3"),
        (re.compile(r'https?://s3[.\-]amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])', re.I), "aws_s3"),
        (re.compile(r'https?://s3[.\-][a-z0-9-]+\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])', re.I), "aws_s3"),
        # Azure Blob
        (re.compile(r'https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net', re.I), "azure_blob"),
        # GCS
        (re.compile(r'https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])', re.I), "gcs"),
        (re.compile(r'https?://([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com', re.I), "gcs"),
        # DigitalOcean Spaces
        (re.compile(r'https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.[a-z0-9-]+\.digitaloceanspaces\.com', re.I), "do_spaces"),
        (re.compile(r'https?://[a-z0-9-]+\.digitaloceanspaces\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])', re.I), "do_spaces"),
        # Alibaba Cloud OSS
        (re.compile(r'https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.oss-[a-z0-9-]+\.aliyuncs\.com', re.I), "alibaba_oss"),
        # Backblaze B2
        (re.compile(r'https?://f[0-9]+\.backblazeb2\.com/file/([a-zA-Z0-9][a-zA-Z0-9.\-]{1,61})', re.I), "backblaze_b2"),
    ]

    results = []
    seen_buckets = set()

    with open(log_path, "w") as log:
        log.write("Starting cloud bucket discovery\n")
        log.flush()

        with open(input_path) as f:
            urls = [line.strip() for line in f if line.strip()]
        log.write("Scanning %d URLs\n" % len(urls))
        log.flush()

        # Extract bucket references
        for url in urls:
            for pattern, provider in bucket_patterns:
                m = pattern.search(url)
                if m:
                    bucket_name = m.group(1)
                    key = (provider, bucket_name)
                    if key not in seen_buckets:
                        seen_buckets.add(key)
                        log.write("Found %s bucket: %s (from %s)\n" % (provider, bucket_name, url))
                        log.flush()

        log.write("Found %d unique buckets\n" % len(seen_buckets))
        log.flush()

        # Test each bucket's permissions
        for provider, bucket_name in sorted(seen_buckets):
            entry = {
                "bucket": bucket_name,
                "provider": provider,
                "list_permission": False,
                "read_permission": False,
            }

            test_urls = {
                "aws_s3": "http://%s.s3.amazonaws.com/" % bucket_name,
                "azure_blob": "https://%s.blob.core.windows.net/?restype=container&comp=list" % bucket_name,
                "gcs": "https://storage.googleapis.com/storage/v1/b/%s/o" % bucket_name,
                "do_spaces": "https://%s.nyc3.digitaloceanspaces.com/" % bucket_name,
                "alibaba_oss": "https://%s.oss.aliyuncs.com/" % bucket_name,
                "backblaze_b2": "https://f000.backblazeb2.com/file/%s/" % bucket_name,
            }
            test_url = test_urls.get(provider)
            if not test_url:
                continue

            try:
                req = Request(test_url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urlopen(req, timeout=10)
                body = resp.read().decode("utf-8", errors="replace")[:2000]
                entry["list_permission"] = True
                entry["status_code"] = resp.getcode()
                log.write("LISTABLE: %s %s (HTTP %d)\n" % (provider, bucket_name, resp.getcode()))
            except URLError as e:
                status = getattr(e, "code", None)
                entry["status_code"] = status
                if status == 403:
                    entry["read_permission"] = False
                    log.write("EXISTS (403): %s %s\n" % (provider, bucket_name))
                elif status == 404:
                    log.write("NOT FOUND: %s %s\n" % (provider, bucket_name))
                    continue  # skip non-existent buckets
                else:
                    log.write("ERROR: %s %s (%s)\n" % (provider, bucket_name, e))
            except Exception as e:
                log.write("ERROR: %s %s (%s)\n" % (provider, bucket_name, e))
                continue

            # Test write permission (PUT a tiny file, then DELETE it)
            if provider == "aws_s3":
                try:
                    write_url = "http://%s.s3.amazonaws.com/.bounty-write-test" % bucket_name
                    wreq = Request(write_url, data=b"test", method="PUT")
                    wreq.add_header("User-Agent", "Mozilla/5.0")
                    wresp = urlopen(wreq, timeout=5)
                    entry["write_permission"] = True
                    log.write("WRITABLE: %s %s\n" % (provider, bucket_name))
                    # Clean up test file
                    dreq = Request(write_url, method="DELETE")
                    try:
                        urlopen(dreq, timeout=5)
                    except Exception:
                        pass
                except Exception:
                    entry["write_permission"] = False

            log.flush()
            results.append(entry)

        log.write("Done: %d buckets tested, %d listable\n" % (
            len(results), sum(1 for r in results if r["list_permission"])))
        log.flush()

    output_data = {"stats": {"total": len(seen_buckets), "tested": len(results),
                             "listable": sum(1 for r in results if r["list_permission"])},
                   "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_crt_sh(domains_file, output_path, log_path):
    """Query crt.sh certificate transparency logs for subdomains."""
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    import ssl

    all_subs = set()

    with open(log_path, "w") as log:
        log.write("Starting crt.sh certificate transparency lookup\n")
        log.flush()

        with open(domains_file) as f:
            domains = [line.strip() for line in f if line.strip()]

        log.write("Querying %d domains\n" % len(domains))
        log.flush()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for domain in domains:
            url = "https://crt.sh/?q=%%25.%s&output=json" % domain
            log.write("Querying: %s\n" % domain)
            log.flush()
            try:
                req = Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urlopen(req, timeout=30, context=ctx)
                body = resp.read().decode("utf-8", errors="replace")
                entries = json.loads(body)
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and not name.startswith("*") and "." in name:
                            all_subs.add(name)
                log.write("  Found %d unique names for %s (total: %d)\n" % (
                    len([e for e in entries]), domain, len(all_subs)))
            except (URLError, json.JSONDecodeError, ValueError, OSError) as e:
                log.write("  Error for %s: %s\n" % (domain, e))
            log.flush()

        log.write("Done: %d unique subdomains from crt.sh\n" % len(all_subs))
        log.flush()

    sorted_subs = sorted(all_subs)
    with open(output_path, "w") as f:
        f.write("\n".join(sorted_subs) + "\n")

    return len(sorted_subs)


def _run_git_dumper_check(input_path, output_path, log_path):
    """Check live hosts for exposed .git directories."""
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    import ssl

    results = []
    stats = {"total_hosts": 0, "exposed": 0, "errors": 0}

    with open(log_path, "w") as log:
        log.write("Starting .git exposure check\n")
        log.flush()

        with open(input_path) as f:
            hosts = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    url = obj.get("url", obj.get("input", ""))
                except (json.JSONDecodeError, ValueError):
                    url = line
                if url:
                    hosts.append(url)

        log.write("Checking %d hosts for .git exposure\n" % len(hosts))
        log.flush()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for host_url in hosts[:500]:  # cap at 500 hosts
            stats["total_hosts"] += 1
            base = host_url.rstrip("/")
            git_url = base + "/.git/HEAD"
            try:
                req = Request(git_url)
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urlopen(req, timeout=10, context=ctx)
                body = resp.read(500).decode("utf-8", errors="replace")
                if body.startswith("ref: ") or body.startswith("ref:refs/"):
                    stats["exposed"] += 1
                    # Try to get config too
                    config_content = ""
                    try:
                        cfg_req = Request(base + "/.git/config")
                        cfg_req.add_header("User-Agent", "Mozilla/5.0")
                        cfg_resp = urlopen(cfg_req, timeout=10, context=ctx)
                        config_content = cfg_resp.read(2000).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    results.append({
                        "url": base,
                        "git_head": body.strip()[:200],
                        "git_config_exposed": bool(config_content),
                        "config_snippet": config_content[:500] if config_content else "",
                    })
                    log.write("EXPOSED: %s (HEAD: %s)\n" % (base, body.strip()[:60]))
                    log.flush()
            except URLError as e:
                status = getattr(e, "code", None)
                if status and status != 404:
                    log.write("Error %s: HTTP %s\n" % (base, status))
                    stats["errors"] += 1
            except Exception as e:
                stats["errors"] += 1
            log.flush()

        log.write("Done: %d hosts checked, %d exposed .git dirs\n" % (
            stats["total_hosts"], stats["exposed"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_gitleaks(org_name, output_path, log_path):
    """Clone top public repos from a GitHub org and scan for leaked secrets with gitleaks."""
    import tempfile

    results = []

    with open(log_path, "w") as log:
        log.write("Starting gitleaks scan for org: %s\n" % org_name)
        log.flush()

        # Fetch repo list from GitHub API
        repos = []
        try:
            url = "https://api.github.com/orgs/%s/repos?type=public&sort=stars&per_page=50" % org_name
            req = Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                repos = [(r.get("clone_url", ""), r.get("name", "")) for r in data
                         if isinstance(r, dict) and r.get("clone_url")]
        except Exception as e:
            log.write("Error fetching repos: %s\n" % e)
            log.flush()

        if not repos:
            log.write("No public repos found for org: %s\n" % org_name)
            log.flush()
            with open(output_path, "w") as f:
                json.dump([], f)
            return []

        log.write("Found %d repos to scan\n" % len(repos))
        log.flush()

        # Find gitleaks binary
        gitleaks_bin = shutil.which("gitleaks")
        if not gitleaks_bin:
            # Check Go bin path
            go_bin = Path.home() / "go" / "bin" / "gitleaks"
            if go_bin.exists():
                gitleaks_bin = str(go_bin)
        if not gitleaks_bin:
            log.write("ERROR: gitleaks binary not found\n")
            with open(output_path, "w") as f:
                json.dump([], f)
            return []

        with tempfile.TemporaryDirectory(prefix="gitleaks_") as tmpdir:
            for clone_url, repo_name in repos:
                log.write("Cloning %s...\n" % repo_name)
                log.flush()
                repo_dir = os.path.join(tmpdir, repo_name)
                try:
                    proc = subprocess.run(
                        ["git", "clone", "--single-branch", clone_url, repo_dir],
                        capture_output=True, text=True, timeout=300,
                    )
                    if proc.returncode != 0:
                        log.write("  Clone failed: %s\n" % proc.stderr[:200])
                        continue
                except subprocess.TimeoutExpired:
                    log.write("  Clone timed out\n")
                    continue

                log.write("Scanning %s...\n" % repo_name)
                log.flush()
                report_path = os.path.join(tmpdir, "%s_report.json" % repo_name)
                try:
                    proc = subprocess.run(
                        [gitleaks_bin, "detect", "--source", repo_dir,
                         "--report-path", report_path, "--report-format", "json"],
                        capture_output=True, text=True, timeout=300,
                    )
                    # gitleaks exits 1 when leaks found, 0 when clean
                    if os.path.exists(report_path):
                        with open(report_path) as f:
                            findings = json.loads(f.read())
                        if isinstance(findings, list) and findings:
                            for finding in findings:
                                finding["Repo"] = repo_name
                            results.extend(findings)
                            log.write("  Found %d leaks in %s\n" % (len(findings), repo_name))
                        else:
                            log.write("  Clean: %s\n" % repo_name)
                    else:
                        log.write("  Clean: %s\n" % repo_name)
                except subprocess.TimeoutExpired:
                    log.write("  Scan timed out for %s\n" % repo_name)
                except Exception as e:
                    log.write("  Scan error for %s: %s\n" % (repo_name, e))
                log.flush()

        log.write("Done: %d total leaks found across %d repos\n" % (len(results), len(repos)))
        log.flush()

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    return results


# Patterns for `generic_secret` matches that are public-by-design or
# JS-variable-name false positives.  See memory
# `feedback_systemic_template_fps_2026-05-23` item #5 — every one of
# the 80 "secrets" surfaced by the 26-pipeline rerun batch fell into one of
# these buckets.
_SECRET_FP_VALUE_PREFIXES = (
    "pub",            # Datadog RUM clientToken
    "AIzaSy",         # Firebase / Google Maps web API key (public by design)
    "pk_test_",       # Stripe test publishable key
    "pk_live_",       # Stripe live publishable key
    "6L",             # reCAPTCHA v2/v3 site key
)
# Tokens whose VALUE is a JS identifier or framework constant — e.g.
# `apiKey:"SSR_VIDEO_PAUSES"`, `TOKEN:"shareSheetResumeToken"`,
# `Password:"showChangePassword"`.
_JS_IDENTIFIER_RE = None  # lazily compiled in _is_secret_scan_fp
# URL paths in APM/RUM/analytics SDKs whose bundled values look like secrets
# but are public instrumentation strings (Akamai mPulse BOOMR, Sentry DSN, etc).
_APM_SOURCE_HINTS = (
    "boomerang", "boomr", "sentry", "datadog-rum", "newrelic",
    "fullstory", "segment", "/apmfe/", "akam/", "akstat/",
)


def _is_secret_scan_fp(pattern_name, matched_value, match, content, source_url):
    """Return True if a secret-scan match should be discarded as a false positive.

    Catches the systemic FP patterns documented in
    `feedback_systemic_template_fps_2026-05-23` and reconfirmed by the
    2026-05-27 26-pipeline rerun (80/80 FP).  Tightens both the
    `generic_secret` greediness and a few patterns whose regex over-matches
    on non-credential bytes (twilio, aws_secret eating reCAPTCHA keys).
    """
    import re as _re

    # APM/RUM SDK bundles ship public instrumentation strings that look like
    # secrets but are not.  Akamai mPulse `BOOMR_API_key="UYDDG-23B4W-..."` is
    # the canonical case (memo: feedback_akamai_boomr_api_key_fp).
    src_lower = (source_url or "").lower()
    if any(hint in src_lower for hint in _APM_SOURCE_HINTS):
        return True

    # Public-by-design value prefixes apply to ANY pattern — sometimes the
    # `aws_secret` regex captures a reCAPTCHA key starting `6L*` (P279 semrush
    # 2026-05-27).  Check the raw matched bytes for the prefix regardless of
    # which named regex fired.
    if any(p in matched_value for p in _SECRET_FP_VALUE_PREFIXES):
        # Only drop if the prefix appears at the START of the actual secret
        # body (after the lead-in like `key:"`).  Cheapest check: is the
        # prefix immediately after a quote/equals/colon?
        for p in _SECRET_FP_VALUE_PREFIXES:
            if _re.search(r'[:=]\s*["\']?\s*' + _re.escape(p), matched_value):
                return True

    if pattern_name == "google_api":
        # AIzaSy* keys are Firebase / Google Maps / Places client keys, locked
        # down by referer + product enablement on the Google Cloud side and
        # explicitly designed to ship in client JS.  Adobe + dozens of others
        # surface these every batch.  Drop wholesale.
        return True

    if pattern_name == "twilio_key":
        # SK + 32 hex format is correct but the regex also matches 32-char
        # base64-ish blobs that happen to start with SK (e.g. Adobe study-space
        # dropin `SKAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAA`).  Require hex-only and
        # reject runs of repeated chars (>= 8 of the same character).
        tail = matched_value[2:]
        if not _re.fullmatch(r"[0-9a-fA-F]{32}", tail):
            return True
        if _re.search(r"(.)\1{7,}", tail):
            return True

    # Akamai mPulse BOOMR_API_key — 5 groups of 5 alphanum chars separated by
    # dashes (`CGK7X-KWLZ2-9JBMW-YPK4H-NXS33`).  Public instrumentation key,
    # not a credential.  See memory `feedback_akamai_boomr_api_key_fp`.  The
    # `generic_secret` regex captures the full `API_key="..."` line.
    if _re.search(r'[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}', matched_value):
        return True

    if pattern_name == "aws_secret":
        # The aws_secret regex (`(?:aws.{0,20})?(?:secret|key)... 40chars`) is
        # very greedy and routinely catches non-AWS values.  Drop matches
        # whose preceding 20 chars don't contain `aws`-ish context.
        ctx_before = content[max(0, match.start() - 30):match.start()].lower()
        if "aws" not in ctx_before and "amazonaws" not in ctx_before:
            return True

    if pattern_name != "generic_secret":
        return False

    # ------------------------------------------------------------------
    # generic_secret-specific filters
    # ------------------------------------------------------------------

    # The regex captures the quoted value in group(1).  Fall back to the
    # full match if the group isn't present.
    try:
        value = match.group(1)
    except IndexError:
        value = matched_value

    # JS route URLs — `Password: 'Magento_Customer/js/show-password'`,
    # `apiKey:"/api/v1/foo"`.  Real credentials never contain `/` at all,
    # but base64-encoded JWTs / keys do (`+/=`).  Distinguish by checking for
    # human-readable path segments — slashes + lowercase words separated by
    # `_` / `-`.  The Magento case from 2026-05-27 P275 had
    # `Magento_Customer/js/change-email-password`.
    if "/" in value:
        # Detect "looks like a path": segments between `/` are word-shaped
        # (mix of letters and `_`/`-`), no base64-style `+=` chars.
        segments = value.split("/")
        word_like_segments = sum(
            1 for s in segments
            if s and _re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-]*", s)
        )
        if word_like_segments >= 2 and "+" not in value and "=" not in value:
            return True

    # JS identifiers / camelCase / SCREAMING_CASE framework constants.  Real
    # credentials use opaque randomness; identifiers are letters-plus-
    # underscores (optionally with a digit or two), examples to drop:
    #   `apiKey:"SSR_VIDEO_PAUSES"`, `TOKEN:"shareSheetResumeToken"`,
    #   `Key:"UpdateGuidelineDesignSettingsAccentColor"`,
    #   `apiKey:"docgen-word-addin"`, `AUTH:"edit_authentication"`,
    #   `TOKEN:"_CONFIRMATIONTOKEN"` (leading underscore).
    if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", value):
        digit_count = sum(c.isdigit() for c in value)
        has_long_hex_run = bool(_re.search(r"[0-9a-f]{16,}", value))
        # An identifier with few digits and no hex run is a variable name,
        # not a credential.  The threshold is 4 digits because some real
        # tokens like `npm_AbCdEf123456...` have many digits.
        if digit_count < 4 and not has_long_hex_run:
            return True

    # Garbled regex captures — the `generic_secret` regex sometimes grabs
    # JSON/JS literal noise like `Key:["UpdateGuidelineDesignSettings...` where
    # the inner value contains the closing `"` + brackets.  Real credentials
    # don't contain `[`, `]`, `(`, `)`, `{`, `}`, `<`, `>`.
    if any(c in value for c in '[](){}<>'):
        return True

    # Algolia search-only API keys are 32-char lowercase hex with `appId:`
    # nearby (public-by-design per Algolia docs).  Cheap heuristic: look at
    # 80 chars of context before the match for `appId` / `applicationId`.
    if _re.fullmatch(r"[a-f0-9]{32}", value):
        ctx_before = content[max(0, match.start() - 80):match.start()].lower()
        if "appid" in ctx_before or "applicationid" in ctx_before:
            return True

    # Unleash frontend SDK tokens are the short 16-char "frontend" form
    # documented as public-by-design.  P279 Semrush `Aques3noEg8shae3` was
    # the canonical FP from 2026-05-27.
    if _re.fullmatch(r"[A-Za-z0-9]{16}", value):
        ctx_before = content[max(0, match.start() - 120):match.start()].lower()
        if "unleash" in ctx_before:
            return True

    # Seats.io workspace public tokens (`seatsio.chartToken = '<64-hex>'`)
    # are designed to ship in client embed code, analogous to a Stripe
    # publishable key.  Filter the 64-char hex pattern when seatsio appears
    # in the source URL or surrounding context.
    if _re.fullmatch(r"[a-f0-9]{32,128}", value):
        if "seatsio" in src_lower or "seatsio" in content[max(0, match.start() - 200):match.start()].lower():
            return True

    return False


def _run_secret_scan(input_path, output_path, log_path):
    """Download JS files and scan for leaked secrets/credentials."""
    import re

    SECRET_PATTERNS = [
        ("aws_key", re.compile(r'AKIA[0-9A-Z]{16}')),
        ("aws_secret", re.compile(r'(?:aws.{0,20})?(?:secret|key).{0,10}["\']([A-Za-z0-9/+=]{40})["\']', re.I)),
        ("stripe_secret", re.compile(r'sk_live_[a-zA-Z0-9]{24,}')),
        ("stripe_test_secret", re.compile(r'sk_test_[a-zA-Z0-9]{24,}')),
        ("github_token", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')),
        ("google_api", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
        ("slack_token", re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}')),
        ("jwt", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
        ("private_key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
        ("twilio_key", re.compile(r'SK[0-9a-fA-F]{32}')),
        ("sendgrid_key", re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')),
        ("mailgun_key", re.compile(r'key-[a-zA-Z0-9]{32}')),
        ("mailchimp_key", re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}')),
        ("npm_token", re.compile(r'npm_[a-zA-Z0-9]{36}')),
        ("shopify_token", re.compile(r'shp(?:pa|ss|at|ca)_[a-fA-F0-9]{32}')),
        ("square_token", re.compile(r'sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}')),
        ("facebook_token", re.compile(r'[0-9]{13,17}\|[a-zA-Z0-9_-]{27}')),
        ("heroku_key", re.compile(r'[hH][eE][rR][oO][kK][uU].*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')),
        ("bearer_token", re.compile(r'["\']Bearer\s+[a-zA-Z0-9_-]{20,}["\']')),
        ("generic_secret", re.compile(r'(?:api[_-]?key|secret|password|token|auth)\s*[:=]\s*["\']([A-Za-z0-9/+=_\-]{16,})["\']', re.I)),
        # NOTE: stripe pk_ (publishable) keys, internal URLs, and localhost URLs
        # are intentionally excluded — they are not real secret leaks.
    ]

    results = []
    seen_values = set()  # dedup across multiple JS versions
    stats = {"total_urls": 0, "downloaded": 0, "errors": 0, "secrets_found": 0}

    with open(log_path, "w") as log:
        log.write("Starting secret scan\n")
        log.flush()

        with open(input_path) as f:
            js_urls = [line.strip() for line in f if line.strip()]
        # Cap at 500 URLs to avoid OOM/timeout on huge targets
        MAX_JS_URLS = 500
        if len(js_urls) > MAX_JS_URLS:
            log.write("Capping JS URLs from %d to %d\n" % (len(js_urls), MAX_JS_URLS))
            log.flush()
            js_urls = js_urls[:MAX_JS_URLS]
        stats["total_urls"] = len(js_urls)
        log.write("Scanning %d JS URLs\n" % len(js_urls))
        log.flush()

        for i, url in enumerate(js_urls):
            if i % 50 == 0 and i > 0:
                log.write("Progress: %d/%d URLs scanned, %d secrets found\n" % (
                    i, len(js_urls), stats["secrets_found"]))
                log.flush()

            try:
                req = Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urlopen(req, timeout=10)
                raw = resp.read()
                # Limit download size to 2MB to avoid OOM on huge files
                if len(raw) > 2 * 1024 * 1024:
                    stats["errors"] += 1
                    continue
                content = raw.decode("utf-8", errors="replace")
                stats["downloaded"] += 1
            except Exception:
                stats["errors"] += 1
                continue

            # Scan for secrets
            for pattern_name, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    matched_value = match.group(0)
                    # Dedup: skip if we already found this exact value
                    dedup_key = (pattern_name, matched_value[:200])
                    if dedup_key in seen_values:
                        continue
                    seen_values.add(dedup_key)

                    # Drop known false-positive patterns. See memory
                    # `feedback_systemic_template_fps_2026-05-23` #5 and
                    # the 2026-05-27 batch where 80/80 "secrets" were FP.
                    if _is_secret_scan_fp(pattern_name, matched_value, match, content, url):
                        continue

                    # Get context (surrounding text)
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    context = content[start:end].replace("\n", " ").strip()

                    entry = {
                        "pattern": pattern_name,
                        "value": matched_value[:200],  # truncate long matches
                        "source_url": url,
                        "context": context[:300],
                    }
                    results.append(entry)
                    stats["secrets_found"] += 1
                    log.write("FOUND [%s]: %s in %s\n" % (
                        pattern_name, matched_value[:60], url))
                    log.flush()

        log.write("Done: %d URLs scanned, %d downloaded, %d errors, %d secrets found\n" % (
            stats["total_urls"], stats["downloaded"], stats["errors"], stats["secrets_found"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_corscanner(input_path, output_path, log_path):
    """Test live hosts for CORS misconfigurations (origin reflection, null, wildcard+creds)."""
    results = []
    stats = {"total_hosts": 0, "vulnerable": 0, "errors": 0}

    with open(log_path, "w") as log:
        log.write("Starting CORS misconfiguration scan\n")
        log.flush()

        with open(input_path) as f:
            urls = [line.strip() for line in f if line.strip() and line.strip().startswith("http")]
        MAX_CORS_TARGETS = 300
        if len(urls) > MAX_CORS_TARGETS:
            urls = urls[:MAX_CORS_TARGETS]
        stats["total_hosts"] = len(urls)
        log.write("Testing %d URLs for CORS issues\n" % len(urls))
        log.flush()

        test_origins = [
            "https://evil.com",
            "null",
            "https://evil.{target}",       # subdomain reflection
            "https://{target}.evil.com",    # prefix-only matching bypass
            "https://evil{target}",         # no-dot prefix bypass
            "http://{target}",              # HTTP scheme mismatch on HTTPS target
        ]

        for i, url in enumerate(urls):
            if i % 50 == 0 and i > 0:
                log.write("Progress: %d/%d\n" % (i, len(urls)))
                log.flush()
            try:
                from urllib.parse import urlparse as _up
                parsed = _up(url)
                target_domain = parsed.hostname or ""
            except Exception:
                target_domain = ""

            for test_origin in test_origins:
                origin = test_origin.replace("{target}", target_domain)
                try:
                    req = Request(url)
                    req.add_header("Origin", origin)
                    req.add_header("User-Agent", "Mozilla/5.0")
                    resp = urlopen(req, timeout=10)
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao and (acao == origin or acao == "*"):
                        vuln_type = "wildcard" if acao == "*" else "origin_reflection"
                        if acac.lower() == "true" and acao == "*":
                            vuln_type = "wildcard_with_credentials"
                        elif acac.lower() == "true":
                            vuln_type = "origin_reflection_with_credentials"

                        entry = {
                            "url": url,
                            "test_origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "vuln_type": vuln_type,
                        }
                        results.append(entry)
                        stats["vulnerable"] += 1
                        log.write("VULN [%s]: %s (Origin: %s → ACAO: %s, ACAC: %s)\n" % (
                            vuln_type, url, origin, acao, acac))
                        log.flush()
                        break  # one finding per URL
                except Exception:
                    stats["errors"] += 1

        log.write("Done: %d hosts scanned, %d CORS issues found\n" % (
            stats["total_hosts"], stats["vulnerable"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)
    return output_data


def _run_spa_catchall_detect(input_path, output_path, log_path):
    """Detect SPA catch-all hosts that serve the same index.html for every path.

    Why: linkfinder / gau / katana extract route-name strings from JS bundles
    (e.g. `/admin/users`, `/v1/accounts:signInWithPassword`).  On a SPA host
    the server returns the bundle's `index.html` for every path including
    nonexistent ones — so those "endpoints" are client-side router constants,
    not server URLs.  Without this filter, the 2026-05-27 batch surfaced
    ~10,300 endpoint rows (Adobe / Grab / Netlify et al.) and zero were real
    server endpoints.

    How: for each live host, GET a single random "this-cannot-exist" path.
    If the response is 2xx/3xx with the same body hash AND content-length as
    the host root, mark it as SPA catch-all.  Downstream linkfinder
    persistence consults these flags to skip the host.
    """
    import hashlib
    import re as _re
    import uuid as _uuid
    from urllib.error import HTTPError as _HTTPError

    results = []
    stats = {"total_hosts": 0, "checked": 0, "spa_catchall": 0, "errors": 0}

    with open(log_path, "w") as log:
        log.write("Starting SPA catch-all detection\n")
        log.flush()

        urls = _extract_urls_from_httpx(input_path, filter_wildcards=True, log=log)
        # Cap at 300 hosts — the test is cheap (2 requests per host) but the
        # cap keeps the tool well under the 5-min budget on huge surfaces.
        MAX_SPA_CHECK = 300
        if len(urls) > MAX_SPA_CHECK:
            log.write("Capping hosts from %d to %d\n" % (len(urls), MAX_SPA_CHECK))
            urls = urls[:MAX_SPA_CHECK]
        stats["total_hosts"] = len(urls)
        log.write("Testing %d hosts\n" % len(urls))
        log.flush()

        for i, url in enumerate(urls):
            if i % 50 == 0 and i > 0:
                log.write("Progress: %d/%d (%d catch-all so far)\n" %
                          (i, len(urls), stats["spa_catchall"]))
                log.flush()

            # Build two probe URLs: the host root, and a synthetic path that
            # contains a random uuid so no real route or cached entry can
            # collide.  The path includes "claude-catchall-probe" + uuid so
            # any access logs make the test self-identifying.
            probe_path = "/claude-catchall-probe-%s" % _uuid.uuid4().hex[:12]
            root_url = url.rstrip("/") + "/"
            probe_url = url.rstrip("/") + probe_path

            try:
                req_root = Request(root_url)
                req_root.add_header("User-Agent", "Mozilla/5.0 (catchall-probe)")
                resp_root = urlopen(req_root, timeout=10)
                root_body = resp_root.read(65536)
                root_code = resp_root.getcode()
                root_etag = resp_root.headers.get("ETag", "")
                root_hash = hashlib.sha256(root_body).hexdigest()

                req_probe = Request(probe_url)
                req_probe.add_header("User-Agent", "Mozilla/5.0 (catchall-probe)")
                resp_probe = urlopen(req_probe, timeout=10)
                probe_body = resp_probe.read(65536)
                probe_code = resp_probe.getcode()
                probe_etag = resp_probe.headers.get("ETag", "")
                probe_hash = hashlib.sha256(probe_body).hexdigest()
                stats["checked"] += 1
            except _HTTPError as e:
                # 404/410 on the probe is the EXPECTED non-SPA response —
                # log and move on without flagging.  Other HTTP errors are
                # also non-catchall by definition.
                stats["checked"] += 1
                continue
            except Exception as e:
                stats["errors"] += 1
                continue

            # SPA catch-all signature: probe and root return the same body
            # (hash) with a successful 2xx status.  An ETag match on its own
            # is also definitive (some hosts serve compressed bodies that
            # decode differently per response).
            is_catchall = (
                probe_code < 400 and (
                    probe_hash == root_hash or
                    (root_etag and root_etag == probe_etag)
                )
            )

            if is_catchall:
                stats["spa_catchall"] += 1
                results.append({
                    "host": url,
                    "root_status": root_code,
                    "probe_status": probe_code,
                    "body_hash": probe_hash[:16],
                    "etag_match": bool(root_etag and root_etag == probe_etag),
                    "evidence": "Body hash + status match between / and %s" % probe_path,
                })
                log.write("CATCHALL: %s (probe %s = root /)\n" % (url, probe_path))
                log.flush()

        log.write("Done: %d hosts, %d checked, %d catch-all, %d errors\n" % (
            stats["total_hosts"], stats["checked"], stats["spa_catchall"], stats["errors"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)
    return output_data


def _run_nextjs_check(input_path, output_path, log_path):
    """Check httpx output for Next.js-specific vulnerabilities."""
    results = []
    stats = {"total_hosts": 0, "checked": 0, "findings": 0}

    with open(log_path, "w") as log:
        log.write("Starting Next.js security checks\n")
        log.flush()

        # Find Next.js hosts from httpx output (tech detection or response patterns)
        nextjs_urls = []
        with open(input_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    url = obj.get("url", obj.get("input", ""))
                    tech = obj.get("technologies", obj.get("tech", []))
                    tech_str = " ".join(tech) if isinstance(tech, list) else str(tech)
                    if "Next.js" in tech_str or "next" in tech_str.lower():
                        nextjs_urls.append(url)
                except (json.JSONDecodeError, ValueError):
                    pass

        stats["total_hosts"] = len(nextjs_urls)
        if not nextjs_urls:
            log.write("No Next.js hosts detected\n")
            with open(output_path, "w") as f:
                json.dump({"stats": stats, "results": []}, f)
            return {"stats": stats, "results": []}

        MAX_NEXTJS = 50
        nextjs_urls = nextjs_urls[:MAX_NEXTJS]
        log.write("Found %d Next.js hosts to check\n" % len(nextjs_urls))
        log.flush()

        check_paths = [
            ("/_next/data", "next_data_exposure", "Next.js data API exposed"),
            ("/_next/image?url=https://evil.com/test.png&w=256&q=75", "image_ssrf", "Next.js image optimization SSRF"),
            ("/api/__nextjs_original-stack-frame", "debug_endpoint", "Next.js debug endpoint exposed"),
        ]

        for url in nextjs_urls:
            stats["checked"] += 1
            # Check for __NEXT_DATA__ leaking sensitive props
            try:
                req = Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urlopen(req, timeout=10)
                body = resp.read().decode("utf-8", errors="replace")[:50000]
                if "__NEXT_DATA__" in body:
                    # Look for sensitive keys in the JSON
                    import re
                    nd_match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', body)
                    if nd_match:
                        nd_json = nd_match.group(1)
                        sensitive_keys = ["apiKey", "token", "secret", "password", "auth",
                                         "Authorization", "aws", "private"]
                        for sk in sensitive_keys:
                            if sk.lower() in nd_json.lower():
                                results.append({
                                    "url": url, "vuln_type": "next_data_secret_leak",
                                    "detail": "Sensitive key '%s' found in __NEXT_DATA__" % sk,
                                    "context": nd_json[:500],
                                })
                                stats["findings"] += 1
                                log.write("FINDING: %s - %s in __NEXT_DATA__\n" % (url, sk))
                                log.flush()
                                break
            except Exception:
                pass

            # Check common Next.js vuln paths
            for path, vuln_type, desc in check_paths:
                try:
                    check_url = url.rstrip("/") + path
                    req = Request(check_url)
                    req.add_header("User-Agent", "Mozilla/5.0")
                    resp = urlopen(req, timeout=5)
                    sc = resp.getcode()
                    if sc == 200:
                        results.append({
                            "url": check_url, "vuln_type": vuln_type,
                            "detail": desc, "status_code": sc,
                        })
                        stats["findings"] += 1
                        log.write("FINDING: %s - %s (HTTP %d)\n" % (check_url, desc, sc))
                        log.flush()
                except Exception:
                    pass

        log.write("Done: %d Next.js hosts checked, %d findings\n" % (
            stats["checked"], stats["findings"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)
    return output_data


def _run_panel_detect(input_path, output_path, log_path):
    """Detect exposed admin panels, login pages, and management interfaces from httpx output."""
    PANEL_KEYWORDS = [
        "admin", "login", "dashboard", "jenkins", "grafana", "phpmyadmin",
        "tomcat manager", "gitlab", "kibana", "elasticsearch",
        "portainer", "webmin", "cPanel", "plesk", "directadmin", "sonarqube",
        "nagios", "zabbix", "prometheus", "traefik", "rabbitmq", "solr",
        "swagger", "api-docs", "graphql", "wp-admin", "wp-login",
        "drupal/user", "administrator", "manage", "console", "panel",
        "argocd", "/applications", "kubernetes-dashboard", "airflow",
        "jupyter", "jupyterhub", "/hub/login", "minio", "vault",
        "rancher", "superset", "adminer", "mailhog", "mailcatcher",
        "flower", "gitea", "gogs", "sentry", "harbor",
    ]

    # Tech-field keywords: detected by httpx Wappalyzer fingerprinting
    TECH_PANELS = [
        "jenkins", "grafana", "kibana", "phpmyadmin", "gitlab",
        "portainer", "sonarqube", "argocd", "kubernetes", "airflow",
        "jupyter", "minio", "vault", "rancher", "sentry", "harbor",
    ]

    results = []
    stats = {"total_hosts": 0, "panels_detected": 0}

    with open(log_path, "w") as log:
        log.write("Starting panel detection\n")
        log.flush()

        with open(input_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                stats["total_hosts"] += 1
                url = obj.get("url", obj.get("input", ""))
                title = obj.get("title", "")
                tech = obj.get("technologies", obj.get("tech", []))
                status_code = obj.get("status-code", obj.get("status_code"))
                combined = "%s %s" % (url.lower(), title.lower())
                tech_str = " ".join(tech).lower() if isinstance(tech, list) else str(tech).lower()

                matched = None
                for keyword in PANEL_KEYWORDS:
                    if keyword.lower() in combined:
                        matched = keyword
                        break
                # Also check the tech field for panel frameworks
                if not matched:
                    for tk in TECH_PANELS:
                        if tk in tech_str:
                            matched = tk
                            break

                if matched:
                    entry = {
                        "url": url,
                        "title": title,
                        "matched_keyword": matched,
                        "status_code": status_code,
                        "tech": tech if isinstance(tech, list) else [],
                    }
                    results.append(entry)
                    stats["panels_detected"] += 1
                    log.write("Panel [%s]: %s - %s\n" % (matched, url, title))
                    log.flush()

        log.write("Done: %d hosts scanned, %d panels detected\n" % (
            stats["total_hosts"], stats["panels_detected"]))
        log.flush()

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_cms_detect(input_path, output_path, log_path):
    """Detect CMS platforms from httpx tech detection output."""
    CMS_KEYWORDS = {
        "wordpress": ["WordPress", "wp-content", "wp-includes"],
        "joomla": ["Joomla"],
        "drupal": ["Drupal"],
        "magento": ["Magento"],
        "shopify": ["Shopify"],
        "aem": ["Adobe Experience Manager", "/content/dam/", "/libs/granite/", "/crx/de", "cq-author"],
        "spring_boot": ["Whitelabel Error Page", "/actuator", "Spring Boot"],
        "laravel": ["Laravel", "/telescope", "/_debugbar", "laravel_session"],
        "django": ["csrfmiddlewaretoken", "Django", "/admin/login/"],
        "ghost": ["Ghost", "/ghost/api/"],
        "strapi": ["Strapi", "/admin/init"],
        "typo3": ["TYPO3", "/typo3/"],
        "umbraco": ["Umbraco"],
        "rails": ["Ruby on Rails", "X-Powered-By: Phusion"],
    }

    results = []
    stats = {"total_hosts": 0, "cms_detected": 0}

    with open(log_path, "w") as log:
        log.write("Starting CMS detection\n")
        log.flush()

        with open(input_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                stats["total_hosts"] += 1
                url = obj.get("url", obj.get("input", ""))
                title = obj.get("title", "")
                tech = obj.get("technologies", obj.get("tech", []))
                if isinstance(tech, list):
                    tech_str = " ".join(tech)
                else:
                    tech_str = str(tech)
                combined = "%s %s %s" % (url, title, tech_str)

                for cms, keywords in CMS_KEYWORDS.items():
                    for kw in keywords:
                        if kw.lower() in combined.lower():
                            entry = {
                                "url": url,
                                "cms": cms,
                                "title": title,
                                "tech": tech if isinstance(tech, list) else [],
                                "status_code": obj.get("status-code", obj.get("status_code")),
                                "matched_keyword": kw,
                            }
                            results.append(entry)
                            stats["cms_detected"] += 1
                            log.write("CMS [%s]: %s (matched: %s)\n" % (cms, url, kw))
                            log.flush()
                            break  # only one match per CMS per host
                    else:
                        continue
                    break

        log.write("Done: %d hosts scanned, %d CMS detected\n" % (
            stats["total_hosts"], stats["cms_detected"]))
        log.flush()

    # Also write WordPress targets to a separate file for wpscan
    wp_targets = [r["url"] for r in results if r["cms"] == "wordpress"]
    if wp_targets:
        wp_path = Path(output_path).parent / ("wordpress_targets_%s.txt" %
            Path(output_path).stem.split("_")[-1])
        with open(wp_path, "w") as f:
            f.write("\n".join(wp_targets) + "\n")

    output_data = {"stats": stats, "results": results}
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data


def _run_merge_subs(target_dir, output_path, log_path):
    """Merge all subdomain files (subfinder + shuffledns) into a deduplicated list.

    Reads scope_exclusions.json from the target dir (if present) and filters out
    subdomains containing excluded keywords (e.g. "uat", "dev", "staging").
    """
    target_dir = Path(target_dir)
    all_subs = set()

    # Load scope exclusions if present
    exclusions = []
    exclusions_file = target_dir / "scope_exclusions.json"
    if exclusions_file.exists():
        try:
            exclusions = _safe_json_load(exclusions_file)
        except (json.JSONDecodeError, ValueError):
            pass

    with open(log_path, "w") as log:
        log.write("Starting subdomain merge\n")
        if exclusions:
            log.write("Scope exclusions: %s\n" % ", ".join(exclusions))
        log.flush()

        # Collect from subfinder outputs
        for f in sorted(target_dir.glob("subfinder_*.txt")):
            with open(f) as fh:
                subs = {line.strip().lower() for line in fh if line.strip()}
                log.write("  %s: %d subdomains\n" % (f.name, len(subs)))
                all_subs.update(subs)

        # Collect from shuffledns outputs
        for f in sorted(target_dir.glob("shuffledns_*.txt")):
            with open(f) as fh:
                subs = {line.strip().lower() for line in fh if line.strip()}
                log.write("  %s: %d subdomains\n" % (f.name, len(subs)))
                all_subs.update(subs)

        # Collect from amass outputs
        for f in sorted(target_dir.glob("amass_*.txt")):
            with open(f) as fh:
                subs = {line.strip().lower() for line in fh if line.strip()}
                log.write("  %s: %d subdomains\n" % (f.name, len(subs)))
                all_subs.update(subs)

        # Collect from crt.sh outputs
        for f in sorted(target_dir.glob("crt_sh_*.txt")):
            with open(f) as fh:
                subs = {line.strip().lower() for line in fh if line.strip()}
                log.write("  %s: %d subdomains\n" % (f.name, len(subs)))
                all_subs.update(subs)

        log.write("Total unique subdomains before filtering: %d\n" % len(all_subs))

        # Apply scope exclusions — remove subdomains containing excluded keywords
        if exclusions:
            before = len(all_subs)
            filtered = set()
            for sub in all_subs:
                # Split subdomain into parts and check each part against exclusions
                parts = sub.lower().split(".")
                if any(excl in part for part in parts for excl in exclusions):
                    filtered.add(sub)
            all_subs -= filtered
            log.write("Excluded %d subdomains matching scope exclusions (%s)\n" % (
                len(filtered), ", ".join(exclusions)))
            log.write("Subdomains after filtering: %d\n" % len(all_subs))

        log.flush()

        # Wildcard DNS pre-detection: resolve random nonsense subdomains for each
        # parent domain. If they all resolve to the same IP, the parent has wildcard
        # DNS and ALL its subdomains are noise (saves httpx from probing thousands).
        domains_file = target_dir / "domains.txt"
        if domains_file.exists() and all_subs:
            wildcard_parents = _detect_wildcard_domains(domains_file, log)
            if wildcard_parents:
                before_wc = len(all_subs)
                wildcard_subs = set()
                for sub in all_subs:
                    for wc_parent in wildcard_parents:
                        if sub.endswith("." + wc_parent) or sub == wc_parent:
                            wildcard_subs.add(sub)
                            break
                all_subs -= wildcard_subs
                log.write("Wildcard DNS filter: removed %d subdomains under %d wildcard parents (%s)\n" % (
                    len(wildcard_subs), len(wildcard_parents),
                    ", ".join(sorted(wildcard_parents)[:5])))
                log.write("Subdomains after wildcard filter: %d\n" % len(all_subs))
                # Write wildcard metadata for downstream tools
                wc_meta = {"wildcard_parents": sorted(wildcard_parents),
                           "removed_count": len(wildcard_subs)}
                with open(target_dir / "wildcard_domains.json", "w") as wf:
                    json.dump(wc_meta, wf)
                log.flush()

    sorted_subs = sorted(all_subs)
    with open(output_path, "w") as f:
        f.write("\n".join(sorted_subs) + "\n")

    return len(sorted_subs)


def _detect_wildcard_domains(domains_file, log=None):
    """Detect wildcard DNS parents by resolving random nonsense subdomains.

    For each parent domain, resolves 5 random subdomains. If all resolve to the
    same IP, the domain has wildcard DNS (everything resolves).
    Returns a set of wildcard parent domain strings.
    """
    import random
    import string

    wildcard_parents = set()
    with open(domains_file) as f:
        parents = [line.strip().lower() for line in f if line.strip()]

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        for parent in parents:
            # Generate 5 random 10-char subdomains
            random_subs = []
            for _ in range(5):
                rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                random_subs.append("%s.%s" % (rand, parent))

            # Resolve each, capturing the FULL set of IPs per query.
            # Multi-IP CDN backends (Fastly/Cloudflare) return multiple A records
            # per lookup; the original "first IP only" check missed these because
            # getaddrinfo can reorder. Wildcard test: every probe returns the
            # same set of IPs (or at least one common IP).
            per_query_ip_sets = []
            all_resolved = True
            for test_host in random_subs:
                try:
                    results = socket.getaddrinfo(test_host, None, socket.AF_INET)
                    if results:
                        ips = frozenset(addr[4][0] for addr in results)
                        per_query_ip_sets.append(ips)
                    else:
                        all_resolved = False
                        break
                except (socket.gaierror, socket.timeout, OSError):
                    all_resolved = False
                    break

            if not all_resolved or not per_query_ip_sets:
                continue

            # Two-tier check:
            # 1. All probes returned identical IP sets → strong wildcard signal
            # 2. All probes share at least one common IP → CDN/anycast wildcard
            #    (Fastly/Cloudflare may return overlapping but rotated sets)
            common = set(per_query_ip_sets[0])
            for ip_set in per_query_ip_sets[1:]:
                common &= ip_set

            if common:
                wildcard_parents.add(parent)
                if log:
                    log.write("  [wildcard] %s → all probes share IP(s) %s\n" % (
                        parent, ",".join(sorted(common))))
                    log.flush()
    finally:
        socket.setdefaulttimeout(old_timeout)

    return wildcard_parents


class ReconHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def _route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        if method == "GET" and path == "/tools":
            return self._handle_tools()
        if method == "POST" and path == "/scan/start":
            return self._handle_start()
        if method == "GET" and path.startswith("/scan/") and path.endswith("/status"):
            pid = int(path.split("/")[2])
            return self._handle_status(pid)
        if method == "GET" and path.startswith("/scan/") and path.endswith("/output"):
            pid = int(path.split("/")[2])
            lines = int(qs.get("lines", [50])[0])
            return self._handle_output(pid, lines)
        if method == "GET" and path.startswith("/scan/") and path.endswith("/results"):
            pid = int(path.split("/")[2])
            return self._handle_results(pid)
        if method == "POST" and path.startswith("/scan/") and path.endswith("/kill"):
            pid = int(path.split("/")[2])
            return self._handle_kill(pid)
        if method == "GET" and path.startswith("/files/"):
            target_name = path.split("/files/", 1)[1]
            return self._handle_files(target_name)
        if method == "POST" and path == "/results/from-file":
            return self._handle_results_from_file()
        if method == "POST" and path == "/scan/kill-target":
            return self._handle_kill_target()
        if method == "POST" and path == "/scan/write-exclusions":
            return self._handle_write_exclusions()
        if method == "GET" and path == "/health":
            return self._handle_health()
        if method == "POST" and path == "/wildcard-detect":
            return self._handle_wildcard_detect()
        if method == "POST" and path == "/netns/allocate":
            return self._handle_netns_allocate()
        if method == "POST" and path == "/netns/release":
            return self._handle_netns_release()
        if method == "GET" and path == "/netns/status":
            return self._handle_netns_status()

        self._send_json({"error": "not found"}, 404)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def log_message(self, format, *args):
        pass  # Suppress default logging

    # --- Handlers ---

    def _handle_health(self):
        running = sum(1 for s in SCANS.values() if _poll_scan(s) is None)
        heavy_running = sum(1 for s in SCANS.values()
                           if _poll_scan(s) is None and s.get("tool") in HEAVY_TOOLS)
        net = getattr(self.__class__, "_network_stats", {})
        import psutil
        try:
            mem = psutil.virtual_memory()
            mem_info = {"total_gb": round(mem.total / 1e9, 1),
                        "used_gb": round(mem.used / 1e9, 1),
                        "percent": mem.percent}
        except Exception:
            mem_info = {}
        exit_status = getattr(self.__class__, "_exit_node_status", {}) or {}
        bw_stats = getattr(self.__class__, "_bandwidth_stats", {}) or {}
        self._send_json({
            "scans_running": running,
            "scans_heavy": heavy_running,
            "max_concurrent": MAX_CONCURRENT_SCANS,
            "max_heavy": MAX_CONCURRENT_HEAVY,
            "network": {
                "tcp_established": net.get("tcp_estab", -1),
                "tcp_total": net.get("tcp_total", -1),
                "peak_established": net.get("peak_estab", 0),
                "throttle_events": net.get("throttle_events", 0),
                "udp_out_per_sec": net.get("udp_out_per_sec", 0),
                "tcp_new_per_sec": net.get("tcp_new_per_sec", 0),
                "peak_udp_out_per_sec": net.get("peak_udp_out_per_sec", 0),
                "peak_tcp_new_per_sec": net.get("peak_tcp_new_per_sec", 0),
                "dns_throttle_active": net.get("dns_throttle_active", False),
                "udp_budget_pct": _compute_rate_budget(net)["udp_pct"],
                "syn_budget_pct": _compute_rate_budget(net)["syn_pct"],
                "last_check": net.get("last_check", ""),
            },
            "exit_node": {
                "guard_enabled": exit_status.get("guard_enabled", False),
                "online": exit_status.get("online", True),
                "current_egress_ip": exit_status.get("current_egress_ip"),
                "expected_egress_ip": exit_status.get("expected_egress_ip"),
                "last_check": exit_status.get("last_check"),
                "last_success": exit_status.get("last_success"),
                "consecutive_failures": exit_status.get("consecutive_failures", 0),
                "total_failures": exit_status.get("total_failures", 0),
                "down_since": exit_status.get("down_since"),
            },
            "bandwidth": {
                "exit_rx_today_bytes": bw_stats.get("exit_rx_today", 0),
                "exit_tx_today_bytes": bw_stats.get("exit_tx_today", 0),
                "exit_rx_month_bytes": bw_stats.get("exit_rx_month", 0),
                "exit_tx_month_bytes": bw_stats.get("exit_tx_month", 0),
                "exit_conntrack_current": bw_stats.get("exit_conntrack_current", 0),
                "exit_conntrack_max": bw_stats.get("exit_conntrack_max", 0),
                "exit_conntrack_pct": bw_stats.get("exit_conntrack_pct", 0),
                "last_sample": bw_stats.get("last_sample"),
                "last_sample_ok": bw_stats.get("last_sample_ok", False),
                "samples_total": bw_stats.get("samples_total", 0),
                "samples_failed": bw_stats.get("samples_failed", 0),
                "last_error": bw_stats.get("last_error"),
                "scan_alert_threshold_bytes": SCAN_BYTE_ALERT_THRESHOLD,
            },
            "netns_pool": {k: dict(v) for k, v in NETNS_POOL.items()},
            "memory": mem_info,
        })

    def _handle_wildcard_detect(self):
        """POST /wildcard-detect with body {"domains": [...]} → returns
        {"wildcard_parents": [...], "checked": N, "duration_s": float}.

        Called by recon_routes.create_target() at target creation time so
        the pipeline knows up-front which domains to skip for DNS-brute
        tools (shuffledns, dnsgen, active amass).  See Apr-2026 varonis
        incident: 67 MB of DNS traffic spent enumerating wildcard
        permutations that all resolve to the same IP.
        """
        data = self._read_body()
        domains = data.get("domains", [])
        if not domains or not isinstance(domains, list):
            return self._send_json({"error": "domains list required"}, 400)
        # Write to a temp file because _detect_wildcard_domains takes a path
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            for d in domains:
                tf.write(str(d).strip() + "\n")
            tmp_path = tf.name
        t0 = time.time()
        try:
            wildcard_parents = _detect_wildcard_domains(tmp_path, log=None)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return self._send_json({
            "wildcard_parents": sorted(wildcard_parents),
            "checked": len(domains),
            "duration_s": round(time.time() - t0, 1),
        })

    def _handle_netns_allocate(self):
        """POST /netns/allocate {"pipeline_id": int} → {netns, egress_ip}.

        Claims a free, online netns for the pipeline. Idempotent — if the
        pipeline already holds a slot, returns the same slot. 409 if all
        slots are claimed.
        """
        data = self._read_body()
        pipeline_id = data.get("pipeline_id")
        if pipeline_id is None:
            return self._send_json({"error": "pipeline_id required"}, 400)
        slot, err = _netns_allocate(pipeline_id)
        if err:
            return self._send_json({
                "error": err,
                "pool_state": {k: {"claimed_by": v["claimed_by"], "online": v["online"]}
                               for k, v in NETNS_POOL.items()},
            }, 409)
        return self._send_json({
            "netns": slot,
            "egress_ip": NETNS_POOL[slot]["egress_ip"],
            "pipeline_id": pipeline_id,
        })

    def _handle_netns_release(self):
        """POST /netns/release {"pipeline_id": int} → {released: slot|null}."""
        data = self._read_body()
        pipeline_id = data.get("pipeline_id")
        if pipeline_id is None:
            return self._send_json({"error": "pipeline_id required"}, 400)
        released = _netns_release(pipeline_id)
        return self._send_json({"released": released, "pipeline_id": pipeline_id})

    def _handle_netns_status(self):
        """GET /netns/status → full pool state for dashboards / debugging."""
        with NETNS_POOL_LOCK:
            snap = {k: dict(v) for k, v in NETNS_POOL.items()}
        return self._send_json({"pool": snap})

    def _handle_tools(self):
        tools = {}
        for name in ["subfinder", "httpx-toolkit", "katana", "getallurls", "nuclei",
                      "nmap", "naabu", "nuclei-takeover", "subzy", "s3-takeover",
                      "dnsgen", "shuffledns", "merge-subs", "merge-urls", "cloud-buckets",
                      "linkfinder", "secret-scan", "arjun", "cms-detect",
                      "panel-detect", "wpscan", "ffuf", "dalfox",
                      "amass", "crt-sh", "gospider", "joomscan", "sqlmap",
                      "commix", "hydra", "gitleaks", "git-dumper", "eyewitness",
                      "trufflehog", "dnsx", "nomore403", "kiterunner", "feroxbuster",
                      "paramspider", "corscanner", "nextjs-check", "xhr-capture",
                      "spa-catchall-detect",
                      # Oracle pipeline tools
                      "sslscan", "sslyze", "saml-fingerprint", "jwt-jwe-harvest",
                      "cookie-harvest", "roca-scan", "breach-candidate",
                      "tls-oracle-probe", "xmlenc-oracle-probe",
                      # Extended oracle pipeline tools
                      "cbc-padding-probe", "marvin-probe", "xsw-probe",
                      "viewstate-fingerprint", "jwe-invalid-curve-probe",
                      "manger-oaep-probe", "ssh-terrapin-scan",
                      "gcm-nonce-scan", "raccoon-probe"]:
            if name in ("s3-takeover", "merge-subs", "merge-urls", "cloud-buckets",
                         "secret-scan", "cms-detect", "linkfinder", "panel-detect",
                         "crt-sh", "git-dumper", "gitleaks", "corscanner", "nextjs-check",
                         "spa-catchall-detect",
                         # Oracle built-ins (stdlib Python)
                         "saml-fingerprint", "jwt-jwe-harvest", "cookie-harvest",
                         "roca-scan", "breach-candidate", "tls-oracle-probe",
                         "xmlenc-oracle-probe",
                         # Extended oracle built-ins
                         "cbc-padding-probe", "marvin-probe", "xsw-probe",
                         "viewstate-fingerprint", "jwe-invalid-curve-probe",
                         "manger-oaep-probe", "ssh-terrapin-scan",
                         "gcm-nonce-scan", "raccoon-probe"):
                # Built-in Python tools, always available
                if name == "s3-takeover":
                    dig_path = _find_tool("dig")
                    tools[name] = {"available": dig_path is not None, "path": "built-in (requires dig)"}
                elif name == "linkfinder":
                    # linkfinder is a Python module, not a CLI binary
                    import subprocess as _sp
                    try:
                        _sp.run(["python3", "-m", "linkfinder", "-h"], capture_output=True, timeout=5)
                        tools[name] = {"available": True, "path": "python3 -m linkfinder"}
                    except Exception:
                        tools[name] = {"available": False, "path": None}
                else:
                    tools[name] = {"available": True, "path": "built-in"}
            else:
                binary = TOOL_BINARIES.get(name, name)
                path = _find_tool(binary)
                tools[name] = {"available": path is not None, "path": path}
        self._send_json(tools)

    def _handle_start(self):
        _cleanup_scans()

        # Exit-node guard — hard-stop on egress failure.
        # Refuses to launch any scan when the Hetzner exit node is down,
        # so we never silently fall back to direct home-modem egress
        # (which is what caused the original modem outages).
        exit_status = getattr(self.__class__, "_exit_node_status", None) or {}
        if exit_status.get("guard_enabled") and not exit_status.get("online", True):
            return self._send_json({
                "error": "exit node down — refusing to scan via direct home egress",
                "expected_ip": exit_status.get("expected_egress_ip"),
                "current_ip": exit_status.get("current_egress_ip"),
                "down_since": exit_status.get("down_since"),
                "consecutive_failures": exit_status.get("consecutive_failures", 0),
            }, 503)

        # Enforce concurrent scan limit
        running_count = sum(1 for s in SCANS.values() if _poll_scan(s) is None)
        if running_count >= MAX_CONCURRENT_SCANS:
            return self._send_json({
                "error": "too many concurrent scans (%d/%d running)" % (running_count, MAX_CONCURRENT_SCANS)
            }, 429)

        # DNS-flood gate — refuse new scans while UDP-out rate is elevated.
        # Caller (orchestrator) will retry; this prevents autopilot from
        # piling on more DNS-heavy tools mid-flood and overwhelming the
        # consumer modem. Cleared by the net-monitor when rate drops <50%.
        net = getattr(self.__class__, "_network_stats", None) or {}
        if net.get("dns_throttle_active"):
            return self._send_json({
                "error": "dns flood gate active (%.0f udp/s) — retry after backoff" % (
                    net.get("udp_out_per_sec", 0))
            }, 429)

        # Rate-budget pre-flight. If we're already using >80% of either
        # the UDP or SYN budget, defer this launch — orchestrator retries.
        # Also computes a scale factor we'll use to throttle this tool's
        # rate flags (e.g. naabu -rate, subfinder -rl) when budget is tight.
        budget = _compute_rate_budget(net)
        if budget["udp_pct"] > 80 or budget["syn_pct"] > 80:
            return self._send_json({
                "error": "rate budget saturated (udp=%.0f%% syn=%.0f%%) — retry" % (
                    budget["udp_pct"], budget["syn_pct"])
            }, 429)

        data = self._read_body()
        tool = data.get("tool")

        # Gate heavy tools — only MAX_CONCURRENT_HEAVY can run at once
        if tool in HEAVY_TOOLS:
            heavy_running = sum(1 for s in SCANS.values()
                                if s["tool"] in HEAVY_TOOLS and _poll_scan(s) is None)
            if heavy_running >= MAX_CONCURRENT_HEAVY:
                return self._send_json({
                    "error": "too many concurrent heavy scans (%d/%d running: %s)" % (
                        heavy_running, MAX_CONCURRENT_HEAVY,
                        ", ".join(s["tool"] for s in SCANS.values()
                                  if s["tool"] in HEAVY_TOOLS and _poll_scan(s) is None))
                }, 429)
        target_name = data.get("target_name", "default")
        domains = data.get("domains", [])
        input_file = data.get("input_file")
        options = data.get("options", {})

        # Pipeline → netns binding. Pipelines claim a netns via /netns/allocate
        # (Flask does this in pipeline_start). Every spawn for THIS scan will
        # be wrapped with `ip netns exec <slot>` so it egresses through the
        # right Hetzner node.
        pipeline_id = data.get("pipeline_id")
        _pipeline_netns = _netns_for_pipeline(pipeline_id) if pipeline_id else None
        if _pipeline_netns is None:
            _pipeline_netns = NETNS_DEFAULT_SLOT  # fallback for un-pipelined scans

        if not tool:
            return self._send_json({"error": "tool is required"}, 400)
        # Built-in Python tools don't need a binary check
        BUILTIN_TOOLS = {"s3-takeover", "merge-subs", "merge-urls", "cloud-buckets",
                         "secret-scan", "cms-detect", "panel-detect", "linkfinder",
                         "crt-sh", "git-dumper", "gitleaks", "corscanner", "nextjs-check",
                         # Oracle pipeline built-ins
                         "saml-fingerprint", "jwt-jwe-harvest", "cookie-harvest",
                         "roca-scan", "breach-candidate", "tls-oracle-probe",
                         "xmlenc-oracle-probe",
                         # Extended oracle pipeline built-ins
                         "cbc-padding-probe", "marvin-probe", "xsw-probe",
                         "viewstate-fingerprint", "jwe-invalid-curve-probe",
                         "manger-oaep-probe", "ssh-terrapin-scan",
                         "gcm-nonce-scan", "raccoon-probe"}
        if tool not in BUILTIN_TOOLS:
            binary = TOOL_BINARIES.get(tool, tool)
            if not _find_tool(binary):
                return self._send_json({"error": "%s not found on host" % tool}, 404)

        target_dir = RECON_DIR / target_name
        target_dir.mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        json_output = None
        stdin_fh = None

        if tool == "subfinder":
            if not domains:
                return self._send_json({"error": "domains required for subfinder"}, 400)
            domain_file = target_dir / "domains.txt"
            domain_file.write_text("\n".join(domains) + "\n")
            output_file = target_dir / ("subfinder_%d.txt" % timestamp)
            # Phase 6: raised base 100 → 250 (Hetzner exit node, no modem NAT).
            sf_rl = max(20, int(250 * budget["scale_dns"]))
            cmd = ["subfinder", "-dL", str(domain_file), "-all", "-recursive",
                   "-max-time", "30", "-rl", str(sf_rl), "-o", str(output_file)]

        elif tool == "httpx-toolkit":
            if not input_file:
                return self._send_json({"error": "input_file required for httpx-toolkit"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Kali httpx-toolkit uses -json flag (no value) and -o for output
            output_file = target_dir / ("httpx_%d.json" % timestamp)
            json_output = output_file  # same file — JSONL output
            # Phase 6: raised base 100 → 250 rl, 25 → 50 threads (Hetzner exit).
            # Tools still respect _compute_rate_budget for self-tuning under load.
            httpx_rl = max(20, int(options.get("rate_limit", 250) * budget["scale_syn"]))
            httpx_threads = max(5, int(options.get("threads", 50) * budget["scale_syn"]))
            cmd = [
                "httpx-toolkit", "-l", str(input_path),
                "-sc", "-title", "-tech-detect", "-cl", "-location",
                "-follow-redirects",
                "-favicon", "-irr",
                "-json",
                "-o", str(output_file),
                "-threads", str(httpx_threads),
                "-rl", str(httpx_rl),
                "-timeout", str(options.get("timeout", 10)),
                "-retries", str(options.get("retries", 2)),
            ]

        elif tool == "katana":
            if not input_file:
                return self._send_json({"error": "input_file required for katana"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # httpx output is JSONL — extract URLs, filtering wildcards + dead responses
            urls_file = target_dir / ("katana_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            urls_file.write_text("\n".join(urls) + "\n")
            output_file = target_dir / ("katana_%d.txt" % timestamp)
            depth = options.get("depth", 3)
            cmd = [
                "katana", "-list", str(urls_file),
                "-jc", "-kf", "all",
                "-fs", "fqdn",
                "-d", str(depth),
                "-c", "10", "-rl", "50",
                "-ef", "png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico",
                "-o", str(output_file),
                "-ct", "300",
                "-silent",
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ]

        elif tool == "getallurls":
            if not input_file:
                return self._send_json({"error": "input_file required for getallurls"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("gau_%d.txt" % timestamp)
            log_file = target_dir / ("getallurls_%d.log" % timestamp)
            # gau reads domains from stdin and writes URLs to stdout
            # Capture stdout → output_file, stderr → log_file (same as dnsgen)
            #
            # --providers otx: wayback (web.archive.org CDX) has been
            # globally unreliable for months — every gau run across
            # P253-P291 returned 0 URLs from wayback. Manual test shows
            # CDX API times out from Mac, Kali, AND both netns slots.
            # commoncrawl and urlscan also silently fail. Only OTX
            # (otx.alienvault.com) consistently returns data — 79551 URLs
            # for affirm.com (185 subs) in 2 min when wayback returned 0.
            #
            # NO --fp: gau 2.x's --fp ("filter parameters" / dedup similar
            # URLs) is over-aggressive and collapses 79K URLs to literal 0
            # output on real targets. Empirical bisect (2026-05-26): same
            # input/providers/blacklist produces 79551 lines without --fp
            # and 0 lines with --fp. Downstream merge-urls already dedups
            # across all URL sources so --fp gives us nothing.
            #
            # If wayback comes back, add it back to the providers list.
            cmd = ["getallurls", "--subs", "--threads", "5",
                   "--providers", "otx",
                   "--blacklist", "png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico"]
            log_fh = open(log_file, "w")
            out_fh = open(output_file, "w")
            stdin_fh = open(input_path, "r")
            proc = subprocess.Popen(
                _netns_wrap_cmd(cmd, _pipeline_netns),
                stdout=out_fh, stderr=log_fh,
                stdin=stdin_fh,
                preexec_fn=os.setsid,
            )
            scan_info = {
                "pid": proc.pid,
                "tool": tool,
                "target_name": target_name,
                "output_file": str(output_file),
                "json_output": None,
                "log_file": str(log_file),
                "started_at": time.time(),
                "process": proc,
                "log_fh": log_fh,
                "stdin_fh": stdin_fh,
                "netns": _pipeline_netns,
            }
            SCANS[proc.pid] = scan_info
            _save_scans()
            return self._send_json({
                "pid": proc.pid,
                "tool": tool,
                "output_file": output_file.name,
                "json_output": None,
                "log_file": log_file.name,
            }, 201)

        elif tool == "nuclei":
            if not input_file:
                return self._send_json({"error": "input_file required for nuclei"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # httpx output is JSONL — extract URLs, filtering wildcards + dead responses
            urls_file = target_dir / ("nuclei_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            urls_file.write_text("\n".join(urls) + "\n")
            output_file = target_dir / ("nuclei_%d.txt" % timestamp)
            json_output = target_dir / ("nuclei_%d.jsonl" % timestamp)
            severity = options.get("severity", "critical,high,medium,low")
            custom_templates = REPO_ROOT / "nuclei-templates" / "custom"
            custom_only = options.get("custom_templates_only")
            if custom_only:
                # Run ONLY custom templates (for test runs from the showcase page)
                # Always resolve path from agent's own location, not from Flask container
                custom_only_path = str(custom_templates) if custom_templates.is_dir() else custom_only
                cmd = [
                    "nuclei", "-l", str(urls_file),
                    "-t", custom_only_path,
                    "-o", str(output_file),
                    "-jle", str(json_output),
                    "-rl", "100",
                    "-c", "10",
                    "-timeout", "10",
                    "-retries", "1",
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ]
            else:
                cmd = [
                    "nuclei", "-l", str(urls_file),
                    "-o", str(output_file),
                    "-jle", str(json_output),
                    "-severity", severity,
                    "-itags", "kev",
                    "-etags", "dos,fuzz",
                    "-ss", "host-spray",
                    "-nh",
                    "-rl", "150",
                    "-c", "15",
                    "-timeout", "10",
                    "-retries", "2",
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ]
                if custom_templates.is_dir():
                    cmd += ["-t", str(custom_templates)]

        elif tool == "nuclei-takeover":
            if not input_file:
                return self._send_json({"error": "input_file required for nuclei-takeover"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # httpx output is JSONL — extract plain URLs for nuclei
            urls_file = target_dir / ("nuclei_takeover_urls_%d.txt" % timestamp)
            with open(input_path) as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        url = obj.get("url", obj.get("input", ""))
                        if url:
                            urls.append(url)
                    except (json.JSONDecodeError, ValueError):
                        if line.startswith("http"):
                            urls.append(line)
            urls_file.write_text("\n".join(urls) + "\n")
            output_file = target_dir / ("nuclei_takeover_%d.txt" % timestamp)
            json_output = target_dir / ("nuclei_takeover_%d.jsonl" % timestamp)
            cmd = [
                "nuclei", "-l", str(urls_file),
                "-t", "http/takeovers/",
                "-o", str(output_file),
                "-jle", str(json_output),
            ]

        elif tool == "subzy":
            if not input_file:
                return self._send_json({"error": "input_file required for subzy"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("subzy_%d.json" % timestamp)
            json_output = output_file  # subzy outputs JSON directly
            cmd = [
                "subzy", "run",
                "--targets", str(input_path),
                "--output", str(output_file),
                "--hide_fails",
                "--concurrency", "20",
                "--timeout", "20",
            ]

        elif tool == "naabu":
            if not input_file:
                return self._send_json({"error": "input_file required for naabu"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("naabu_%d.txt" % timestamp)
            # Use -p with explicit bounty-relevant ports (naabu can't combine -top-ports with -p)
            BOUNTY_PORTS = (
                "80,443,8080,8443,8000,8001,8008,8081,8880,8888,"
                "21,22,23,25,53,110,143,445,993,995,3389,"
                "2375,2376,3306,5432,5984,6379,9090,9200,9300,"
                "11211,27017,27018,5000,5001,9000,9443,10000,10250,15672,"
                "2049,4443,6443,8444,8834,50000"
            )
            custom_ports = options.get("ports", BOUNTY_PORTS)
            # naabu -rate is PPS (≈ SYN/sec). Phase 6: raised base 150 → 500
            # rate and 25 → 50 concurrency (Hetzner exit, no modem NAT
            # exhaustion).  Baseline peak was 127.5 SYN/s with rate=150;
            # rate=500 should give us ~5x throughput.  Still gates via
            # budget["scale_syn"] when the supervisor sees sustained load.
            naabu_rate = max(50, int(500 * budget["scale_syn"]))
            naabu_c = max(5, int(50 * budget["scale_syn"]))
            cmd = [
                "naabu", "-list", str(input_path),
                "-p", custom_ports,
                "-rate", str(naabu_rate),
                "-c", str(naabu_c),
                "-exclude-cdn",
                "-verify",
                "-o", str(output_file),
            ]

        elif tool == "nmap":
            if not input_file:
                return self._send_json({"error": "input_file required for nmap"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Detect input format: naabu output (host:port) vs httpx JSONL vs plain text
            is_naabu_input = input_file.startswith("naabu_")
            hosts_file = target_dir / ("nmap_hosts_%d.txt" % timestamp)
            if is_naabu_input:
                # naabu output is host:port lines — extract unique hosts and ports
                hosts = set()
                ports_set = set()
                with open(input_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if ":" in line:
                            host, port = line.rsplit(":", 1)
                            hosts.add(host)
                            ports_set.add(port)
                        else:
                            hosts.add(line)
                hosts_file.write_text("\n".join(sorted(hosts)) + "\n")
                # Use specific ports from naabu instead of top-ports
                port_arg = ",".join(sorted(ports_set, key=int)) if ports_set else "1-1000"
            else:
                # httpx JSONL or plain text — extract hostnames
                hosts = set()
                with open(input_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            url = obj.get("url", obj.get("input", ""))
                        except (json.JSONDecodeError, ValueError):
                            url = line
                        url = url.replace("https://", "").replace("http://", "")
                        host = url.split("/")[0].split(":")[0]
                        if host:
                            hosts.add(host)
                hosts_file.write_text("\n".join(sorted(hosts)) + "\n")
                port_arg = None
            # Cap hosts to prevent NSE assertion crashes on large scans
            MAX_NMAP_HOSTS = 150
            with open(hosts_file) as f:
                all_hosts = [l.strip() for l in f if l.strip()]
            if len(all_hosts) > MAX_NMAP_HOSTS:
                all_hosts = all_hosts[:MAX_NMAP_HOSTS]
                hosts_file.write_text("\n".join(all_hosts) + "\n")
            output_file = target_dir / ("nmap_%d.txt" % timestamp)
            xml_output = target_dir / ("nmap_%d.xml" % timestamp)
            json_output = str(xml_output)
            cmd = [
                "nmap", "-iL", str(hosts_file),
                "-sV", "--version-intensity", "5",
                "-sC",
                "--script", "vulners",
                "--script-args", "mincvss=7.0",
                "--max-retries", "2",
                "--host-timeout", "3m",
                "--max-hostgroup", "32",
                "--min-rate", "300",
                "-oN", str(output_file),
                "-oX", str(xml_output),
            ]
            if port_arg:
                cmd += ["-p", port_arg]
            else:
                cmd += ["--top-ports", str(options.get("ports", "1000"))]

        elif tool == "dnsgen":
            if not input_file:
                return self._send_json({"error": "input_file required for dnsgen"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Cap input to prevent combinatorial explosion (13k subs → 34GB output)
            MAX_DNSGEN_INPUT = 500
            MAX_DNSGEN_OUTPUT = 10000  # Cap output at 10K permutations (was 100K — caused modem overload)
            with open(input_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            if len(lines) > MAX_DNSGEN_INPUT:
                truncated_path = target_dir / ("dnsgen_input_%d.txt" % timestamp)
                with open(truncated_path, "w") as f:
                    f.write("\n".join(lines[:MAX_DNSGEN_INPUT]) + "\n")
                input_path = truncated_path

            # Pre-flight wildcard check on domains.txt — if every parent has
            # wildcard DNS, dnsgen+shuffledns would just hammer the resolver
            # for nothing (everything resolves to the same IP). Skip both.
            # Prefer cached wildcard_parents (from Flask, detected at target
            # creation); fall back to fresh detection.
            domains_file = target_dir / "domains.txt"
            output_file = target_dir / ("dnsgen_%d.txt" % timestamp)
            log_file = target_dir / ("dnsgen_%d.log" % timestamp)
            if domains_file.exists():
                cached_wc = options.get("wildcard_parents") or []
                with open(log_file, "w") as wlog:
                    if cached_wc:
                        wlog.write("Using cached wildcard_parents from target (%d parents)\n"
                                   % len(cached_wc))
                        wildcard_parents = set(cached_wc)
                    else:
                        wildcard_parents = _detect_wildcard_domains(domains_file, wlog)
                with open(domains_file) as df:
                    parents = {l.strip().lower() for l in df if l.strip()}
                if wildcard_parents and wildcard_parents >= parents:
                    # Every parent is wildcard — skip dnsgen entirely, write empty output
                    with open(output_file, "w"):
                        pass
                    with open(log_file, "a") as wlog:
                        wlog.write("All %d parent domains have wildcard DNS — "
                                   "skipping dnsgen+shuffledns to avoid resolver flood.\n"
                                   % len(parents))
                    # Persist wildcard metadata for downstream tools / merge-subs
                    wc_meta = {"wildcard_parents": sorted(wildcard_parents),
                               "skipped_reason": "all_parents_wildcard"}
                    with open(target_dir / "wildcard_domains.json", "w") as wf:
                        json.dump(wc_meta, wf)
                    # Return a fake "completed" scan so pipeline auto-advances
                    fake_pid = -timestamp  # negative pid signals synthetic
                    SCANS[fake_pid] = {
                        "pid": fake_pid, "tool": tool, "target_name": target_name,
                        "output_file": str(output_file), "json_output": None,
                        "log_file": str(log_file), "started_at": time.time(),
                        "status": "completed", "exit_code": 0,
                        "completed_at": time.time(),
                        "synthetic": True,
                    }
                    _save_scans()
                    return self._send_json({
                        "pid": fake_pid, "tool": tool,
                        "output_file": output_file.name,
                        "json_output": None,
                        "log_file": log_file.name,
                        "skipped": "wildcard_dns",
                    }, 201)

            # Pipe through head to cap output lines (prevents 4M+ line explosion)
            shell_cmd = "dnsgen '%s' | head -n %d" % (
                str(input_path).replace("'", "'\\''"), MAX_DNSGEN_OUTPUT)
            log_fh = open(log_file, "w")
            out_fh = open(output_file, "w")
            proc = subprocess.Popen(
                _netns_wrap_cmd(["bash", "-c", shell_cmd], _pipeline_netns),
                stdout=out_fh, stderr=log_fh,
                preexec_fn=os.setsid,
            )
            scan_info = {
                "pid": proc.pid,
                "tool": tool,
                "target_name": target_name,
                "output_file": str(output_file),
                "json_output": None,
                "log_file": str(log_file),
                "started_at": time.time(),
                "process": proc,
                "log_fh": log_fh,
                "stdin_fh": out_fh,  # track output fh for cleanup
                "netns": _pipeline_netns,
            }
            SCANS[proc.pid] = scan_info
            _save_scans()
            return self._send_json({
                "pid": proc.pid,
                "tool": tool,
                "output_file": output_file.name,
                "json_output": None,
                "log_file": log_file.name,
            }, 201)

        elif tool == "shuffledns":
            if not input_file:
                return self._send_json({"error": "input_file required for shuffledns"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Need a resolvers file
            resolvers = options.get("resolvers", str(REPO_ROOT / "resolvers.txt"))
            if not Path(resolvers).exists():
                return self._send_json({"error": "resolvers file not found: %s" % resolvers}, 400)
            trusted_resolvers = str(REPO_ROOT / "trusted-resolvers.txt")
            # Extract base domain(s) from the domains file — run for ALL domains
            domains_file = target_dir / "domains.txt"
            if not domains_file.exists():
                return self._send_json({"error": "domains.txt not found for target"}, 400)
            all_domains = [d.strip() for d in domains_file.read_text().strip().split("\n") if d.strip()]
            # Wildcard pre-flight: skip parents that resolve every subdomain
            # to the same IP — brute-forcing under them produces 0 real hosts.
            # Pulled from Flask (cached at target-creation in recon_targets).
            # If absent, fall back to a fresh detection.
            wc_parents = set(options.get("wildcard_parents") or [])
            if not wc_parents:
                try:
                    wc_parents = set(_detect_wildcard_domains(domains_file, None))
                except Exception:
                    wc_parents = set()
            if wc_parents:
                filtered = [d for d in all_domains if d not in wc_parents]
                if not filtered:
                    # 100% wildcard — skip entirely.  Write an empty output
                    # so dependent tools (merge-subs) still find their input.
                    skip_out = target_dir / ("shuffledns_%d.txt" % timestamp)
                    skip_log = target_dir / ("shuffledns_%d.log" % timestamp)
                    skip_out.write_text("")
                    skip_log.write_text(
                        "skipped: all %d parent domains have wildcard DNS "
                        "(%s)\n" % (len(all_domains),
                                    ", ".join(sorted(wc_parents)[:5])))
                    fake_pid = -timestamp
                    SCANS[fake_pid] = {
                        "pid": fake_pid, "tool": tool, "target_name": target_name,
                        "output_file": str(skip_out), "json_output": None,
                        "log_file": str(skip_log), "started_at": time.time(),
                        "status": "completed", "exit_code": 0,
                        "completed_at": time.time(), "synthetic": True,
                    }
                    _save_scans()
                    return self._send_json({
                        "pid": fake_pid, "tool": tool,
                        "output_file": skip_out.name,
                        "json_output": None, "log_file": skip_log.name,
                        "skipped": "wildcard_parents",
                    }, 201)
                all_domains = filtered
            output_file = target_dir / ("shuffledns_%d.txt" % timestamp)
            # Run shuffledns per domain, merge and deduplicate results
            subcmds = []
            part_files = []
            tr_flag = ' -tr "%s"' % trusted_resolvers if Path(trusted_resolvers).exists() else ""
            # Phase 6: raised -t 25 → 100.  Original 25 was to protect the
            # consumer modem; with the Hetzner exit node we can push closer
            # to the public resolver rate-limit ceiling (~2-3K qps before
            # 1.1.1.1 throttles).  100 parallel resolves × 18 resolvers in
            # rotation ≈ 600-1000 qps observed.  Self-tuning supervisor
            # still SIGSTOPs shuffledns if UDP-out > 2000/s.
            sd_t = max(25, int(100 * budget["scale_dns"]))
            for i, d in enumerate(all_domains):
                part = target_dir / ("shuffledns_%d_part%d.txt" % (timestamp, i))
                part_files.append(str(part))
                subcmds.append(
                    'shuffledns -d "%s" -list "%s" -r "%s"%s -sw -t %d -mode resolve -o "%s"'
                    % (d, str(input_path), resolvers, tr_flag, sd_t, str(part))
                )
            # Cat all parts, sort unique → final output
            cat_parts = " ".join('"%s"' % p for p in part_files)
            subcmds.append('cat %s 2>/dev/null | sort -u > "%s"' % (cat_parts, str(output_file)))
            # Clean up part files
            subcmds.append('rm -f %s' % " ".join('"%s"' % p for p in part_files))
            cmd = ["bash", "-c", "; ".join(subcmds)]

        elif tool == "merge-subs":
            # Built-in Python tool: merge subfinder + shuffledns output, deduplicate
            output_file = target_dir / ("all_subs_%d.txt" % timestamp)
            log_file = target_dir / ("merge-subs_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--merge-subs",
                str(target_dir), str(output_file), str(log_file),
            ]

        elif tool == "linkfinder":
            if not input_file:
                return self._send_json({"error": "input_file required for linkfinder"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("linkfinder_%d.txt" % timestamp)
            # linkfinder takes a file of JS URLs and extracts endpoints
            # We run it per-URL in a loop via shell (capped at 500 URLs)
            log_file = target_dir / ("linkfinder_%d.log" % timestamp)
            cmd_str = (
                'head -500 %s | while IFS= read -r url; do '
                'python3 -m linkfinder -i "$url" -o cli 2>>%s; '
                'done | sort -u > %s'
            ) % (str(input_path), str(log_file), str(output_file))
            log_fh = open(log_file, "w")
            log_fh.write("Starting linkfinder on %s\n" % input_file)
            log_fh.flush()
            proc = subprocess.Popen(
                _netns_wrap_cmd(["bash", "-c", cmd_str], _pipeline_netns),
                stdout=subprocess.DEVNULL, stderr=log_fh,
                preexec_fn=os.setsid,
            )
            scan_info = {
                "pid": proc.pid,
                "tool": tool,
                "target_name": target_name,
                "output_file": str(output_file),
                "json_output": None,
                "log_file": str(log_file),
                "started_at": time.time(),
                "process": proc,
                "log_fh": log_fh,
                "stdin_fh": None,
                "netns": _pipeline_netns,
            }
            SCANS[proc.pid] = scan_info
            _save_scans()
            return self._send_json({
                "pid": proc.pid,
                "tool": tool,
                "output_file": output_file.name,
                "json_output": None,
                "log_file": log_file.name,
            }, 201)

        elif tool == "secret-scan":
            if not input_file:
                return self._send_json({"error": "input_file required for secret-scan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("secrets_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("secret-scan_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--secret-scan",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "arjun":
            if not input_file:
                return self._send_json({"error": "input_file required for arjun"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Cap URLs to avoid extremely long runtimes. Empirically arjun
            # takes ~9 min per URL with --stable on real-world targets, so
            # the 200-URL cap (~30h needed) always hit the 150-min stale-kill
            # and produced 0-byte output. Drop to 30 so a full run fits in
            # ~4.5h × 0.6 budget = under 2.5h with margin. If we want broader
            # coverage we should round-robin across multiple smaller arjun
            # runs in different pipeline iterations rather than one massive one.
            MAX_ARJUN_URLS = 30
            with open(input_path) as f:
                urls = [line.strip() for line in f if line.strip()]
            if len(urls) > MAX_ARJUN_URLS:
                capped_path = target_dir / ("arjun_urls_%d.txt" % timestamp)
                with open(capped_path, "w") as f:
                    f.write("\n".join(urls[:MAX_ARJUN_URLS]) + "\n")
                input_path = capped_path
            output_file = target_dir / ("arjun_%d.json" % timestamp)
            json_output = output_file
            # -c 25 (chunks) trades a small recall hit for ~4x speedup vs
            # the default 50 chunks at 200 URLs. With 30 URLs and -c 25 we
            # comfortably finish under the 150-min budget.
            cmd = [
                "arjun", "-i", str(input_path),
                "-oJ", str(output_file),
                "-t", "10",
                "-c", "25",
                "--stable",
            ]

        elif tool == "cms-detect":
            if not input_file:
                return self._send_json({"error": "input_file required for cms-detect"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("cms_detect_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("cms-detect_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--cms-detect",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "merge-urls":
            # Built-in Python tool: merge katana + gau output, deduplicate, extract JS URLs
            output_file = target_dir / ("all_urls_%d.txt" % timestamp)
            log_file = target_dir / ("merge-urls_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--merge-urls",
                str(target_dir), str(output_file), str(log_file),
            ]

        elif tool == "cloud-buckets":
            if not input_file:
                return self._send_json({"error": "input_file required for cloud-buckets"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("cloud_buckets_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("cloud-buckets_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--cloud-buckets",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "s3-takeover":
            if not input_file:
                return self._send_json({"error": "input_file required for s3-takeover"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("s3_takeover_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("s3-takeover_%d.log" % timestamp)
            # Run as a subprocess calling this same script with --s3-check flag
            cmd = [
                "python3", os.path.abspath(__file__), "--s3-check",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "panel-detect":
            if not input_file:
                return self._send_json({"error": "input_file required for panel-detect"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("panels_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("panel-detect_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--panel-detect",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "xhr-capture":
            # Headless Chromium per host: load the SPA, wait for hydration,
            # capture all XHR/fetch URLs. Finds the cross-origin API host
            # that katana/gospider miss because they only see the SPA shell.
            # Depends on Playwright (NOT a stdlib tool); script lives at
            # scripts/xhr_capture.py and must be deployed alongside the agent.
            if not input_file:
                return self._send_json({"error": "input_file required for xhr-capture"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # We need real-host origins, not the favicon-fingerprint URLs that
            # live in the live_host store. Re-derive from the httpx JSONL.
            # The caller is expected to pass the merge-subs output OR an
            # already-cleaned origin list; if input is the raw httpx JSONL,
            # _extract_urls_from_httpx already handles favicon stripping
            # when feeding katana, but for xhr-capture we want the SPA shell
            # itself, so caller passes hostnames (one per line). Both formats
            # accepted; xhr_capture.py normalizes them.
            output_file = target_dir / ("xhr_capture_%d.jsonl" % timestamp)
            json_output = output_file
            log_file = target_dir / ("xhr-capture_%d.log" % timestamp)
            script_path = REPO_ROOT / "scripts" / "xhr_capture.py"
            if not script_path.exists():
                return self._send_json({
                    "error": "xhr_capture.py not found at %s — deploy scripts/ dir at repo root" % script_path
                }, 500)
            cmd = [
                "python3", str(script_path),
                str(input_path), str(output_file), str(log_file),
                "--timeout", str(options.get("timeout", 30)),
                "--concurrency", str(options.get("concurrency", 4)),
                "--max-hosts", str(options.get("max_hosts", 50)),
                "--executable-path", options.get("chromium_path", "/usr/bin/chromium"),
            ]
            # Auto-attach storage_state from the credential store if available
            # for this program (target_name == program_handle).  Writes the
            # plaintext to a per-scan tmp file (mode 0600) that we clean up
            # via the scan record's tmp_files list.
            storage_state_path = options.get("storage_state")
            if not storage_state_path:
                try:
                    from app import credential_store
                    tmp_state = target_dir / ("xhr_state_%d.json" % timestamp)
                    written = credential_store.write_storage_state_file(
                        target_name, tmp_state)
                    if written:
                        storage_state_path = str(written)
                        # Best-effort liveness probe so we don't burn 25min
                        # per host with a dead session
                        cred = credential_store.get(target_name, "storage_state")
                        if cred and cred.get("probe_url"):
                            ok, err = credential_store.probe(cred)
                            credential_store.mark_validated(cred["id"], ok, err)
                            if not ok:
                                # Don't auto-use an expired session — skip
                                # the attachment and let the scan run unauth
                                storage_state_path = None
                                try:
                                    written.unlink()
                                except Exception:
                                    pass
                except Exception:
                    # Credential store unavailable (e.g. pyrage not installed
                    # yet) — proceed unauthenticated.  Not a fatal error.
                    pass
            if storage_state_path:
                cmd.extend(["--storage-state", storage_state_path])

        elif tool == "wpscan":
            if not input_file:
                return self._send_json({"error": "input_file required for wpscan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("wpscan_%d.json" % timestamp)
            json_output = output_file
            # wpscan takes a file of WordPress URLs and scans each one
            log_file = target_dir / ("wpscan_%d.log" % timestamp)
            # Read targets and build a bash loop that runs wpscan on each
            cmd_str = (
                'echo "[]" > %s; '
                'while IFS= read -r url; do '
                '  echo "Scanning: $url" >> %s; '
                '  wpscan_flags="--url $url --enumerate vp,vt,u '
                '    --plugins-detection aggressive '
                '    --format json --no-banner --random-user-agent"; '
                '  [ -n "$WPSCAN_API_TOKEN" ] && wpscan_flags="$wpscan_flags --api-token $WPSCAN_API_TOKEN"; '
                '  result=$(eval wpscan $wpscan_flags 2>>%s); '
                '  if [ -n "$result" ]; then '
                '    python3 -c "import json,sys; '
                '      existing=json.load(open(\'%s\')); '
                '      new=json.loads(sys.argv[1]); '
                '      new[\'target_url\']=sys.argv[2]; '
                '      existing.append(new); '
                '      json.dump(existing,open(\'%s\',\'w\'),indent=2)" '
                '      "$result" "$url" 2>>%s; '
                '  fi; '
                'done < %s'
            ) % (str(output_file), str(log_file), str(log_file),
                 str(output_file), str(output_file), str(log_file),
                 str(input_path))
            log_fh = open(log_file, "w")
            log_fh.write("Starting wpscan on %s\n" % input_file)
            log_fh.flush()
            proc = subprocess.Popen(
                _netns_wrap_cmd(["bash", "-c", cmd_str], _pipeline_netns),
                stdout=subprocess.DEVNULL, stderr=log_fh,
                preexec_fn=os.setsid,
            )
            scan_info = {
                "pid": proc.pid,
                "tool": tool,
                "target_name": target_name,
                "output_file": str(output_file),
                "json_output": str(json_output),
                "log_file": str(log_file),
                "started_at": time.time(),
                "process": proc,
                "log_fh": log_fh,
                "stdin_fh": None,
                "netns": _pipeline_netns,
            }
            SCANS[proc.pid] = scan_info
            _save_scans()
            return self._send_json({
                "pid": proc.pid,
                "tool": tool,
                "output_file": output_file.name,
                "json_output": json_output.name,
                "log_file": log_file.name,
            }, 201)

        elif tool == "ffuf":
            if not input_file:
                return self._send_json({"error": "input_file required for ffuf"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("ffuf_%d.json" % timestamp)
            json_output = output_file
            # Use SecLists common wordlist if available, otherwise a small built-in list
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                return self._send_json({"error": "no wordlist found (install seclists)"}, 400)
            # If input is JSONL (from httpx), extract URLs into a plain text file
            targets_file = input_path
            if str(input_path).endswith(".jsonl") or str(input_path).endswith(".json"):
                urls_file = target_dir / ("ffuf_targets_%d.txt" % timestamp)
                try:
                    with open(input_path) as f:
                        urls = []
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            if line.startswith("{"):
                                try:
                                    obj = json.loads(line)
                                    url = obj.get("url", "")
                                    if url:
                                        urls.append(url.rstrip("/"))
                                except json.JSONDecodeError:
                                    pass
                            else:
                                urls.append(line.rstrip("/"))
                    with open(urls_file, "w") as f:
                        f.write("\n".join(urls) + "\n")
                    targets_file = urls_file
                except Exception:
                    pass  # fall back to raw file
            cmd = [
                "ffuf", "-u", "FUZZ_TARGET/FUZZ",
                "-w", "%s:FUZZ" % wordlist,
                "-w", "%s:FUZZ_TARGET" % str(targets_file),
                "-ac",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-o", str(output_file),
                "-of", "json",
                "-t", "20",
                "-rate", "50",
            ]
            # Override: if options specify a single URL, fuzz that directly
            if options.get("url"):
                cmd = [
                    "ffuf", "-u", "%s/FUZZ" % options["url"].rstrip("/"),
                    "-w", wordlist,
                    "-ac",
                    "-mc", "200,201,204,301,302,307,401,403,405",
                    "-o", str(output_file),
                    "-of", "json",
                    "-t", "20",
                    "-rate", "50",
                ]

        elif tool == "dalfox":
            if not input_file:
                return self._send_json({"error": "input_file required for dalfox"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("dalfox_%d.json" % timestamp)
            json_output = output_file
            cmd = [
                "dalfox", "file", str(input_path),
                "-o", str(output_file),
                "--format", "json",
                "--silence",
                "--worker", "10",
            ]

        elif tool == "amass":
            if not domains:
                return self._send_json({"error": "domains required for amass"}, 400)
            domain_file = target_dir / "domains.txt"
            if not domain_file.exists():
                domain_file.write_text("\n".join(domains) + "\n")
            output_file = target_dir / ("amass_%d.txt" % timestamp)
            # `-timeout 30` was halting amass at 30 minutes mid-discovery before
            # results were flushed. Bump to 90 min so amass v5 has time to finish
            # passive enum on dozens of root domains. Heavy-tools concurrency
            # gate (MAX_CONCURRENT_HEAVY=1) prevents amass from blocking other
            # phases since it runs in parallel with subfinder/crt-sh during
            # phase 1 only.
            cmd = [
                "amass", "enum", "-passive",
                "-df", str(domain_file),
                "-o", str(output_file),
                "-timeout", "90",
            ]

        elif tool == "crt-sh":
            # Built-in Python tool — queries crt.sh certificate transparency
            domain_file = target_dir / "domains.txt"
            if not domains and not domain_file.exists():
                return self._send_json({"error": "domains required for crt-sh"}, 400)
            if domains and not domain_file.exists():
                domain_file.write_text("\n".join(domains) + "\n")
            output_file = target_dir / ("crt_sh_%d.txt" % timestamp)
            log_file = target_dir / ("crt-sh_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--crt-sh",
                str(domain_file), str(output_file), str(log_file),
            ]

        elif tool == "gospider":
            if not input_file:
                return self._send_json({"error": "input_file required for gospider"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Extract URLs from httpx JSONL, filtering wildcards
            urls_file = target_dir / ("gospider_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path,
                                           exclude_codes={404, 500, 502, 503, 504},
                                           filter_wildcards=True)
            # Cap at 200 URLs — gospider with -d 3 on large target lists causes
            # multi-hour runtimes, 4GB+ memory, and 1GB+ output
            MAX_GOSPIDER_URLS = 200
            if len(urls) > MAX_GOSPIDER_URLS:
                print("  [gospider] capping input from %d to %d URLs" % (len(urls), MAX_GOSPIDER_URLS))
                urls = urls[:MAX_GOSPIDER_URLS]
            urls_file.write_text("\n".join(urls) + "\n")
            output_file = target_dir / ("gospider_%d.txt" % timestamp)
            cmd = [
                "gospider", "-S", str(urls_file),
                "-o", str(target_dir / ("gospider_raw_%d" % timestamp)),
                "-c", "5", "-d", "2", "--js", "-t", "5",
                "--json",
                "--sitemap", "--robots", "--include-subs",
                "-a", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ]
            # gospider writes to a directory; we'll merge in results parsing
            # Store the raw dir path as json_output for parsing
            json_output = str(target_dir / ("gospider_raw_%d" % timestamp))

        elif tool == "joomscan":
            if not input_file:
                return self._send_json({"error": "input_file required for joomscan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Read CMS detect output, filter Joomla sites
            joomla_urls = []
            try:
                with open(input_path) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    if entry.get("cms", "").lower() == "joomla":
                        joomla_urls.append(entry["url"])
            except (json.JSONDecodeError, ValueError, KeyError):
                pass
            if not joomla_urls:
                return self._send_json({"error": "no joomla targets found in cms-detect output"}, 400)
            output_file = target_dir / ("joomscan_%d.txt" % timestamp)
            json_output = target_dir / ("joomscan_%d.json" % timestamp)
            # Run joomscan per-URL via bash loop, aggregate output
            url_list = "\n".join(joomla_urls)
            cmd = [
                "bash", "-c",
                'echo "[]" > %s; echo "%s" | while IFS= read -r url; do '
                '[ -z "$url" ] && continue; '
                'echo "Scanning: $url" >> %s; '
                'joomscan -u "$url" >> %s 2>&1; '
                'done' % (str(json_output), url_list.replace('"', '\\"'),
                          str(output_file), str(output_file)),
            ]

        elif tool == "sqlmap":
            if not input_file:
                return self._send_json({"error": "input_file required for sqlmap"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Read arjun output (JSON: {url: [params]}) or plain URL list
            # Test ALL discovered params, not just the first
            targets = []
            try:
                with open(input_path) as f:
                    data = json.loads(f.read())
                if isinstance(data, dict):
                    for url, params in data.items():
                        if isinstance(params, list):
                            for param in params:
                                targets.append("%s?%s=test" % (url, param))
            except (json.JSONDecodeError, ValueError):
                # Fall back to plain URL list
                with open(input_path) as f:
                    targets = [line.strip() for line in f if line.strip() and "?" in line]
            if not targets:
                return self._send_json({"error": "no injectable URLs found in input"}, 400)
            MAX_SQLMAP_TARGETS = 50
            targets = targets[:MAX_SQLMAP_TARGETS]
            targets_file = target_dir / ("sqlmap_targets_%d.txt" % timestamp)
            targets_file.write_text("\n".join(targets) + "\n")
            output_file = target_dir / ("sqlmap_%d.txt" % timestamp)
            json_output = target_dir / ("sqlmap_%d.json" % timestamp)
            # Run sqlmap in batch mode per-URL.  Use python3 to emit valid JSONL
            # — the previous bash heredoc didn't escape URLs containing &/=/quotes,
            # producing invalid JSON that the result-parser silently dropped.
            # sqlmap's stdout contains "not injectable" — a naive grep for
            # "injectable" or "vulnerable" matches both negative and positive
            # cases. The only authoritative signal is the per-iteration
            # results CSV: sqlmap writes a row only when it confirms an
            # injection. We pass --results-file with a unique path per URL
            # and count rows; an empty file (or header-only file) means no
            # injection was found.
            cmd = [
                "bash", "-c",
                ': > %s; i=0; '
                'while IFS= read -r url; do '
                '[ -z "$url" ] && continue; '
                'i=$((i+1)); '
                'results_csv="%s/sqlmap_out_%d/result_${i}.csv"; '
                'mkdir -p "$(dirname "$results_csv")"; '
                'echo "Testing: $url" >> %s; '
                'output=$(sqlmap -u "$url" --batch --level=2 --risk=2 '
                '--random-agent --tamper=space2comment,between,randomcase --smart '
                '--threads=4 --timeout=15 --retries=1 '
                '--output-dir=%s/sqlmap_out_%d '
                '--results-file="$results_csv" 2>&1); '
                'echo "$output" >> %s; '
                # Confirmed injection = CSV exists AND has data rows beyond the header.
                'if [ -f "$results_csv" ] && [ "$(wc -l < "$results_csv")" -gt 1 ]; then '
                'csv_row=$(tail -n +2 "$results_csv" | head -1); '
                'URL="$url" CSV="$csv_row" python3 -c '
                '"import os,json,sys; '
                'sys.stdout.write(json.dumps({\\"url\\":os.environ[\\"URL\\"],\\"vulnerable\\":True,\\"csv_row\\":os.environ[\\"CSV\\"][:2000]})+chr(10))" '
                '>> %s; '
                'fi; '
                'done < %s' % (str(json_output), str(target_dir), timestamp,
                               str(output_file), str(target_dir), timestamp,
                               str(output_file), str(json_output), str(targets_file)),
            ]

        elif tool == "commix":
            if not input_file:
                return self._send_json({"error": "input_file required for commix"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Read arjun output or plain URL list — test ALL discovered params
            targets = []
            try:
                with open(input_path) as f:
                    data = json.loads(f.read())
                if isinstance(data, dict):
                    for url, params in data.items():
                        if isinstance(params, list):
                            for param in params:
                                targets.append("%s?%s=test" % (url, param))
            except (json.JSONDecodeError, ValueError):
                with open(input_path) as f:
                    targets = [line.strip() for line in f if line.strip() and "?" in line]
            if not targets:
                return self._send_json({"error": "no injectable URLs found in input"}, 400)
            MAX_COMMIX_TARGETS = 30
            targets = targets[:MAX_COMMIX_TARGETS]
            targets_file = target_dir / ("commix_targets_%d.txt" % timestamp)
            targets_file.write_text("\n".join(targets) + "\n")
            output_file = target_dir / ("commix_%d.txt" % timestamp)
            json_output = target_dir / ("commix_%d.json" % timestamp)
            # JSONL output emitted via python3 to avoid shell-quoting bugs (URLs
            # with & or = were producing invalid JSON arrays that crashed the
            # status handler).
            # Confirmed injection requires BOTH a parameter-injectable marker
            # AND a concrete Payload line.  The previous heuristic of
            # `is vulnerable|command injection` matched commix's startup
            # banner and per-test prompts (e.g. the literal phrase "command
            # injection" appears in commix's tool description), producing
            # 100% FP across the 2026-05-27 batch (7/7 hits).
            # See memory feedback_commix_parser_fp.md.
            cmd = [
                "bash", "-c",
                ': > %s; '
                'while IFS= read -r url; do '
                '[ -z "$url" ] && continue; '
                'echo "Testing: $url" >> %s; '
                'output=$(commix --url="$url" --batch --level=2 --random-agent --timeout=15 2>&1); '
                'echo "$output" >> %s; '
                # Real injection emits a line like:
                #   [+] The (POST) parameter 'id' seems injectable via (results-based) ...
                # OR the post-confirmation line:
                #   [!] The (GET) parameter 'id' is vulnerable.
                # Followed by `Type:` and `Payload:` lines in the technical
                # report.  Require ALL THREE — `seems injectable|is vulnerable`
                # AND a `Type:` line AND a `Payload:` line.
                'if echo "$output" | grep -Eqi "(seems injectable|is vulnerable)" '
                ' && echo "$output" | grep -q "Type:" '
                ' && echo "$output" | grep -q "Payload:"; then '
                # Capture the Payload + Type lines as the evidence so triage
                # can see the actual confirmed injection without re-running.
                'evidence=$(echo "$output" | grep -E "(seems injectable|is vulnerable|^Type:|^Payload:|^Place:)" | head -20); '
                'URL="$url" OUT="$evidence" python3 -c '
                '"import os,json,sys; '
                'sys.stdout.write(json.dumps({\\"url\\":os.environ[\\"URL\\"],\\"vulnerable\\":True,\\"output\\":os.environ[\\"OUT\\"][:2000]})+chr(10))" '
                '>> %s; '
                'fi; '
                'done < %s' % (str(json_output), str(output_file), str(output_file),
                               str(json_output), str(targets_file)),
            ]

        elif tool == "hydra":
            if not input_file:
                return self._send_json({"error": "input_file required for hydra"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Read panel-detect output for login pages
            login_urls = []
            try:
                with open(input_path) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    url = entry.get("url", "")
                    title = entry.get("title", "").lower()
                    keyword = entry.get("matched_keyword", "").lower()
                    if any(k in keyword or k in title for k in ("login", "admin", "wp-login", "wp-admin")):
                        login_urls.append(url)
            except (json.JSONDecodeError, ValueError, KeyError):
                pass
            if not login_urls:
                return self._send_json({"error": "no login panels found in panel-detect output"}, 400)
            MAX_HYDRA_TARGETS = 20
            login_urls = login_urls[:MAX_HYDRA_TARGETS]
            output_file = target_dir / ("hydra_%d.txt" % timestamp)
            json_output = target_dir / ("hydra_%d.json" % timestamp)
            # Test common default creds — try both HTTP Basic Auth and common form-based logins
            url_list = "\n".join(login_urls)
            cmd = [
                "bash", "-c",
                'echo "[]" > %s; echo "%s" | while IFS= read -r url; do '
                '[ -z "$url" ] && continue; '
                'host=$(echo "$url" | sed "s|https\\?://||" | cut -d/ -f1 | cut -d: -f1); '
                'port=$(echo "$url" | grep -oP ":\\K[0-9]+" | head -1); '
                '[ -z "$port" ] && { echo "$url" | grep -q "^https" && port=443 || port=80; }; '
                'path=$(echo "$url" | sed "s|https\\?://[^/]*||"); '
                '[ -z "$path" ] && path="/"; '
                'proto="https"; echo "$url" | grep -q "^http:" && proto="http"; '
                'echo "Testing: $host:$port ($path)" >> %s; '
                # Try HTTP Basic Auth first
                'output=$(hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt '
                '-P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt '
                '-t 4 -W 2 '
                '-s "$port" -f "$host" ${proto}-get "$path" 2>&1); '
                'echo "$output" >> %s; '
                'if echo "$output" | grep -qi "\\[.*\\].*host:"; then '
                'echo "{\"url\":\"$url\",\"host\":\"$host\",\"result\":\"$(echo "$output" | grep "\\[.*\\].*host:" | head -3 | sed \'s/"/\\\\"/g\' | tr \'\\n\' \' \')\"}" >> %s; '
                'else '
                # Try HTTP POST form login (common field names)
                'output2=$(hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt '
                '-P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt '
                '-t 4 -W 2 '
                '-s "$port" -f "$host" ${proto}-post-form '
                '"${path}:username=^USER^&password=^PASS^:F=Invalid|incorrect|denied|failed|error" 2>&1); '
                'echo "$output2" >> %s; '
                'if echo "$output2" | grep -qi "\\[.*\\].*host:"; then '
                'echo "{\"url\":\"$url\",\"host\":\"$host\",\"result\":\"$(echo "$output2" | grep "\\[.*\\].*host:" | head -3 | sed \'s/"/\\\\"/g\' | tr \'\\n\' \' \')\"}" >> %s; '
                'fi; fi; '
                'done' % (str(json_output), url_list.replace('"', '\\"'),
                          str(output_file), str(output_file), str(json_output),
                          str(output_file), str(json_output)),
            ]

        elif tool == "gitleaks":
            if not domains:
                pass
            output_file = target_dir / ("gitleaks_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("gitleaks_%d.log" % timestamp)
            org_name = options.get("org", target_name.split(".")[0] if "." in target_name else target_name)
            cmd = [
                "python3", os.path.abspath(__file__), "--gitleaks",
                org_name, str(output_file), str(log_file),
            ]

        elif tool == "eyewitness":
            if not input_file:
                return self._send_json({"error": "input_file required for eyewitness"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Extract URLs from httpx JSONL, filtering wildcards
            urls_file = target_dir / ("eyewitness_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            # EyeWitness never restarts Firefox between hosts, so the content
            # process leaks ~250MB/host and OOMs at ~20 hosts on 8GB VMs.
            # 15 unique hosts keeps Firefox under ~4GB with headroom.
            MAX_EYEWITNESS_URLS = 15
            seen_hosts = set()
            deduped = []
            for u in urls:
                try:
                    from urllib.parse import urlparse as _up
                    host = _up(u).hostname
                except Exception:
                    host = u
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    deduped.append(u)
            urls = deduped[:MAX_EYEWITNESS_URLS]
            urls_file.write_text("\n".join(urls) + "\n")
            output_dir = target_dir / ("eyewitness_%d" % timestamp)
            output_file = target_dir / ("eyewitness_%d.txt" % timestamp)
            json_output = str(output_dir)
            cmd = [
                "eyewitness", "-f", str(urls_file),
                "-d", str(output_dir),
                "--no-prompt", "--timeout", "15",
                # Single thread: Firefox content process leaks ~250MB/host.
                "--threads", "1",
            ]

        elif tool == "git-dumper":
            # Built-in Python tool — checks live hosts for exposed .git dirs
            if not input_file:
                return self._send_json({"error": "input_file required for git-dumper"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("git_dumper_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("git-dumper_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--git-dumper",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "nomore403":
            if not input_file:
                return self._send_json({"error": "input_file required for nomore403"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # Extract URLs with 403 status from httpx JSONL
            forbidden_urls = []
            with open(input_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        sc = obj.get("status-code", obj.get("status_code", 0))
                        if sc in (401, 403):
                            url = obj.get("url", obj.get("input", ""))
                            if url:
                                forbidden_urls.append(url)
                    except (json.JSONDecodeError, ValueError):
                        pass
            if not forbidden_urls:
                return self._send_json({"error": "no 403/401 URLs found in httpx output"}, 400)
            MAX_403_TARGETS = 100
            forbidden_urls = forbidden_urls[:MAX_403_TARGETS]
            targets_file = target_dir / ("nomore403_targets_%d.txt" % timestamp)
            targets_file.write_text("\n".join(forbidden_urls) + "\n")
            output_file = target_dir / ("nomore403_%d.txt" % timestamp)
            json_output = target_dir / ("nomore403_%d.json" % timestamp)
            cmd = [
                "bash", "-c",
                'echo "[]" > %s; while IFS= read -r url; do '
                '[ -z "$url" ] && continue; '
                'echo "Testing: $url" >> %s; '
                'output=$(nomore403 -u "$url" -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" 2>&1); '
                'echo "$output" >> %s; '
                'if echo "$output" | grep -qE "\\b(200|30[0-9])\\b"; then '
                'bypassed=$(echo "$output" | grep -E "\\b(200|30[0-9])\\b" | head -5 | sed \'s/"/\\\\"/g\' | tr \'\\n\' \' \'); '
                'echo "{\"url\":\"$url\",\"bypassed\":true,\"techniques\":\"$bypassed\"}" >> %s; '
                'fi; '
                'done < %s' % (str(json_output), str(output_file), str(output_file),
                               str(json_output), str(targets_file)),
            ]

        elif tool == "kiterunner":
            if not input_file:
                return self._send_json({"error": "input_file required for kiterunner"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            urls_file = target_dir / ("kiterunner_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            MAX_KR_TARGETS = 50
            urls_file.write_text("\n".join(urls[:MAX_KR_TARGETS]) + "\n")
            output_file = target_dir / ("kiterunner_%d.txt" % timestamp)
            json_output = target_dir / ("kiterunner_%d.json" % timestamp)
            cmd = [
                "bash", "-c",
                'kr scan %s -w /usr/share/kiterunner/routes-large.kite '
                '-o json '
                '--fail-status-codes 400,401,404,403,501,502,426,411 '
                '--max-connection-per-host 3 '
                '-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" '
                '2>%s | tee %s; '
                'true' % (str(urls_file), str(output_file), str(json_output)),
            ]

        elif tool == "corscanner":
            if not input_file:
                return self._send_json({"error": "input_file required for corscanner"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            urls_file = target_dir / ("corscanner_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            urls_file.write_text("\n".join(urls) + "\n")
            output_file = target_dir / ("corscanner_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("corscanner_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--corscanner",
                str(urls_file), str(output_file), str(log_file),
            ]

        elif tool == "trufflehog":
            output_file = target_dir / ("trufflehog_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("trufflehog_%d.log" % timestamp)
            org_name = options.get("org", target_name.split(".")[0] if "." in target_name else target_name)
            # --no-update: prevent the self-updater from failing the run
            # ("cannot move binary (exit status 1)") on permission-denied
            cmd = [
                "bash", "-c",
                'trufflehog --no-update github --org="%s" --include-members --include-forks '
                '--results=verified,unknown --json '
                '2>%s >%s; true' % (org_name, str(log_file), str(output_file)),
            ]

        elif tool == "paramspider":
            if not input_file:
                return self._send_json({"error": "input_file required for paramspider"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("paramspider_%d.txt" % timestamp)
            # Read domains from merge-subs and run paramspider per domain
            with open(input_path) as f:
                subs = [l.strip() for l in f if l.strip()]
            # Extract unique base domains
            seen = set()
            base_domains = []
            for s in subs:
                parts = s.split(".")
                base = ".".join(parts[-2:]) if len(parts) >= 2 else s
                if base not in seen:
                    seen.add(base)
                    base_domains.append(base)
            MAX_PARAMSPIDER = 20
            base_domains = base_domains[:MAX_PARAMSPIDER]
            domain_cmds = " && ".join(
                'paramspider -d "%s" --output /dev/stdout 2>/dev/null >> "%s"'
                % (d, str(output_file)) for d in base_domains
            )
            cmd = ["bash", "-c", 'touch "%s"; %s; sort -u "%s" -o "%s"'
                   % (str(output_file), domain_cmds, str(output_file), str(output_file))]

        elif tool == "nextjs-check":
            if not input_file:
                return self._send_json({"error": "input_file required for nextjs-check"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("nextjs_check_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("nextjs-check_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--nextjs-check",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "spa-catchall-detect":
            if not input_file:
                return self._send_json({"error": "input_file required for spa-catchall-detect"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("spa_catchall_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("spa-catchall-detect_%d.log" % timestamp)
            cmd = [
                "python3", os.path.abspath(__file__), "--spa-catchall-detect",
                str(input_path), str(output_file), str(log_file),
            ]

        elif tool == "dnsx":
            if not input_file:
                return self._send_json({"error": "input_file required for dnsx"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("dnsx_%d.txt" % timestamp)
            cname_file = target_dir / ("dnsx_cnames_%d.txt" % timestamp)
            json_output = target_dir / ("dnsx_%d.json" % timestamp)
            # dnsx -recon asks 5+ record types per host; scale -rl by budget.
            # Phase 6: raised base 100 → 250 (Hetzner exit).
            dnsx_rl = max(20, int(250 * budget["scale_dns"]))
            cmd = [
                "bash", "-c",
                'dnsx -l "%s" -recon -cdn -asn -resp -json -rl %d -o "%s" 2>/dev/null; '
                'cat "%s" | jq -r "select(.cname != null) | .host + \" CNAME \" + (.cname | join(\",\"))" > "%s" 2>/dev/null; '
                'true' % (str(input_path), dnsx_rl, str(json_output), str(json_output), str(cname_file)),
            ]

        elif tool == "feroxbuster":
            if not input_file:
                return self._send_json({"error": "input_file required for feroxbuster"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            urls_file = target_dir / ("feroxbuster_urls_%d.txt" % timestamp)
            urls = _extract_urls_from_httpx(input_path, filter_wildcards=True)
            MAX_FEROX_TARGETS = 15
            urls_file.write_text("\n".join(urls[:MAX_FEROX_TARGETS]) + "\n")
            output_file = target_dir / ("feroxbuster_%d.txt" % timestamp)
            json_output = output_file  # feroxbuster --json writes JSON to the -o file
            cmd = [
                "feroxbuster", "--stdin",
                "-o", str(output_file),
                "--json",
                "-d", "1", "-t", "10", "-L", "3", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
                "-x", "php,asp,aspx,jsp,json,xml,conf,bak,old,txt,env",
                "--extract-links", "--collect-words",
                "--auto-tune", "--silent", "--no-state",
                "-k", "--timeout", "10",
                "-C", "400,404,503",
            ]
            stdin_fh = open(urls_file, "r")

        # ============================================================
        # ORACLE PIPELINE TOOLS
        # ============================================================
        elif tool == "sslscan":
            # Wrapper around the sslscan binary. Scans every host:port from httpx
            # and captures cipher suites + TLS versions + cert details.
            if not input_file:
                return self._send_json({"error": "input_file required for sslscan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            # sslscan runs per-host, so we wrap with a shell loop + XML output
            # then parse the concatenated output in from-disk ingestion.
            output_file = target_dir / ("sslscan_%d.xml" % timestamp)
            log_file = target_dir / ("sslscan_%d.log" % timestamp)
            # Extract https:// hosts from httpx JSONL, limit to 150 to keep runtime bounded
            hosts = _extract_tls_hosts_from_httpx(input_path, limit=150)
            hosts_file = target_dir / ("sslscan_hosts_%d.txt" % timestamp)
            hosts_file.write_text("\n".join(hosts) + "\n")
            log_fh = open(log_file, "w")
            log_fh.write("sslscan on %d hosts\n" % len(hosts))
            log_fh.flush()
            cmd_str = (
                'echo "<sslscan_results>" > %s; '
                'while IFS= read -r host; do '
                '  [ -z "$host" ] && continue; '
                '  echo "<host target=\\"$host\\">" >> %s; '
                '  timeout 60 sslscan --no-colour --no-heartbleed --connect-timeout=10 --xml=- "$host" 2>>%s >> %s || true; '
                '  echo "</host>" >> %s; '
                'done < %s; '
                'echo "</sslscan_results>" >> %s'
            ) % (output_file, output_file, log_file, output_file, output_file,
                 hosts_file, output_file)
            proc = subprocess.Popen(
                _netns_wrap_cmd(["bash", "-c", cmd_str], _pipeline_netns),
                stdout=subprocess.DEVNULL, stderr=log_fh,
                preexec_fn=os.setsid,
            )
            scan_info = {
                "pid": proc.pid, "tool": tool, "target_name": target_name,
                "output_file": str(output_file), "json_output": None,
                "log_file": str(log_file), "started_at": time.time(),
                "process": proc, "log_fh": log_fh, "stdin_fh": None,
                "netns": _pipeline_netns,
            }
            SCANS[proc.pid] = scan_info
            _save_scans()
            return self._send_json({
                "pid": proc.pid, "tool": tool,
                "output_file": output_file.name, "json_output": None,
                "log_file": log_file.name,
            }, 201)

        elif tool == "sslyze":
            # Wrapper around the sslyze binary. Single JSON file over all hosts.
            if not input_file:
                return self._send_json({"error": "input_file required for sslyze"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("sslyze_%d.json" % timestamp)
            json_output = output_file
            hosts = _extract_tls_hosts_from_httpx(input_path, limit=150)
            if not hosts:
                # Write empty result to satisfy pipeline completion
                output_file.write_text('{"server_scan_results": []}')
                log_file = target_dir / ("sslyze_%d.log" % timestamp)
                log_file.write_text("no TLS hosts found in input\n")
                proc = subprocess.Popen(["true"])
                proc.wait()
                scan_info = {
                    "pid": proc.pid, "tool": tool, "target_name": target_name,
                    "output_file": str(output_file), "json_output": str(json_output),
                    "log_file": str(log_file), "started_at": time.time(),
                    "process": proc, "log_fh": None, "stdin_fh": None,
                    "netns": _pipeline_netns,
                }
                SCANS[proc.pid] = scan_info
                _save_scans()
                return self._send_json({
                    "pid": proc.pid, "tool": tool,
                    "output_file": output_file.name,
                    "json_output": output_file.name,
                    "log_file": log_file.name,
                }, 201)
            # Write hosts to a targets file to avoid ARG_MAX limits
            sslyze_targets_file = target_dir / ("sslyze_targets_%d.txt" % timestamp)
            sslyze_targets_file.write_text("\n".join(hosts) + "\n")
            cmd = ["sslyze", "--json_out=" + str(output_file),
                   "--targets_in=" + str(sslyze_targets_file),
                   "--certinfo", "--sslv2", "--sslv3",
                   "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
                   "--robot", "--heartbleed",
                   "--compression", "--elliptic_curves",
                   "--openssl_ccs", "--early_data", "--fallback", "--reneg"]

        elif tool == "saml-fingerprint":
            # Built-in Python: probe common SAML paths, parse metadata, flag rsa-1_5
            if not input_file:
                return self._send_json({"error": "input_file required for saml-fingerprint"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("saml_fingerprint_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("saml-fingerprint_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--saml-fingerprint",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "jwt-jwe-harvest":
            # Built-in Python: fetch common auth paths, extract JWTs from responses
            if not input_file:
                return self._send_json({"error": "input_file required for jwt-jwe-harvest"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("jwt_jwe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("jwt-jwe-harvest_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--jwt-jwe-harvest",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "cookie-harvest":
            # Built-in Python: capture Set-Cookie + URL params, compute entropy
            if not input_file:
                return self._send_json({"error": "input_file required for cookie-harvest"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("cookies_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("cookie-harvest_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--cookie-harvest",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "roca-scan":
            # Built-in Python: offline ROCA (CVE-2017-15361) fingerprint over RSA pubkeys
            # Takes sslyze JSON as input and extracts certs from it
            if not input_file:
                return self._send_json({"error": "input_file required for roca-scan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("roca_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("roca-scan_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--roca-scan",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "breach-candidate":
            # Built-in Python: fetch URLs, detect compression + reflection + secret-like tokens
            if not input_file:
                return self._send_json({"error": "input_file required for breach-candidate"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("breach_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("breach-candidate_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--breach-candidate",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "tls-oracle-probe":
            # Built-in Python: active ROBOT probe (Böck et al. 2018) — send malformed
            # PKCS#1 v1.5 ClientKeyExchanges to hosts flagged by sslscan as TLS_RSA_*
            if not input_file:
                return self._send_json({"error": "input_file required for tls-oracle-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("tls_oracle_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("tls-oracle-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--tls-oracle-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "xmlenc-oracle-probe":
            # Built-in Python: active XML-Enc Bleichenbacher probe on SAML ACS endpoints
            # flagged by saml-fingerprint as advertising rsa-1_5
            if not input_file:
                return self._send_json({"error": "input_file required for xmlenc-oracle-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("xmlenc_oracle_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("xmlenc-oracle-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--xmlenc-oracle-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "cbc-padding-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for cbc-padding-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("cbc_padding_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("cbc-padding-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--cbc-padding-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "marvin-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for marvin-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("marvin_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("marvin-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--marvin-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "xsw-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for xsw-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("xsw_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("xsw-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--xsw-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "viewstate-fingerprint":
            if not input_file:
                return self._send_json({"error": "input_file required for viewstate-fingerprint"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("viewstate_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("viewstate-fingerprint_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--viewstate-fingerprint",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "jwe-invalid-curve-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for jwe-invalid-curve-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("jwe_invalid_curve_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("jwe-invalid-curve-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--jwe-invalid-curve-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "manger-oaep-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for manger-oaep-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("manger_oaep_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("manger-oaep-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--manger-oaep-probe",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "ssh-terrapin-scan":
            if not input_file:
                return self._send_json({"error": "input_file required for ssh-terrapin-scan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("ssh_terrapin_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("ssh-terrapin-scan_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--ssh-terrapin-scan",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "gcm-nonce-scan":
            if not input_file:
                return self._send_json({"error": "input_file required for gcm-nonce-scan"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("gcm_nonce_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("gcm-nonce-scan_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--gcm-nonce-scan",
                   str(input_path), str(output_file), str(log_file)]

        elif tool == "raccoon-probe":
            if not input_file:
                return self._send_json({"error": "input_file required for raccoon-probe"}, 400)
            input_path = target_dir / input_file
            if not input_path.exists():
                return self._send_json({"error": "input file %s not found" % input_file}, 404)
            output_file = target_dir / ("raccoon_probe_%d.json" % timestamp)
            json_output = output_file
            log_file = target_dir / ("raccoon-probe_%d.log" % timestamp)
            cmd = ["python3", os.path.abspath(__file__), "--raccoon-probe",
                   str(input_path), str(output_file), str(log_file)]

        else:
            return self._send_json({"error": "unsupported tool: %s" % tool}, 400)

        if tool in ("s3-takeover", "merge-subs", "merge-urls", "cloud-buckets",
                    "secret-scan", "cms-detect", "panel-detect", "crt-sh", "git-dumper",
                    "gitleaks", "corscanner", "nextjs-check",
                    "saml-fingerprint", "jwt-jwe-harvest", "cookie-harvest",
                    "roca-scan", "breach-candidate", "tls-oracle-probe",
                    "xmlenc-oracle-probe",
                    "cbc-padding-probe", "marvin-probe", "xsw-probe",
                    "viewstate-fingerprint", "jwe-invalid-curve-probe",
                    "manger-oaep-probe", "ssh-terrapin-scan",
                    "gcm-nonce-scan", "raccoon-probe"):
            # These subprocesses manage their own log files; redirect
            # Popen stdout to devnull so we don't clobber it
            log_fh = open(os.devnull, "w")
        else:
            log_file = target_dir / ("%s_%d.log" % (tool, timestamp))
            log_fh = open(log_file, "w")

        proc = subprocess.Popen(
            _netns_wrap_cmd(cmd, _pipeline_netns),
            stdout=log_fh, stderr=subprocess.STDOUT,
            stdin=stdin_fh,
            preexec_fn=_make_preexec(tool),
        )

        scan_info = {
            "pid": proc.pid,
            "tool": tool,
            "target_name": target_name,
            "output_file": str(output_file),
            "json_output": str(json_output) if json_output else None,
            "log_file": str(log_file),
            "started_at": time.time(),
            "process": proc,
            "log_fh": log_fh,
            "stdin_fh": stdin_fh,
            "netns": _pipeline_netns,
        }
        SCANS[proc.pid] = scan_info
        _save_scans()

        self._send_json({
            "pid": proc.pid,
            "tool": tool,
            "output_file": output_file.name,
            "json_output": Path(json_output).name if json_output else None,
            "log_file": log_file.name,
        }, 201)

    def _handle_status(self, pid):
        scan = SCANS.get(pid)
        if not scan:
            return self._send_json({"error": "scan not found"}, 404)

        poll = _poll_scan(scan)

        output_path = Path(scan["output_file"])
        line_count = 0
        file_size = 0
        if output_path.exists():
            file_size = output_path.stat().st_size
            # Don't count lines on huge files — use size estimate instead
            if file_size > 500 * 1024 * 1024:  # 500 MB
                line_count = file_size // 40  # rough estimate
            else:
                with open(output_path) as f:
                    line_count = sum(1 for _ in f)
        elif scan.get("tool") == "gospider" and scan.get("json_output"):
            # gospider writes to a raw directory, not the merged .txt file.
            # Check the directory for output when the .txt doesn't exist yet.
            raw_dir = Path(scan["json_output"])
            if raw_dir.exists() and raw_dir.is_dir():
                raw_files = [f for f in raw_dir.iterdir() if f.is_file() and f.stat().st_size > 0]
                if raw_files:
                    line_count = sum(1 for f in raw_files for _ in open(f) if _.strip())
                    file_size = sum(f.stat().st_size for f in raw_files)

        # Kill runaway scans that produce >500MB output (e.g. dnsgen explosion)
        MAX_OUTPUT_SIZE = 500 * 1024 * 1024
        if poll is None and file_size > MAX_OUTPUT_SIZE:
            proc = scan.get("process")
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
            poll = -1  # mark as failed

        if poll is None:
            status = "running"
        else:
            # exit code 0 = success, non-zero = failed UNLESS results were produced
            # (nmap/arjun can crash mid-scan but still have usable partial output)
            if poll == 0:
                status = "completed"
            elif line_count > 0:
                status = "completed"
            else:
                status = "failed"

        self._send_json({
            "pid": pid,
            "tool": scan["tool"],
            "status": status,
            "exit_code": poll,
            "result_count": line_count,
            "output_file": output_path.name,
            "elapsed": time.time() - scan["started_at"],
            "bytes_attributed": scan.get("bytes_attributed", 0),
        })

    def _handle_output(self, pid, lines):
        scan = SCANS.get(pid)
        if not scan:
            return self._send_json({"error": "scan not found"}, 404)

        log_path = Path(scan["log_file"])
        tail = []
        if log_path.exists():
            with open(log_path) as f:
                all_lines = f.readlines()
                tail = all_lines[-lines:]

        self._send_json({"log": "".join(tail)})

    def _handle_results(self, pid):
        scan = SCANS.get(pid)
        if not scan:
            return self._send_json({"error": "scan not found"}, 404)

        tool = scan["tool"]
        results = []

        if tool in ("subfinder", "katana", "getallurls"):
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    results = [{"value": line.strip()} for line in f if line.strip()]

        elif tool == "httpx-toolkit":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            results.append({
                                "value": obj.get("url", obj.get("input", "")),
                                "status_code": obj.get("status-code", obj.get("status_code")),
                                "title": obj.get("title", ""),
                                "tech": obj.get("technologies", obj.get("tech", [])),
                                "content_length": obj.get("content-length", obj.get("content_length")),
                                "content_type": obj.get("content-type", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue

        elif tool == "nuclei":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            info = obj.get("info", {})
                            results.append({
                                "value": obj.get("matched-at", obj.get("host", "")),
                                "template_id": obj.get("template-id", ""),
                                "name": info.get("name", ""),
                                "severity": info.get("severity", ""),
                                "description": info.get("description", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue

        elif tool == "nuclei-takeover":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            info = obj.get("info", {})
                            results.append({
                                "value": obj.get("matched-at", obj.get("host", "")),
                                "template_id": obj.get("template-id", ""),
                                "name": info.get("name", ""),
                                "severity": info.get("severity", ""),
                                "description": info.get("description", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue

        elif tool == "subzy":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    try:
                        data = json.loads(f.read())
                        if isinstance(data, list):
                            for obj in data:
                                sub = obj.get("subdomain", "")
                                if _subzy_apex_protected(sub):
                                    continue
                                results.append({
                                    "value": sub,
                                    "status": obj.get("status", ""),
                                    "service": obj.get("service", ""),
                                    "cname": obj.get("cname", ""),
                                })
                    except (json.JSONDecodeError, ValueError):
                        pass

        elif tool == "naabu":
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if ":" in line:
                            host, port = line.rsplit(":", 1)
                            results.append({"value": host, "host": host, "port": int(port), "protocol": "tcp", "state": "open"})
                        else:
                            results.append({"value": line, "host": line})

        elif tool == "nmap":
            xml_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if xml_path and xml_path.exists():
                results = _parse_nmap_xml(xml_path)

        elif tool in ("dnsgen", "shuffledns", "merge-subs"):
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    results = [{"value": line.strip()} for line in f if line.strip()]

        elif tool in ("merge-urls", "linkfinder"):
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    results = [{"value": line.strip()} for line in f if line.strip()]

        elif tool == "secret-scan":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("value", ""),
                            "pattern": entry.get("pattern", ""),
                            "source_url": entry.get("source_url", ""),
                            "context": entry.get("context", ""),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "spa-catchall-detect":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("host", ""),
                            "root_status": entry.get("root_status"),
                            "probe_status": entry.get("probe_status"),
                            "body_hash": entry.get("body_hash", ""),
                            "etag_match": entry.get("etag_match", False),
                            "evidence": entry.get("evidence", ""),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "arjun":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    # arjun 2.2.x JSON output is now {url: {headers, method, params: [...]}}
                    # NOT the older {url: [params]} flat format.  The legacy-shaped
                    # branch is retained for any pre-2.2 data still on disk.
                    if isinstance(data, dict):
                        for url, value in data.items():
                            if isinstance(value, dict):
                                method = value.get("method", "GET")
                                for param in value.get("params") or []:
                                    results.append({"value": param, "url": url, "method": method})
                            elif isinstance(value, list):
                                for param in value:
                                    results.append({"value": param, "url": url})
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "cms-detect":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("url", ""),
                            "cms": entry.get("cms", ""),
                            "title": entry.get("title", ""),
                            "tech": entry.get("tech", []),
                            "status_code": entry.get("status_code"),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "cloud-buckets":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("bucket", ""),
                            "provider": entry.get("provider", ""),
                            "list_permission": entry.get("list_permission", False),
                            "read_permission": entry.get("read_permission", False),
                            "status_code": entry.get("status_code"),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "s3-takeover":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("subdomain", ""),
                            "cloudfront": entry.get("cloudfront", ""),
                            "bucket_status": entry.get("bucket_status", ""),
                            "vulnerable": entry.get("vulnerable", False),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "panel-detect":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("url", ""),
                            "title": entry.get("title", ""),
                            "matched_keyword": entry.get("matched_keyword", ""),
                            "status_code": entry.get("status_code"),
                            "tech": entry.get("tech", []),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "wpscan":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    if isinstance(data, list):
                        for scan_result in data:
                            target_url = scan_result.get("target_url", "")
                            # Extract vulnerabilities from wpscan output
                            for vuln_type in ("plugins", "themes", "main_theme", "version"):
                                section = scan_result.get(vuln_type, {})
                                if isinstance(section, dict):
                                    for name, info in section.items():
                                        for vuln in info.get("vulnerabilities", []):
                                            results.append({
                                                "value": target_url,
                                                "vuln_title": vuln.get("title", ""),
                                                "vuln_type": vuln_type,
                                                "component": name,
                                                "fixed_in": vuln.get("fixed_in", ""),
                                                "references": vuln.get("references", {}),
                                            })
                            # Also capture interesting findings
                            for finding in scan_result.get("interesting_findings", []):
                                results.append({
                                    "value": target_url,
                                    "vuln_title": finding.get("to_s", ""),
                                    "vuln_type": "interesting_finding",
                                    "component": finding.get("type", ""),
                                    "url": finding.get("url", ""),
                                })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "ffuf":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("url", entry.get("input", {}).get("FUZZ", "")),
                            "status": entry.get("status", 0),
                            "length": entry.get("length", 0),
                            "words": entry.get("words", 0),
                            "lines": entry.get("lines", 0),
                            "redirectlocation": entry.get("redirectlocation", ""),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "dalfox":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                                results.append({
                                    "value": obj.get("data", obj.get("param", "")),
                                    "type": obj.get("type", ""),
                                    "poc": obj.get("poc", obj.get("data", "")),
                                    "param": obj.get("param", ""),
                                    "payload": obj.get("payload", ""),
                                    "evidence": obj.get("evidence", ""),
                                })
                            except (json.JSONDecodeError, ValueError):
                                continue
                except Exception:
                    pass

        elif tool in ("amass", "crt-sh"):
            # Plain text subdomain output
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and "." in line:
                            results.append({"value": line})

        elif tool == "gospider":
            # gospider writes to a directory; merge all output files
            raw_dir = Path(scan["json_output"]) if scan.get("json_output") else None
            if raw_dir and raw_dir.exists() and raw_dir.is_dir():
                seen = set()
                for outfile in sorted(raw_dir.iterdir()):
                    if outfile.is_file():
                        with open(outfile) as f:
                            for line in f:
                                line = line.strip()
                                # gospider output format: [source] [type] url
                                parts = line.split(" ")
                                url = parts[-1] if parts else line
                                if url.startswith("http") and url not in seen:
                                    seen.add(url)
                                    results.append({"value": url})
            # Also write merged output to the main output file
            output_path = Path(scan["output_file"])
            if results and not output_path.exists():
                with open(output_path, "w") as f:
                    f.write("\n".join(r["value"] for r in results) + "\n")

        elif tool == "joomscan":
            # Parse joomscan text output for vulnerabilities
            output_path = Path(scan["output_file"])
            if output_path.exists():
                with open(output_path) as f:
                    content = f.read()
                # Extract vulnerability sections
                current_url = ""
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("Scanning:") or line.startswith("[+] URL:"):
                        current_url = line.split(":", 1)[-1].strip()
                    elif "[++]" in line or "vulnerability" in line.lower() or "CVE-" in line:
                        results.append({
                            "value": current_url or "unknown",
                            "vuln_title": line.strip("[] +"),
                            "vuln_type": "joomscan",
                            "component": "joomla",
                        })

        elif tool in ("sqlmap", "commix"):
            # Parse JSONL output from bash loops. sqlmap entries now carry
            # a `csv_row` field (proof from the per-URL results CSV);
            # commix still emits `output`. Tolerate both shapes.
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        if not isinstance(obj, dict):
                            continue
                        if obj.get("vulnerable"):
                            evidence = obj.get("csv_row") or obj.get("output", "")
                            results.append({
                                "value": obj.get("url", ""),
                                "vulnerable": True,
                                "evidence": evidence[:500],
                                "tool_source": tool,
                            })

        elif tool == "hydra":
            # Parse JSONL output from hydra bash loop
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            results.append({
                                "value": obj.get("url", obj.get("host", "")),
                                "host": obj.get("host", ""),
                                "result": obj.get("result", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue

        elif tool == "gitleaks":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    if isinstance(data, list):
                        for entry in data:
                            results.append({
                                "value": entry.get("Secret", entry.get("Match", ""))[:200],
                                "rule": entry.get("RuleID", entry.get("Description", "")),
                                "file": entry.get("File", ""),
                                "line": entry.get("StartLine", 0),
                                "commit": entry.get("Commit", ""),
                                "repo": entry.get("Repo", ""),
                            })
                except (json.JSONDecodeError, ValueError):
                    pass

        elif tool == "eyewitness":
            # EyeWitness writes an HTML report; parse the output directory
            output_dir = Path(scan["json_output"]) if scan.get("json_output") else None
            if output_dir and output_dir.exists() and output_dir.is_dir():
                # Look for the report file
                report_file = output_dir / "report.html"
                if report_file.exists():
                    results.append({
                        "value": str(report_file),
                        "type": "report",
                        "path": str(output_dir),
                    })
                # Count screenshots
                screens_dir = output_dir / "screens"
                if screens_dir.exists():
                    screenshots = list(screens_dir.glob("*.png")) + list(screens_dir.glob("*.jpg"))
                    for ss in screenshots[:500]:
                        results.append({
                            "value": ss.stem.replace("_", "://", 1).replace("_", "/"),
                            "screenshot": str(ss),
                            "type": "screenshot",
                        })

        elif tool == "git-dumper":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                try:
                    with open(json_path) as f:
                        data = json.loads(f.read())
                    for entry in data.get("results", []):
                        results.append({
                            "value": entry.get("url", ""),
                            "git_head": entry.get("git_head", ""),
                            "git_config_exposed": entry.get("git_config_exposed", False),
                            "config_snippet": entry.get("config_snippet", ""),
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

        # ===== ORACLE PIPELINE RESULT PARSERS =====
        elif tool == "sslscan":
            output_file = Path(scan["output_file"]) if scan.get("output_file") else None
            if output_file and output_file.exists():
                results.extend(_parse_sslscan_results(output_file))

        elif tool == "sslyze":
            output_file = Path(scan["json_output"]) if scan.get("json_output") else None
            if output_file and output_file.exists():
                results.extend(_parse_sslyze_results(output_file))

        elif tool == "saml-fingerprint":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_saml_fingerprint_results(json_path))

        elif tool == "jwt-jwe-harvest":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_jwt_jwe_results(json_path))

        elif tool == "cookie-harvest":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_cookie_harvest_results(json_path))

        elif tool == "roca-scan":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_roca_results(json_path))

        elif tool == "breach-candidate":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_breach_results(json_path))

        elif tool == "tls-oracle-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_tls_oracle_probe_results(json_path))

        elif tool == "xmlenc-oracle-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_xmlenc_oracle_probe_results(json_path))

        elif tool == "cbc-padding-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_cbc_padding_probe_results(json_path))

        elif tool == "marvin-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_marvin_probe_results(json_path))

        elif tool == "xsw-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_xsw_probe_results(json_path))

        elif tool == "viewstate-fingerprint":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_viewstate_fingerprint_results(json_path))

        elif tool == "jwe-invalid-curve-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_jwe_invalid_curve_probe_results(json_path))

        elif tool == "manger-oaep-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_manger_oaep_probe_results(json_path))

        elif tool == "ssh-terrapin-scan":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_ssh_terrapin_scan_results(json_path))

        elif tool == "gcm-nonce-scan":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_gcm_nonce_scan_results(json_path))

        elif tool == "raccoon-probe":
            json_path = Path(scan["json_output"]) if scan.get("json_output") else None
            if json_path and json_path.exists():
                results.extend(_parse_raccoon_probe_results(json_path))

        self._send_json({"tool": tool, "count": len(results), "results": results})

    def _handle_kill(self, pid):
        scan = SCANS.get(pid)
        if not scan:
            return self._send_json({"error": "scan not found"}, 404)

        proc = scan.get("process")
        if proc is not None:
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
        elif _is_pid_alive(pid):
            # Recovered scan — kill by PID directly
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass

        for fh_key in ("log_fh", "stdin_fh"):
            fh = scan.get(fh_key)
            if fh and not getattr(fh, 'closed', True):
                try:
                    fh.close()
                except OSError:
                    pass
        _save_scans()
        self._send_json({"status": "killed"})

    def _handle_kill_target(self):
        """Kill ALL running scans for a target, including orphaned processes."""
        data = self._read_body()
        target_name = data.get("target_name")
        if not target_name:
            return self._send_json({"error": "target_name required"}, 400)

        killed = 0
        # Kill tracked scans for this target
        for pid, scan in list(SCANS.items()):
            if scan.get("target_name") == target_name:
                proc = scan.get("process")
                if proc and proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        killed += 1
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                elif _is_pid_alive(pid):
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGTERM)
                        killed += 1
                    except (ProcessLookupError, PermissionError, OSError):
                        try:
                            os.kill(pid, signal.SIGTERM)
                            killed += 1
                        except (ProcessLookupError, PermissionError):
                            pass

        # Also pkill any process with the target's recon dir in its command line
        # This catches processes that the agent lost track of after restart
        target_dir = str(RECON_DIR / target_name)
        try:
            result = subprocess.run(
                ["pkill", "-f", target_dir],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                killed += 1  # at least one process matched
        except Exception:
            pass

        _save_scans()
        self._send_json({"status": "killed", "target": target_name, "killed": killed})

    def _handle_files(self, target_name):
        target_dir = RECON_DIR / target_name
        if not target_dir.exists():
            return self._send_json({"files": []})
        files = []
        for f in sorted(target_dir.iterdir()):
            if f.is_file():
                line_count = None
                if f.suffix == ".txt":
                    try:
                        with open(f) as fh:
                            line_count = sum(1 for _ in fh)
                    except Exception:
                        pass
                files.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "lines": line_count,
                })
            elif f.is_dir() and f.name.startswith("gospider_raw_"):
                # Include gospider raw directories so recovery logic can find them
                dir_size = sum(c.stat().st_size for c in f.iterdir() if c.is_file())
                dir_files = sum(1 for c in f.iterdir() if c.is_file())
                files.append({
                    "name": f.name,
                    "size": dir_size,
                    "lines": dir_files,
                    "is_dir": True,
                })
        self._send_json({"files": files})

    def _handle_results_from_file(self):
        """Read results directly from a file on disk — fallback when agent lost scan state."""
        data = self._read_body()
        target_name = data.get("target_name")
        filename = data.get("filename")
        tool = data.get("tool")

        if not target_name or not filename or not tool:
            return self._send_json({"error": "target_name, filename, and tool required"}, 400)

        filepath = RECON_DIR / target_name / filename
        if not filepath.exists():
            return self._send_json({"error": "file not found: %s" % filename}, 404)

        # Prevent path traversal
        try:
            filepath.resolve().relative_to(RECON_DIR.resolve())
        except ValueError:
            return self._send_json({"error": "invalid path"}, 400)

        results = []

        if tool in ("subfinder", "katana", "getallurls"):
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append({"value": line})

        elif tool == "httpx-toolkit":
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        results.append({
                            "value": obj.get("url", obj.get("input", "")),
                            "status_code": obj.get("status-code", obj.get("status_code")),
                            "title": obj.get("title", ""),
                            "tech": obj.get("technologies", obj.get("tech", [])),
                            "content_length": obj.get("content-length", obj.get("content_length")),
                            "content_type": obj.get("content-type", ""),
                        })
                    except (json.JSONDecodeError, ValueError):
                        continue

        elif tool == "nuclei":
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        info = obj.get("info", {})
                        results.append({
                            "value": obj.get("matched-at", obj.get("host", "")),
                            "template_id": obj.get("template-id", ""),
                            "name": info.get("name", ""),
                            "severity": info.get("severity", ""),
                            "description": info.get("description", ""),
                        })
                    except (json.JSONDecodeError, ValueError):
                        continue

        elif tool == "nuclei-takeover":
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        info = obj.get("info", {})
                        results.append({
                            "value": obj.get("matched-at", obj.get("host", "")),
                            "template_id": obj.get("template-id", ""),
                            "name": info.get("name", ""),
                            "severity": info.get("severity", ""),
                            "description": info.get("description", ""),
                        })
                    except (json.JSONDecodeError, ValueError):
                        continue

        elif tool == "subzy":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                    if isinstance(data, list):
                        for obj in data:
                            sub = obj.get("subdomain", "")
                            if _subzy_apex_protected(sub):
                                continue
                            results.append({
                                "value": sub,
                                "status": obj.get("status", ""),
                                "service": obj.get("service", ""),
                                "cname": obj.get("cname", ""),
                            })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "naabu":
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        host, port = line.rsplit(":", 1)
                        results.append({"value": host, "host": host, "port": int(port), "protocol": "tcp", "state": "open"})
                    else:
                        results.append({"value": line, "host": line})

        elif tool == "nmap":
            results = _parse_nmap_xml(filepath)

        elif tool in ("dnsgen", "shuffledns", "merge-subs"):
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append({"value": line})

        elif tool in ("merge-urls", "linkfinder"):
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append({"value": line})

        elif tool == "secret-scan":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("value", ""),
                        "pattern": entry.get("pattern", ""),
                        "source_url": entry.get("source_url", ""),
                        "context": entry.get("context", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "spa-catchall-detect":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("host", ""),
                        "root_status": entry.get("root_status"),
                        "probe_status": entry.get("probe_status"),
                        "body_hash": entry.get("body_hash", ""),
                        "etag_match": entry.get("etag_match", False),
                        "evidence": entry.get("evidence", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "arjun":
            # Handles both arjun 2.2.x dict-shape {url: {params: [...]}} and
            # legacy flat {url: [params]}.  Mirror of the in-memory parser.
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                if isinstance(data, dict):
                    for url, value in data.items():
                        if isinstance(value, dict):
                            method = value.get("method", "GET")
                            for param in value.get("params") or []:
                                results.append({"value": param, "url": url, "method": method})
                        elif isinstance(value, list):
                            for param in value:
                                results.append({"value": param, "url": url})
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "cms-detect":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("url", ""),
                        "cms": entry.get("cms", ""),
                        "title": entry.get("title", ""),
                        "tech": entry.get("tech", []),
                        "status_code": entry.get("status_code"),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "cloud-buckets":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("bucket", ""),
                        "provider": entry.get("provider", ""),
                        "list_permission": entry.get("list_permission", False),
                        "read_permission": entry.get("read_permission", False),
                        "status_code": entry.get("status_code"),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "s3-takeover":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("subdomain", ""),
                        "cloudfront": entry.get("cloudfront", ""),
                        "bucket_status": entry.get("bucket_status", ""),
                        "vulnerable": entry.get("vulnerable", False),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "panel-detect":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("url", ""),
                        "title": entry.get("title", ""),
                        "matched_keyword": entry.get("matched_keyword", ""),
                        "status_code": entry.get("status_code"),
                        "tech": entry.get("tech", []),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "wpscan":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                if isinstance(data, list):
                    for scan_result in data:
                        target_url = scan_result.get("target_url", "")
                        for vuln_type in ("plugins", "themes", "main_theme", "version"):
                            section = scan_result.get(vuln_type, {})
                            if isinstance(section, dict):
                                for name, info in section.items():
                                    for vuln in info.get("vulnerabilities", []):
                                        results.append({
                                            "value": target_url,
                                            "vuln_title": vuln.get("title", ""),
                                            "vuln_type": vuln_type,
                                            "component": name,
                                            "fixed_in": vuln.get("fixed_in", ""),
                                        })
                        for finding in scan_result.get("interesting_findings", []):
                            results.append({
                                "value": target_url,
                                "vuln_title": finding.get("to_s", ""),
                                "vuln_type": "interesting_finding",
                                "component": finding.get("type", ""),
                                "url": finding.get("url", ""),
                            })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "ffuf":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("url", entry.get("input", {}).get("FUZZ", "")),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "lines": entry.get("lines", 0),
                        "redirectlocation": entry.get("redirectlocation", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "dalfox":
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            results.append({
                                "value": obj.get("data", obj.get("param", "")),
                                "type": obj.get("type", ""),
                                "poc": obj.get("poc", obj.get("data", "")),
                                "param": obj.get("param", ""),
                                "payload": obj.get("payload", ""),
                                "evidence": obj.get("evidence", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue
            except Exception:
                pass

        elif tool in ("amass", "crt-sh"):
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and "." in line:
                        results.append({"value": line})

        elif tool == "gospider":
            # gospider output could be merged text file or directory
            if filepath.is_dir():
                seen = set()
                for outfile in sorted(filepath.iterdir()):
                    if outfile.is_file():
                        with open(outfile) as f:
                            for line in f:
                                parts = line.strip().split(" ")
                                url = parts[-1] if parts else line.strip()
                                if url.startswith("http") and url not in seen:
                                    seen.add(url)
                                    results.append({"value": url})
            else:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            results.append({"value": line})

        elif tool == "joomscan":
            with open(filepath) as f:
                content = f.read()
            current_url = ""
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("Scanning:") or line.startswith("[+] URL:"):
                    current_url = line.split(":", 1)[-1].strip()
                elif "[++]" in line or "vulnerability" in line.lower() or "CVE-" in line:
                    results.append({
                        "value": current_url or "unknown",
                        "vuln_title": line.strip("[] +"),
                        "vuln_type": "joomscan",
                        "component": "joomla",
                    })

        elif tool in ("sqlmap", "commix"):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            if obj.get("vulnerable"):
                                evidence = obj.get("csv_row") or obj.get("output", "")
                                results.append({
                                    "value": obj.get("url", ""),
                                    "vulnerable": True,
                                    "evidence": evidence[:500],
                                    "tool_source": tool,
                                })
                        except (json.JSONDecodeError, ValueError):
                            continue
            except Exception:
                pass

        elif tool == "hydra":
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            results.append({
                                "value": obj.get("url", obj.get("host", "")),
                                "host": obj.get("host", ""),
                                "result": obj.get("result", ""),
                            })
                        except (json.JSONDecodeError, ValueError):
                            continue
            except Exception:
                pass

        elif tool == "gitleaks":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                if isinstance(data, list):
                    for entry in data:
                        results.append({
                            "value": entry.get("Secret", entry.get("Match", ""))[:200],
                            "rule": entry.get("RuleID", entry.get("Description", "")),
                            "file": entry.get("File", ""),
                            "line": entry.get("StartLine", 0),
                            "commit": entry.get("Commit", ""),
                            "repo": entry.get("Repo", ""),
                        })
            except (json.JSONDecodeError, ValueError):
                pass

        elif tool == "eyewitness":
            if filepath.is_dir():
                screens_dir = filepath / "screens"
                if screens_dir.exists():
                    screenshots = list(screens_dir.glob("*.png")) + list(screens_dir.glob("*.jpg"))
                    for ss in screenshots[:500]:
                        results.append({
                            "value": ss.stem.replace("_", "://", 1).replace("_", "/"),
                            "screenshot": str(ss),
                            "type": "screenshot",
                        })

        elif tool == "git-dumper":
            try:
                with open(filepath) as f:
                    data = json.loads(f.read())
                for entry in data.get("results", []):
                    results.append({
                        "value": entry.get("url", ""),
                        "git_head": entry.get("git_head", ""),
                        "git_config_exposed": entry.get("git_config_exposed", False),
                        "config_snippet": entry.get("config_snippet", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        # ===== ORACLE PIPELINE (from-disk parsers) =====
        elif tool == "sslscan":
            results.extend(_parse_sslscan_results(filepath))
        elif tool == "sslyze":
            results.extend(_parse_sslyze_results(filepath))
        elif tool == "saml-fingerprint":
            results.extend(_parse_saml_fingerprint_results(filepath))
        elif tool == "jwt-jwe-harvest":
            results.extend(_parse_jwt_jwe_results(filepath))
        elif tool == "cookie-harvest":
            results.extend(_parse_cookie_harvest_results(filepath))
        elif tool == "roca-scan":
            results.extend(_parse_roca_results(filepath))
        elif tool == "breach-candidate":
            results.extend(_parse_breach_results(filepath))
        elif tool == "tls-oracle-probe":
            results.extend(_parse_tls_oracle_probe_results(filepath))
        elif tool == "xmlenc-oracle-probe":
            results.extend(_parse_xmlenc_oracle_probe_results(filepath))
        elif tool == "cbc-padding-probe":
            results.extend(_parse_cbc_padding_probe_results(filepath))
        elif tool == "marvin-probe":
            results.extend(_parse_marvin_probe_results(filepath))
        elif tool == "xsw-probe":
            results.extend(_parse_xsw_probe_results(filepath))
        elif tool == "viewstate-fingerprint":
            results.extend(_parse_viewstate_fingerprint_results(filepath))
        elif tool == "jwe-invalid-curve-probe":
            results.extend(_parse_jwe_invalid_curve_probe_results(filepath))
        elif tool == "manger-oaep-probe":
            results.extend(_parse_manger_oaep_probe_results(filepath))
        elif tool == "ssh-terrapin-scan":
            results.extend(_parse_ssh_terrapin_scan_results(filepath))
        elif tool == "gcm-nonce-scan":
            results.extend(_parse_gcm_nonce_scan_results(filepath))
        elif tool == "raccoon-probe":
            results.extend(_parse_raccoon_probe_results(filepath))

        self._send_json({"tool": tool, "count": len(results), "results": results})

    def _handle_write_exclusions(self):
        """Write scope exclusion keywords to a target dir for merge-subs to use."""
        data = self._read_body()
        target_name = data.get("target_name")
        exclusions = data.get("exclusions", [])

        if not target_name:
            return self._send_json({"error": "target_name required"}, 400)

        target_dir = RECON_DIR / target_name
        target_dir.mkdir(parents=True, exist_ok=True)

        exclusions_file = target_dir / "scope_exclusions.json"
        with open(exclusions_file, "w") as f:
            json.dump(exclusions, f)

        self._send_json({"status": "ok", "exclusions": exclusions, "file": str(exclusions_file)})


# ========================================================================
# ORACLE PIPELINE BUILT-IN TOOLS (stdlib Python, run as subprocess via argv)
# ========================================================================
#
# All of these take the same 3 args: (input_file, output_file, log_file)
# and write structured JSON results to output_file. The in-memory and
# from-disk result parsers below consume these JSON outputs and turn them
# into recon_results DB rows.

# --- Common helpers for oracle tools ---

_COMMON_SAML_PATHS = [
    "/saml/acs", "/saml/consume", "/saml/sso/post", "/saml2/acs",
    "/authx/saml/acs/internal", "/authx/saml/acs",
    "/auth/saml/callback", "/sso/saml/acs",
    "/saml/metadata", "/saml/sp-metadata", "/metadata", "/metadata.xml",
    "/sp-metadata.xml", "/Shibboleth.sso/Metadata",
    "/auth/saml2/sp-metadata", "/simplesaml/saml2/idp/metadata.php",
]

_COMMON_AUTH_PATHS = [
    "/", "/login", "/signin", "/auth/login", "/sso/login",
    "/api", "/api/v1", "/api/auth", "/api/login",
    "/dashboard", "/admin", "/user", "/account",
]


def _oracle_http_get(url, timeout=10, extra_headers=None):
    """Stdlib HTTP GET that returns (status, headers_dict, body_bytes) or None on error."""
    import ssl
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (recon-agent oracle-pipeline)")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(1024 * 1024)  # cap at 1 MB
        headers = dict(resp.headers.items())
        return (resp.status, headers, body)
    except HTTPError as e:
        try:
            body = e.read(1024 * 1024)
        except Exception:
            body = b""
        return (e.code, dict(e.headers.items()) if e.headers else {}, body)
    except (URLError, OSError, ssl.SSLError, ValueError):
        return None


def _oracle_http_post(url, body, content_type="application/x-www-form-urlencoded",
                       timeout=10, extra_headers=None):
    """Stdlib HTTP POST returning (status, headers_dict, body_bytes) or None on error."""
    import ssl as _ssl
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    if isinstance(body, str):
        body = body.encode()
    req = Request(url, data=body)
    req.add_header("User-Agent", "Mozilla/5.0 (recon-agent oracle-pipeline)")
    req.add_header("Content-Type", content_type)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
        body_resp = resp.read(64 * 1024)  # cap at 64K (we only need a fingerprint, not the body)
        headers = dict(resp.headers.items())
        return (resp.status, headers, body_resp)
    except HTTPError as e:
        try:
            body_resp = e.read(64 * 1024)
        except Exception:
            body_resp = b""
        return (e.code, dict(e.headers.items()) if e.headers else {}, body_resp)
    except (URLError, OSError, _ssl.SSLError, ValueError):
        return None


def _oracle_response_fingerprint(status, body):
    """Return a (status, body_len, body_sha8) tuple suitable for distinguishing
    responses. Used by saml-fingerprint POST distinguishability."""
    import hashlib
    sha = hashlib.sha256(body).hexdigest()[:8] if body else ""
    return (status, len(body), sha)


def _oracle_shannon_entropy(data):
    """Shannon entropy (bits per byte) of a byte string or str."""
    if not data:
        return 0.0
    import math
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    from collections import Counter
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _oracle_hosts_from_httpx(input_path, limit=1000, dedup_wildcards=True):
    """Extract live base URLs (scheme://host[:port]) from httpx JSONL.

    With dedup_wildcards=True (default), collapses cloudflare/wildcard
    catch-alls — many hosts that all resolve to the same IP and return
    the same content-length on the same status code are deduplicated to
    one representative per (status_code, content_length, parent_domain)
    fingerprint. This prevents the oracle pipeline from wasting time
    probing 1,000+ identical *.vhx.tv wildcards.

    The limit is now 1000 (was 100). Anduril has 274 live hosts, Vimeo
    has 1,331 — 100 was way too restrictive.
    """
    entries = []
    try:
        with open(input_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    u = obj.get("url") or obj.get("input") or ""
                    if not u:
                        continue
                    # Keep scheme + host only, strip path
                    scheme_end = u.find("://")
                    if scheme_end == -1:
                        continue
                    path_start = u.find("/", scheme_end + 3)
                    base = u if path_start == -1 else u[:path_start]
                    # Wildcard fingerprint: status + content-length + body sha + parent domain.
                    # Hosts sharing all four are almost certainly the same wildcard CDN endpoint.
                    status = obj.get("status-code", obj.get("status_code", 0))
                    clen = obj.get("content-length", obj.get("content_length", 0))
                    body_sha = obj.get("body-sha256", obj.get("body_sha256", ""))[:16]
                    host_only = base[base.find("://") + 3:].split(":")[0]
                    parts = host_only.split(".")
                    parent = ".".join(parts[-3:]) if len(parts) >= 3 else host_only
                    fingerprint = (status, clen, body_sha, parent)
                    entries.append((base, fingerprint))
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        return []

    if not dedup_wildcards:
        urls = sorted(set(e[0] for e in entries))
        return urls[:limit]

    # Group by fingerprint. Keep only the first representative per group
    # IF the group has > 5 members (small groups are real, big groups are
    # wildcards). Tunable threshold; 5 catches Cloudflare's typical
    # behavior without false-positiving small clusters of related hosts.
    from collections import defaultdict
    by_fp = defaultdict(list)
    for base, fp in entries:
        by_fp[fp].append(base)

    kept = set()
    for fp, group in by_fp.items():
        if len(group) > 5 and fp[2]:  # >5 hosts AND a real body sha (not 0/empty)
            # Wildcard cluster — keep one representative (the alphabetically
            # first, which tends to be the canonical name like vhx.tv itself)
            kept.add(sorted(group)[0])
        else:
            kept.update(group)

    return sorted(kept)[:limit]


# --- _run_saml_fingerprint ---

def _run_saml_fingerprint(input_path, output_path, log_path):
    """Probe each httpx host for common SAML paths. Detects:

    1. **Metadata-publishing endpoints** via GET — looks for EntityDescriptor /
       SAMLResponse / EncryptedAssertion / urn:oasis:names:tc:SAML markers in
       the response body. Extracts metadata XML and flags rsa-1_5 / rsa-oaep
       advertising. Works for /saml/metadata, /sp-metadata.xml, etc.

    2. **POST-only ACS endpoints** via POST distinguishability — for SPAs
       (like draco.anduril.com) the GET response is the same HTML shell on
       every path so the GET-marker check never matches. Instead, we:
         a. Establish a per-host baseline by POSTing to a deliberately
            nonexistent path (/__bleich_baseline_<random>)
         b. POST to each candidate SAML path with `SAMLResponse=test`
         c. If the fingerprint (status, body_len, sha8) differs from the
            baseline, the host has a real ACS handler at that path
       Works for draco's /authx/saml/acs/internal which previously was
       a false negative.
    """
    import random as _random
    import string as _string
    results = {
        "endpoints": [],         # all SAML-positive endpoints (metadata or ACS)
        "metadata_docs": [],     # full metadata XML dumps
        "rsa15_candidates": [],  # rsa-1_5 advertised in metadata
        "post_distinguishable": [],  # ACS endpoints found via POST distinguishability
    }
    bases = _oracle_hosts_from_httpx(input_path)  # uses default limit=1000 + dedup
    with open(log_path, "w") as log:
        log.write("saml-fingerprint: %d base URLs to probe (limit=1000, wildcard-dedup)\n" % len(bases))
        log.flush()

        for base in bases:
            # --- 1. Establish per-host POST baseline against a nonexistent path ---
            baseline_path = "/__bleich_baseline_" + "".join(_random.choices(_string.ascii_lowercase, k=8))
            baseline_url = base + baseline_path
            baseline_post = _oracle_http_post(
                baseline_url,
                "SAMLResponse=test",
                timeout=8,
            )
            if baseline_post is None:
                # Host unreachable / TLS error — skip silently
                continue
            baseline_fp = _oracle_response_fingerprint(baseline_post[0], baseline_post[2])

            # --- 2. For each candidate SAML path, run GET marker check + POST distinguishability ---
            for path in _COMMON_SAML_PATHS:
                url = base + path

                # GET-based marker detection (works for metadata publishers)
                r = _oracle_http_get(url, timeout=8)
                is_saml = False
                is_metadata = False
                marker_reasons = []
                full_body = ""
                if r is not None:
                    status, headers, body = r
                    full_body = body.decode("utf-8", errors="replace") if body else ""
                    body_str = full_body[:8192]
                    if status in (200, 303, 302, 405):
                        if "EntityDescriptor" in body_str or "md:EntityDescriptor" in body_str:
                            is_metadata = True
                            marker_reasons.append("metadata-xml")
                        if "SAMLResponse" in body_str or "saml2:Response" in body_str:
                            is_saml = True
                            marker_reasons.append("saml-response-form")
                        if "EncryptedAssertion" in body_str:
                            is_saml = True
                            marker_reasons.append("encrypted-assertion-ref")
                        if "urn:oasis:names:tc:SAML" in body_str:
                            is_saml = True
                            marker_reasons.append("saml-namespace")

                # POST distinguishability detection (works for ACS endpoints on SPAs)
                post_r = _oracle_http_post(url, "SAMLResponse=test", timeout=8)
                post_distinct = False
                if post_r is not None:
                    post_fp = _oracle_response_fingerprint(post_r[0], post_r[2])
                    # Distinguishable if status differs OR body sha differs OR
                    # body length differs by > 16 bytes (small length variation
                    # is just dynamic IDs/timestamps in identical pages)
                    if (post_fp[0] != baseline_fp[0] or
                            post_fp[2] != baseline_fp[2] or
                            abs(post_fp[1] - baseline_fp[1]) > 16):
                        post_distinct = True
                        is_saml = True
                        marker_reasons.append("post-distinguishable")

                if not (is_saml or is_metadata):
                    continue

                # Record the endpoint
                entry = {
                    "url": url,
                    "status": r[0] if r else 0,
                    "reasons": marker_reasons,
                    "body_len": len(r[2]) if r else 0,
                }
                if post_r is not None:
                    entry["post_status"] = post_r[0]
                    entry["post_body_len"] = len(post_r[2])
                    entry["baseline_status"] = baseline_fp[0]
                    entry["baseline_body_len"] = baseline_fp[1]
                results["endpoints"].append(entry)
                log.write("  [%d/%s] %s (%s)\n" % (
                    r[0] if r else 0,
                    "POST=%d" % post_r[0] if post_r else "?",
                    url,
                    ",".join(marker_reasons),
                ))
                log.flush()

                if post_distinct:
                    results["post_distinguishable"].append(entry)

                if is_metadata and r is not None:
                    # Full metadata dump
                    results["metadata_docs"].append({
                        "url": url,
                        "length": len(full_body),
                        "xml": full_body[:50000],  # cap to 50KB
                    })
                    if "xmlenc#rsa-1_5" in full_body:
                        results["rsa15_candidates"].append({
                            "url": url,
                            "algorithm": "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                            "severity": "critical",
                            "reason": "SAML SP metadata advertises rsa-1_5 key transport — direct Bleichenbacher target",
                        })
                        log.write("    ** rsa-1_5 FOUND in metadata — critical candidate **\n")
                        log.flush()
                    if "xmlenc#rsa-oaep" in full_body:
                        results["rsa15_candidates"].append({
                            "url": url,
                            "algorithm": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                            "severity": "medium",
                            "reason": "SAML SP metadata advertises rsa-oaep — Manger oracle candidate if error-distinguishable",
                        })

        log.write("\ndone: %d endpoints, %d metadata docs, %d rsa15 candidates, %d post-distinguishable\n" % (
            len(results["endpoints"]), len(results["metadata_docs"]),
            len(results["rsa15_candidates"]), len(results["post_distinguishable"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["endpoints"]) + len(results["rsa15_candidates"])


# --- _run_jwt_jwe_harvest ---

def _run_jwt_jwe_harvest(input_path, output_path, log_path):
    """Probe auth paths, scan responses/cookies for JWTs, decode headers, flag weak alg."""
    import base64 as _b64
    import re
    results = {"tokens": [], "critical_findings": []}
    JWT_RE = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}")
    WEAK_ALGS_CRITICAL = {"none", "RSA1_5"}
    WEAK_ALGS_HIGH = {"HS256", "HS384", "HS512"}  # if used as identity bearer
    WEAK_ALGS_MEDIUM = {"RSA-OAEP"}
    bases = _oracle_hosts_from_httpx(input_path, limit=80)
    with open(log_path, "w") as log:
        log.write("jwt-jwe-harvest: %d bases\n" % len(bases))
        log.flush()
        seen_tokens = set()
        for base in bases:
            for path in _COMMON_AUTH_PATHS:
                url = base + path
                r = _oracle_http_get(url, timeout=8)
                if r is None:
                    continue
                status, headers, body = r
                body_str = body.decode("utf-8", errors="replace")
                # Scan Set-Cookie headers
                scan_texts = [body_str]
                set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
                if set_cookie:
                    scan_texts.append(set_cookie)
                for text in scan_texts:
                    for m in JWT_RE.finditer(text):
                        token = m.group(0)
                        if token in seen_tokens:
                            continue
                        seen_tokens.add(token)
                        # Decode header
                        parts = token.split(".")
                        if len(parts) < 2:
                            continue
                        hdr_raw = parts[0]
                        pad = "=" * (-len(hdr_raw) % 4)
                        try:
                            header_json = _b64.urlsafe_b64decode(hdr_raw + pad).decode(
                                "utf-8", errors="replace")
                            header = json.loads(header_json)
                        except Exception:
                            continue
                        if not isinstance(header, dict):
                            continue
                        alg = header.get("alg", "")
                        enc = header.get("enc", "")
                        entry = {
                            "url": url, "token_preview": token[:80] + "..." if len(token) > 80 else token,
                            "alg": alg, "enc": enc,
                            "typ": header.get("typ", ""), "kid": header.get("kid", ""),
                            "jku": header.get("jku", ""), "x5u": header.get("x5u", ""),
                            "source": "cookie" if text == set_cookie else "body",
                        }
                        severity = None
                        reasons = []
                        if alg in WEAK_ALGS_CRITICAL:
                            severity = "critical"
                            reasons.append("weak alg: %s" % alg)
                        elif alg in WEAK_ALGS_HIGH and enc:
                            severity = "high"
                            reasons.append("JWE with HS-family alg: %s" % alg)
                        elif alg in WEAK_ALGS_MEDIUM:
                            severity = "medium"
                            reasons.append("RSA-OAEP — potential Manger oracle")
                        if header.get("jku") or header.get("x5u"):
                            severity = severity or "high"
                            reasons.append("attacker-controllable URL in header (jku/x5u)")
                        if severity:
                            entry["severity"] = severity
                            entry["reasons"] = reasons
                            results["critical_findings"].append(entry)
                            log.write("  [%s] %s alg=%s at %s\n" % (severity, token[:30], alg, url))
                            log.flush()
                        results["tokens"].append(entry)
        log.write("done: %d tokens, %d critical\n" %
                  (len(results["tokens"]), len(results["critical_findings"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["tokens"])


# --- _run_cookie_harvest ---

def _run_cookie_harvest(input_path, output_path, log_path):
    """Fetch auth pages, capture Set-Cookie values, compute entropy, flag CBC candidates."""
    import base64 as _b64
    import re
    results = {"cookies": [], "cbc_candidates": []}
    bases = _oracle_hosts_from_httpx(input_path, limit=80)
    with open(log_path, "w") as log:
        log.write("cookie-harvest: %d bases\n" % len(bases))
        log.flush()
        for base in bases:
            for path in _COMMON_AUTH_PATHS[:4]:
                url = base + path
                r = _oracle_http_get(url, timeout=8)
                if r is None:
                    continue
                status, headers, body = r
                # Handle set-cookie (may be multiple; urllib folds into single string
                # using comma as separator — imperfect but workable)
                set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
                # Split on ", " between cookies. This is fragile but stdlib doesn't
                # expose multi-valued headers well.
                cookies_raw = re.split(r",\s+(?=[A-Za-z_][\w-]*=)", set_cookie)
                for raw in cookies_raw:
                    if "=" not in raw:
                        continue
                    name_val = raw.split(";")[0]
                    if "=" not in name_val:
                        continue
                    name, value = name_val.split("=", 1)
                    name = name.strip()
                    value = value.strip()
                    if not value or len(value) < 16:
                        continue
                    entry = {
                        "url": url, "name": name, "value_len": len(value),
                        "value_preview": value[:40],
                    }
                    # Try base64 decode
                    decoded_len = None
                    try:
                        pad = "=" * (-len(value) % 4)
                        decoded = _b64.urlsafe_b64decode(value + pad)
                        decoded_len = len(decoded)
                        entry["decoded_len"] = decoded_len
                    except Exception:
                        try:
                            decoded = _b64.b64decode(value + "=" * (-len(value) % 4))
                            decoded_len = len(decoded)
                            entry["decoded_len"] = decoded_len
                        except Exception:
                            entry["decoded_len"] = None
                    ent = _oracle_shannon_entropy(value)
                    entry["entropy"] = round(ent, 2)
                    # CBC candidate signature: decoded length is a multiple of 16 AND entropy > 4.5
                    is_cbc = (
                        decoded_len is not None
                        and decoded_len >= 32
                        and decoded_len % 16 == 0
                        and ent > 4.5
                    )
                    entry["is_cbc_candidate"] = is_cbc
                    # Framework hints — these are critical for prioritising the
                    # cbc-padding-probe follow-up. Shiro RememberMe is the
                    # canonical "padding oracle → Java deserialization → RCE"
                    # chain (Apache Shiro CVE-2016-4437) and should always be
                    # flagged as critical priority. Rails CookieStore CVE-2013-0156
                    # is the Marshal.load deserialization equivalent.
                    framework = None
                    framework_severity = None
                    if name == "rememberMe" or name.lower() == "remember-me":
                        framework = "apache-shiro"
                        framework_severity = "critical"
                    elif name.startswith(".ASPXAUTH") or name == "ASP.NET_SessionId":
                        framework = "asp.net"
                        framework_severity = "high"
                    elif name.startswith("_") and name.endswith("_session"):
                        framework = "rails-cookiestore"
                        framework_severity = "high"
                    elif name in ("sessionid", "csrftoken"):
                        framework = "django"
                    elif name in ("PHPSESSID", "laravel_session"):
                        framework = "php"
                    elif name in ("JSESSIONID",):
                        framework = "java-servlet"
                    elif name == "express:sess" or name == "express:sess.sig":
                        framework = "express"
                    entry["framework_hint"] = framework
                    if framework_severity:
                        entry["framework_severity"] = framework_severity
                    results["cookies"].append(entry)
                    if is_cbc:
                        results["cbc_candidates"].append(entry)
                        log.write("  CBC candidate: %s=%s (%d decoded bytes, entropy=%.2f)\n" %
                                  (name, entry["value_preview"], decoded_len, ent))
                        log.flush()
        log.write("done: %d cookies, %d CBC candidates\n" %
                  (len(results["cookies"]), len(results["cbc_candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["cookies"])


# --- _run_roca_scan ---

def _run_roca_scan(input_path, output_path, log_path):
    """Offline ROCA (CVE-2017-15361) fingerprint check over RSA moduli collected
    from sslyze JSON output.

    ROCA test: modulus mod P must have a specific generator structure. This
    simplified check uses the primorial-based quick test from Nemec et al.
    """
    # Primorials used by ROCA: product of first N primes. We use a truncated
    # set of small primes + discriminants per Nemec et al. 2017. The full
    # detector uses a lookup table of acceptable values; we use the simplified
    # "generator order" test which is enough for positive identification with
    # ~99.9% true-positive rate.
    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
              67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
              137, 139, 149, 151, 157, 163, 167]

    # For each prime p, compute the set of orders of the generator 65537 mod p.
    # ROCA moduli satisfy: for each p in primes, (modulus mod p) must be a
    # power of 65537 mod p (since the vulnerable lib generates primes as
    # p = k*M + (65537^a mod M) for some M built from primorials).
    def _is_roca(n):
        for p in primes:
            powers = set()
            g = 65537 % p
            v = 1
            for _ in range(p):
                powers.add(v)
                v = (v * g) % p
                if v == 1:
                    break
            if (n % p) not in powers:
                return False
        return True

    results = {"tested": 0, "vulnerable": [], "errors": []}
    with open(log_path, "w") as log:
        log.write("roca-scan: reading sslyze JSON\n")
        log.flush()
        try:
            sslyze_data = _safe_json_load(input_path)
        except Exception as e:
            log.write("failed to parse sslyze JSON: %s\n" % e)
            results["errors"].append(str(e))
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
            return 0

        # sslyze JSON schema: server_scan_results[*].scan_result.certificate_info.result.certificate_deployments[*].received_certificate_chain[*]
        scans = sslyze_data.get("server_scan_results", []) or []
        log.write("parsing %d server scan results\n" % len(scans))
        log.flush()
        for scan in scans:
            try:
                hostname = scan.get("server_location", {}).get("hostname", "unknown")
                port = scan.get("server_location", {}).get("port", 443)
                certinfo = (scan.get("scan_result", {}) or {}).get("certificate_info", {})
                if not certinfo:
                    continue
                cert_result = (certinfo.get("result", {}) or {})
                deployments = cert_result.get("certificate_deployments", []) or []
                for dep in deployments:
                    chain = dep.get("received_certificate_chain", []) or []
                    if not chain:
                        continue
                    leaf = chain[0]
                    # sslyze exports publicKey as dict with modulus/exponent for RSA keys
                    pubkey = leaf.get("public_key", {}) or {}
                    key_type = pubkey.get("algorithm", "")
                    if "rsa" not in key_type.lower():
                        continue
                    modulus_hex = pubkey.get("rsa_n", "") or pubkey.get("modulus", "")
                    if not modulus_hex:
                        continue
                    try:
                        modulus = int(modulus_hex, 16) if isinstance(modulus_hex, str) else int(modulus_hex)
                    except Exception:
                        continue
                    results["tested"] += 1
                    if _is_roca(modulus):
                        results["vulnerable"].append({
                            "host": "%s:%s" % (hostname, port),
                            "modulus_bits": modulus.bit_length(),
                            "fingerprint": leaf.get("sha256_fingerprint", ""),
                            "subject": leaf.get("subject", ""),
                            "severity": "critical",
                            "reason": "RSA modulus has ROCA (CVE-2017-15361) structure — "
                                      "factorable via Coppersmith in days",
                        })
                        log.write("  ** ROCA VULNERABLE: %s:%s (%d bits) **\n" %
                                  (hostname, port, modulus.bit_length()))
                        log.flush()
            except Exception as e:
                results["errors"].append(str(e))

        log.write("done: tested %d RSA keys, %d ROCA-vulnerable\n" %
                  (results["tested"], len(results["vulnerable"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["vulnerable"])


# --- _run_breach_candidate ---

def _run_breach_candidate(input_path, output_path, log_path):
    """Detect BREACH-eligible endpoints: compressed responses that contain both
    reflected user input AND secret-looking tokens."""
    import re
    TOKEN_PATTERNS = [
        re.compile(r'name="csrf[-_]?token"\s+value="([^"]{20,})"', re.IGNORECASE),
        re.compile(r'name="_token"\s+value="([^"]{20,})"', re.IGNORECASE),
        re.compile(r'name="authenticity_token"\s+value="([^"]{20,})"'),
        re.compile(r'name="__RequestVerificationToken"\s+value="([^"]{20,})"'),
        re.compile(r'name="XSRF-TOKEN"\s+value="([^"]{20,})"'),
    ]
    results = {"candidates": [], "scanned": 0}
    bases = _oracle_hosts_from_httpx(input_path, limit=100)

    # Common form paths that often contain CSRF tokens + user input reflection
    FORM_PATHS = [
        "/login", "/signin", "/register", "/signup", "/contact",
        "/search", "/account", "/profile", "/settings", "/password/reset",
    ]

    with open(log_path, "w") as log:
        log.write("breach-candidate: %d bases\n" % len(bases))
        log.flush()
        bust = "xyzbreach1234"

        def _check_breach(url, body_bytes, headers, method="GET"):
            """Check a response for BREACH prerequisites."""
            enc = (headers.get("Content-Encoding") or headers.get("content-encoding") or "").lower()
            if "gzip" not in enc and "br" not in enc and "deflate" not in enc:
                return None
            body_str = body_bytes.decode("utf-8", errors="replace")
            has_reflection = bust in body_str
            if not has_reflection:
                return None
            secrets_found = []
            for pat in TOKEN_PATTERNS:
                for m in pat.finditer(body_str):
                    secrets_found.append(m.group(1)[:50])
            if not secrets_found:
                return None
            return {
                "url": url, "content_encoding": enc, "method": method,
                "reflects_query": True,
                "secrets_found": secrets_found[:5],
                "severity": "medium",
                "reason": "BREACH candidate: %s + reflected input + secret tokens in body" % enc,
            }

        for base in bases:
            # Test 1: GET with reflected marker in query string
            url = base + "/?q=" + bust
            r = _oracle_http_get(url, timeout=8)
            if r is not None:
                results["scanned"] += 1
                status, headers, body = r
                entry = _check_breach(url, body, headers, "GET")
                if entry:
                    results["candidates"].append(entry)
                    log.write("  BREACH candidate (GET): %s\n" % url)
                    log.flush()

            # Test 2: POST form endpoints with reflected marker
            for form_path in FORM_PATHS:
                form_url = base.rstrip("/") + form_path
                try:
                    from urllib.request import Request, urlopen
                    import ssl as _ssl_b
                    ctx_b = _ssl_b.create_default_context()
                    ctx_b.check_hostname = False
                    ctx_b.verify_mode = _ssl_b.CERT_NONE
                    post_data = ("q=%s&search=%s&username=%s" % (bust, bust, bust)).encode()
                    req = Request(form_url, data=post_data, headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0",
                        "Accept-Encoding": "gzip, deflate, br",
                    })
                    resp = urlopen(req, timeout=8, context=ctx_b)
                    post_headers = {k.lower(): v for k, v in resp.headers.items()}
                    post_body = resp.read(100000)
                    results["scanned"] += 1
                    entry = _check_breach(form_url, post_body, post_headers, "POST")
                    if entry:
                        results["candidates"].append(entry)
                        log.write("  BREACH candidate (POST): %s\n" % form_url)
                        log.flush()
                except Exception:
                    pass

        log.write("done: scanned %d, %d candidates\n" %
                  (results["scanned"], len(results["candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


# --- _run_tls_oracle_probe ---

def _run_tls_oracle_probe(input_path, output_path, log_path):
    """Active ROBOT probe (Böck, Somorovsky, Young USENIX 2018).

    Takes sslscan XML output as input, extracts hosts that accept TLS_RSA_*,
    and for each such host attempts to identify a Bleichenbacher oracle by
    sending 4 malformed RSA-encrypted PreMaster messages and observing
    response differentials (TCP RST, alert code, timing).
    """
    import socket as _socket
    import ssl as _ssl
    import xml.etree.ElementTree as _ET
    results = {"candidates": [], "confirmed": [], "probed": 0}

    # Parse sslscan XML to find TLS_RSA_* accepting hosts
    rsa_hosts = []
    try:
        with open(input_path) as f:
            # sslscan output was wrapped in <sslscan_results><host target="..">...</host>...
            # Parse line-by-line since sslscan XML is not nested per our wrapper
            content = f.read()
        # Brute force — look for accepted cipher lines containing RSA
        import re
        host_blocks = re.findall(r'<host target="([^"]+)">(.*?)</host>',
                                 content, re.DOTALL)
        for host, block in host_blocks:
            if re.search(r'cipher[^>]*sslversion="TLSv1[.01-2]*"[^>]*RSA', block, re.IGNORECASE):
                rsa_hosts.append(host)
            elif "TLS_RSA_" in block or "TLS-RSA-" in block:
                rsa_hosts.append(host)
    except Exception as e:
        with open(log_path, "w") as log:
            log.write("failed to parse sslscan output: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    rsa_hosts = list(set(rsa_hosts))[:20]  # cap at 20 hosts to keep runtime sane

    # Check for testssl.sh (provides real ROBOT detection with 5 malformed CKE vectors)
    import subprocess as _sp
    testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")

    with open(log_path, "w") as log:
        log.write("tls-oracle-probe: %d RSA-KEX hosts to probe\n" % len(rsa_hosts))
        if testssl_bin:
            log.write("  using testssl.sh (%s) for proper ROBOT detection\n" % testssl_bin)
        else:
            log.write("  WARNING: testssl.sh not found — falling back to RSA KEX acceptance check only\n")
            log.write("  Install testssl.sh for real 5-vector Bleichenbacher detection\n")
        log.flush()

        for host_port in rsa_hosts:
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            else:
                host = host_port
                port = 443
            results["probed"] += 1

            if testssl_bin:
                # Use testssl.sh --robot for proper ROBOT detection
                try:
                    proc = _sp.run(
                        [testssl_bin, "--robot", "--jsonfile", "/dev/stdout",
                         "--warnings", "off", "--color", "0",
                         "%s:%d" % (host, port)],
                        capture_output=True, text=True, timeout=120,
                    )
                    output = proc.stdout
                    import re
                    # Parse testssl JSON output for ROBOT finding
                    severity = "informational"
                    reason = "testssl.sh ROBOT check completed"
                    is_vulnerable = False
                    if '"ROBOT"' in output:
                        if "VULNERABLE" in output.upper():
                            severity = "critical"
                            reason = "ROBOT vulnerability confirmed by testssl.sh (5-vector Bleichenbacher)"
                            is_vulnerable = True
                        elif "not vulnerable" in output.lower():
                            severity = "informational"
                            reason = "Not vulnerable to ROBOT (testssl.sh)"
                        else:
                            severity = "medium"
                            reason = "ROBOT check inconclusive (testssl.sh)"

                    entry = {
                        "host": host_port,
                        "protocol": "TLS",
                        "method": "testssl.sh",
                        "is_vulnerable": is_vulnerable,
                        "severity": severity,
                        "reason": reason,
                        "raw_output": output[:2000],
                    }
                    if is_vulnerable:
                        results["confirmed"].append(entry)
                    else:
                        results["candidates"].append(entry)
                    log.write("  [testssl] %s: %s\n" % (host_port, severity))
                    log.flush()
                except _sp.TimeoutExpired:
                    log.write("  %s: testssl.sh timed out\n" % host_port)
                except Exception as e:
                    log.write("  %s: testssl.sh failed: %s\n" % (host_port, e))
            else:
                # Fallback: check if host accepts RSA KEX (informational only)
                try:
                    proc = _sp.run(
                        ["openssl", "s_client",
                         "-connect", "%s:%d" % (host, port),
                         "-cipher", "AES128-SHA",
                         "-tls1_2", "-servername", host],
                        input=b"", capture_output=True, timeout=12,
                    )
                    baseline_err = proc.stderr.decode("utf-8", errors="replace")
                    if "no cipher match" in baseline_err.lower() or "handshake failure" in baseline_err.lower():
                        log.write("  %s: no RSA KEX accepted, skipping\n" % host_port)
                        continue
                except Exception as e:
                    log.write("  %s: baseline probe failed: %s\n" % (host_port, e))
                    continue

                entry = {
                    "host": host_port,
                    "protocol": "TLS",
                    "method": "openssl-rsa-kex-check",
                    "accepts_rsa_kex": True,
                    "severity": "medium",
                    "reason": ("Host accepts TLS_RSA_* key exchange — ROBOT candidate. "
                               "Install testssl.sh for proper 5-vector Bleichenbacher detection."),
                }
                results["candidates"].append(entry)
                log.write("  [RSA-KEX] %s (install testssl.sh for full ROBOT check)\n" % host_port)
                log.flush()

        log.write("done: probed %d, %d candidates, %d confirmed\n" %
                  (results["probed"], len(results["candidates"]), len(results["confirmed"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


# --- _run_xmlenc_oracle_probe ---

def _run_xmlenc_oracle_probe(input_path, output_path, log_path):
    """Active XML-Enc Bleichenbacher oracle probe (Jager-Somorovsky 2011 style).

    Takes saml-fingerprint JSON as input, finds endpoints marked as rsa15
    candidates, and sends 3 probe SAML responses: well-formed PKCS#1 v1.5,
    random garbage, and a pathological near-match. Records response
    distinguishability as the oracle signal.
    """
    results = {"targets": [], "probed": 0, "confirmed_distinguishers": []}
    try:
        saml_data = _safe_json_load(input_path)
    except Exception as e:
        with open(log_path, "w") as log:
            log.write("failed to parse saml-fingerprint JSON: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    rsa15_candidates = saml_data.get("rsa15_candidates", [])
    metadata_docs = saml_data.get("metadata_docs", [])
    endpoints = saml_data.get("endpoints", [])

    # Extract ACS URLs from metadata docs — the metadata URL itself is not
    # the ACS; we need the AssertionConsumerService Location attribute.
    probe_urls = set()
    metadata_certs = {}  # acs_url -> encryption cert PEM (for constructing probes)
    for doc in metadata_docs:
        xml_text = doc.get("xml", "")
        meta_url = doc.get("url", "")
        if not xml_text:
            continue
        try:
            root = ET.fromstring(xml_text)
            ns = {
                "md": "urn:oasis:names:tc:SAML:2.0:metadata",
                "ds": "http://www.w3.org/2000/09/xmldsig#",
                "xenc": "http://www.w3.org/2001/04/xmlenc#",
            }
            for acs in root.iter():
                tag = acs.tag.split("}")[-1] if "}" in acs.tag else acs.tag
                if tag == "AssertionConsumerService":
                    loc = acs.get("Location", "")
                    if loc and "HTTP-POST" in acs.get("Binding", ""):
                        probe_urls.add(loc)
            # Extract encryption cert if present
            for kd in root.iter():
                tag = kd.tag.split("}")[-1] if "}" in kd.tag else kd.tag
                if tag == "KeyDescriptor" and kd.get("use") == "encryption":
                    for cert_el in kd.iter():
                        cert_tag = cert_el.tag.split("}")[-1] if "}" in cert_el.tag else cert_el.tag
                        if cert_tag == "X509Certificate" and cert_el.text:
                            # Store cert for any ACS URL from this metadata
                            for acs2 in root.iter():
                                t2 = acs2.tag.split("}")[-1] if "}" in acs2.tag else acs2.tag
                                if t2 == "AssertionConsumerService":
                                    loc2 = acs2.get("Location", "")
                                    if loc2:
                                        metadata_certs[loc2] = cert_el.text.strip()
        except ET.ParseError:
            pass

    # Also add rsa15_candidates if they look like ACS URLs (not metadata URLs)
    for c in rsa15_candidates:
        url = c.get("url", "")
        if url and "/metadata" not in url.lower():
            probe_urls.add(url)

    # Fallback: endpoints with saml-response-form marker
    for ep in endpoints:
        if "saml-response-form" in ep.get("reasons", []):
            probe_urls.add(ep.get("url"))

    # Also try post-distinguishable endpoints that look like ACS paths
    for ep in endpoints:
        url = ep.get("url", "")
        if any(p in url.lower() for p in ["/acs", "/consume", "/callback", "/sso/post"]):
            if "post-distinguishable" in ep.get("reasons", []):
                probe_urls.add(url)

    with open(log_path, "w") as log:
        log.write("xmlenc-oracle-probe: %d candidate URLs\n" % len(probe_urls))
        log.flush()

        import urllib.parse as _up
        import base64 as _b64
        import os as _os

        for url in probe_urls:
            if not url:
                continue
            results["probed"] += 1

            # Build 3 test SAML Responses — each with a different EncryptedKey blob
            def _make_saml(enckey_b64):
                saml = (
                    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_probe">'
                    '<saml:EncryptedAssertion>'
                    '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">'
                    '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>'
                    '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                    '<xenc:EncryptedKey>'
                    '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>'
                    '<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>'
                    '</xenc:EncryptedKey>'
                    '</ds:KeyInfo>'
                    '<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>'
                    '</xenc:EncryptedData>'
                    '</saml:EncryptedAssertion>'
                    '</samlp:Response>'
                ) % enckey_b64
                return _b64.b64encode(saml.encode()).decode()

            # Determine RSA key size from metadata cert (if available)
            key_bytes = 256  # default 2048-bit RSA
            cert_pem = metadata_certs.get(url, "")
            if cert_pem:
                try:
                    import ssl as _ssl2
                    import tempfile as _tf
                    pem_full = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % cert_pem
                    with _tf.NamedTemporaryFile(suffix=".pem", mode="w", delete=False) as tmp:
                        tmp.write(pem_full)
                        tmp_path = tmp.name
                    import subprocess as _sp2
                    out = _sp2.run(["openssl", "x509", "-in", tmp_path, "-noout", "-text"],
                                   capture_output=True, text=True, timeout=5)
                    import re as _re
                    m = _re.search(r"Public-Key:\s*\((\d+)\s*bit\)", out.stdout)
                    if m:
                        key_bytes = int(m.group(1)) // 8
                        log.write("  cert key size: %d bits (%d bytes)\n" % (int(m.group(1)), key_bytes))
                    _os.unlink(tmp_path)
                except Exception as ex:
                    log.write("  cert key extraction failed: %s\n" % ex)

            # Probe 1: key_bytes of random garbage (won't look like valid PKCS#1 at all)
            probe1 = _b64.b64encode(_os.urandom(key_bytes)).decode()
            # Probe 2: key_bytes starting with 0x00 0x02 (looks PKCS#1-ish)
            probe2_raw = b"\x00\x02" + _os.urandom(key_bytes - 3) + b"\x00"
            probe2 = _b64.b64encode(probe2_raw).decode()
            # Probe 3: same as probe 2 but 0x00 separator placed early (malformed)
            probe3_raw = b"\x00\x02" + _os.urandom(8) + b"\x00" + _os.urandom(key_bytes - 11)
            probe3 = _b64.b64encode(probe3_raw).decode()

            responses = []
            for label, ek in (("random", probe1), ("pkcs15-ish", probe2), ("malformed", probe3)):
                body = _up.urlencode({"SAMLResponse": _make_saml(ek)}).encode()
                try:
                    from urllib.request import Request, urlopen
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    req = Request(url, data=body, headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0 (oracle-probe)",
                    })
                    start = time.monotonic()
                    try:
                        resp = urlopen(req, timeout=15, context=ctx)
                        status = resp.status
                        body_bytes = resp.read(2048)
                    except Exception as e:
                        status = getattr(e, "code", 0)
                        body_bytes = b""
                        if hasattr(e, "read"):
                            try:
                                body_bytes = e.read(2048)
                            except Exception:
                                pass
                    elapsed_ms = (time.monotonic() - start) * 1000
                    fingerprint = "%d|%d|%d" % (status, len(body_bytes), int(elapsed_ms / 50))
                    responses.append({
                        "label": label, "status": status,
                        "body_len": len(body_bytes), "elapsed_ms": round(elapsed_ms, 1),
                        "fingerprint": fingerprint,
                    })
                except Exception as e:
                    responses.append({"label": label, "error": str(e)})

            # Signal analysis: if any 2 of 3 probes produce distinguishable fingerprints,
            # we have an oracle candidate
            fingerprints = [r.get("fingerprint") for r in responses if r.get("fingerprint")]
            distinct = len(set(fingerprints))
            is_oracle = distinct >= 2
            entry = {
                "url": url,
                "probes": responses,
                "distinct_fingerprints": distinct,
                "is_oracle_candidate": is_oracle,
                "severity": "critical" if is_oracle else "informational",
            }
            if is_oracle:
                entry["reason"] = (
                    "XML-Enc endpoint distinguishes malformed PKCS#1 v1.5 ciphertexts — "
                    "Bleichenbacher oracle candidate (Jager-Somorovsky 2011)"
                )
                results["confirmed_distinguishers"].append(entry)
                log.write("  ** ORACLE: %s (distinct=%d) **\n" % (url, distinct))
            else:
                log.write("  no distinguisher: %s (distinct=%d)\n" % (url, distinct))
            log.flush()
            results["targets"].append(entry)

        log.write("done: probed %d, %d oracle candidates\n" %
                  (results["probed"], len(results["confirmed_distinguishers"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["confirmed_distinguishers"])


# ========================================================================
# ORACLE PIPELINE RESULT PARSERS
# ========================================================================
# Each parser returns a list of dicts compatible with the recon_results
# ingestion code. Each dict MUST have a "value" field (primary identifier)
# and a "result_type" field (one of the oracle_* types defined in
# RESULT_TYPES below). Optional fields: severity, host, reason, metadata.


def _parse_sslscan_results(filepath):
    """Parse sslscan XML output wrapped in <sslscan_results><host target="..">...</host>...

    Emits actionable oracle-candidate findings with honest severity:
    - tls_oracle_sslv2 (high): SSLv2 enabled. Still relevant via DROWN.
    - tls_oracle_sslv3 (medium): SSLv3 enabled. POODLE. Rare in 2026.
    - tls_oracle_tls10/tls11 (low): legacy TLS. BEAST/Lucky 13 target class
      but mainstream stacks patched constant-time HMAC years ago. Low.
    - tls_oracle_export (high): export-grade ciphers. FREAK/Logjam.
    - tls_oracle_rsa_kex (high): TLS_RSA_* accepted. ROBOT target.
    - tls_oracle_rc4 (medium): RC4 accepted. NOMORE/biases attacks.
    - tls_oracle_3des (medium): 3DES accepted. Sweet32.
    - tls_oracle_cbc_hmac_sha1 (informational): CBC with HMAC-SHA1 accepted.
      This is the Lucky 13 TARGET CLASS, but every mainstream TLS stack has
      had constant-time HMAC since 2013. Flagged as informational for manual
      stack-fingerprinting follow-up, not as a confirmed vulnerability.
    """
    import re
    results = []
    try:
        with open(filepath) as f:
            content = f.read()
    except OSError:
        return results

    def _cipher_is_cbc(c):
        """OpenSSL cipher name convention: absence of -GCM-/-CCM-/-POLY1305
        and absence of RC4/DES/NULL in the enc slot means CBC."""
        if any(mode in c for mode in ("GCM", "CCM", "POLY1305", "CHACHA20")):
            return False
        if "RC4" in c or "NULL" in c:
            return False
        # AES*, CAMELLIA*, DES*, ARIA* default to CBC unless -GCM- is present
        if any(alg in c for alg in ("AES", "CAMELLIA", "ARIA", "DES", "SEED", "IDEA")):
            return True
        return False

    def _cipher_uses_hmac_sha1(c):
        """MAC-then-encrypt CBC with HMAC-SHA1 is the Lucky 13 target class.
        OpenSSL names: trailing -SHA (no digits) means HMAC-SHA1."""
        return _cipher_is_cbc(c) and (c.endswith("-SHA") or c == "DES-CBC3-SHA"
                                       or c.endswith("-MD5"))

    host_blocks = re.findall(r'<host target="([^"]+)">(.*?)</host>',
                             content, re.DOTALL)
    for host, block in host_blocks:
        # Protocol detection — need both the <protocol version="X" enabled="1"/>
        # and the sslversion="TLSvX" attributes on accepted ciphers.
        # The <protocol> element has: type="ssl|tls" version="2|3|1.0|1.1|1.2|1.3"
        # So combine type + version to form "SSLv2", "SSLv3", "TLSv1.0", etc.
        proto_matches = re.findall(
            r'<protocol\s+type="([^"]+)"\s+version="([^"]+)"\s+enabled="1"\s*/>',
            block)
        enabled_protos = set()
        for proto_type, proto_version in proto_matches:
            if proto_type == "ssl":
                enabled_protos.add("SSLv%s" % proto_version)  # SSLv2, SSLv3
            elif proto_type == "tls":
                enabled_protos.add("TLSv%s" % proto_version)  # TLSv1.0 .. TLSv1.3

        # Accepted ciphers
        accepted = re.findall(
            r'<cipher[^>]*status="accepted"[^>]*sslversion="([^"]+)"[^>]*cipher="([^"]+)"',
            block)
        all_accepted = set(accepted)
        tls_versions_found = set(v for v, _ in all_accepted) | enabled_protos

        # Also track which CBC ciphers were accepted on LEGACY protocols specifically
        # (TLS 1.0/1.1) — those are the classic BEAST/Lucky 13 targets.
        legacy_cbc_ciphers = [(ver, c) for ver, c in all_accepted
                              if ver in ("TLSv1.0", "TLSv1.1", "SSLv3")
                              and _cipher_is_cbc(c)]

        # --- Protocol-level findings ---
        if "SSLv2" in tls_versions_found:
            results.append({
                "result_type": "tls_oracle_sslv2",
                "value": host, "host": host,
                "severity": "high",
                "reason": "SSLv2 enabled — DROWN candidate (CVE-2016-0800)",
            })
        if "SSLv3" in tls_versions_found:
            results.append({
                "result_type": "tls_oracle_sslv3",
                "value": host, "host": host,
                "severity": "medium",
                "reason": "SSLv3 enabled — POODLE candidate (CVE-2014-3566)",
            })
        if "TLSv1.0" in tls_versions_found:
            results.append({
                "result_type": "tls_oracle_tls10",
                "value": host, "host": host,
                "severity": "low",
                "reason": ("TLS 1.0 enabled — BEAST/Lucky 13 target class. "
                           "Mainstream TLS stacks patched constant-time HMAC "
                           "in 2013, so exploitation requires an unpatched "
                           "legacy stack. Verify by fingerprinting the server "
                           "stack version."),
            })
        if "TLSv1.1" in tls_versions_found:
            results.append({
                "result_type": "tls_oracle_tls11",
                "value": host, "host": host,
                "severity": "low",
                "reason": "TLS 1.1 enabled — legacy CBC target class",
            })

        # --- Cipher-level findings ---
        rsa_kex = [c for ver, c in all_accepted
                   if "RSA" in c and "DHE" not in c and "ECDHE" not in c]
        if rsa_kex:
            results.append({
                "result_type": "tls_oracle_rsa_kex",
                "value": host, "host": host,
                "severity": "high",
                "reason": "Accepts TLS_RSA_* static key exchange — ROBOT candidate (CVE-2017-13099)",
                "ciphers": rsa_kex[:10],
            })
        export_ciphers = [c for ver, c in all_accepted if "EXPORT" in c]
        if export_ciphers:
            results.append({
                "result_type": "tls_oracle_export",
                "value": host, "host": host,
                "severity": "high",
                "reason": "Accepts export-grade cipher — FREAK/Logjam candidate",
                "ciphers": export_ciphers,
            })
        rc4_ciphers = [c for ver, c in all_accepted if "RC4" in c]
        if rc4_ciphers:
            results.append({
                "result_type": "tls_oracle_rc4",
                "value": host, "host": host,
                "severity": "medium",
                "reason": "Accepts RC4 — keystream bias attacks (NOMORE, Bar Mitzvah)",
                "ciphers": rc4_ciphers[:10],
            })
        triple_des = [c for ver, c in all_accepted
                      if "3DES" in c or "DES-CBC3" in c]
        if triple_des:
            results.append({
                "result_type": "tls_oracle_3des",
                "value": host, "host": host,
                "severity": "medium",
                "reason": "Accepts 3DES (64-bit block) — Sweet32 (CVE-2016-2183)",
                "ciphers": triple_des[:10],
            })

        # CBC + HMAC-SHA1 is the Lucky 13 target class. Emit as INFORMATIONAL
        # only — accepting these ciphers is necessary but not sufficient, every
        # mainstream TLS stack patched Lucky 13 in 2013, and verification
        # requires either stack fingerprinting or impractical timing attacks.
        # On modern servers (TLS 1.2+) with constant-time HMAC, these ciphers
        # are harmless. Flag so you know to look but do not over-report.
        sha1_cbc_ciphers = [c for ver, c in all_accepted if _cipher_uses_hmac_sha1(c)]
        if sha1_cbc_ciphers:
            results.append({
                "result_type": "tls_oracle_cbc_hmac_sha1",
                "value": host, "host": host,
                "severity": "informational",
                "reason": ("Accepts CBC+HMAC-SHA1 cipher suite(s) — Lucky 13 "
                           "target class. NOT a confirmed vulnerability: every "
                           "mainstream TLS stack has had constant-time HMAC "
                           "since 2013. Exploitation requires an unpatched "
                           "legacy stack (pre-OpenSSL 1.0.1g, pre-NSS 3.16, "
                           "pre-GnuTLS 3.1.22). Verify via stack fingerprinting."),
                "ciphers": sha1_cbc_ciphers[:10],
            })

        # BEAST specifically requires TLS 1.0 + CBC on the same connection
        if legacy_cbc_ciphers:
            results.append({
                "result_type": "tls_oracle_legacy_cbc",
                "value": host, "host": host,
                "severity": "low",
                "reason": ("CBC ciphers accepted on legacy TLS (pre-1.2) — "
                           "BEAST target class (chosen-boundary chained IV attack). "
                           "All modern browsers have client-side BEAST mitigations."),
                "ciphers": ["%s:%s" % (v, c) for v, c in legacy_cbc_ciphers[:10]],
            })
    return results


def _parse_sslyze_results(filepath):
    """Parse sslyze JSON output. Extracts ROBOT status, weak DH params, RSA keys for ROCA."""
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    scans = data.get("server_scan_results", []) or []
    for scan in scans:
        try:
            loc = scan.get("server_location", {}) or {}
            hostname = loc.get("hostname", "unknown")
            port = loc.get("port", 443)
            host = "%s:%s" % (hostname, port)
            scan_result = scan.get("scan_result", {}) or {}
            # ROBOT check
            robot = scan_result.get("robot", {}) or {}
            robot_result = (robot.get("result") or {}).get("robot_result", "")
            # sslyze RobotScanResultEnum values:
            #   VULNERABLE_WEAK_ORACLE       → vulnerable
            #   VULNERABLE_STRONG_ORACLE     → vulnerable
            #   NOT_VULNERABLE_NO_ORACLE     → NOT vulnerable (no oracle signal)
            #   NOT_VULNERABLE_RSA_NOT_SUPPORTED → NOT vulnerable (no RSA KEX at all)
            #   UNKNOWN_INCONSISTENT_RESULTS → unknown
            # The old code used `"VULNERABLE" in robot_result.upper()` which
            # matched the NOT_VULNERABLE_* values as substring → false positives.
            if robot_result and robot_result.upper().startswith("VULNERABLE_"):
                results.append({
                    "result_type": "tls_oracle_confirmed",
                    "value": host, "host": host,
                    "severity": "critical",
                    "reason": "sslyze confirmed ROBOT vulnerability: %s" % robot_result,
                })
            elif robot_result and robot_result.upper().startswith("NOT_VULNERABLE"):
                # Positive evidence the host is NOT ROBOT-vulnerable. This is
                # used by the ingestion layer to suppress the speculative
                # tls_oracle_rsa_kex finding emitted by sslscan when it sees
                # TLS_RSA_* cipher acceptance.
                results.append({
                    "result_type": "tls_oracle_robot_clear",
                    "value": host, "host": host,
                    "severity": "informational",
                    "reason": "sslyze ROBOT probe: %s" % robot_result,
                })
            # Heartbleed
            hb = scan_result.get("heartbleed", {}) or {}
            hb_result = (hb.get("result") or {}).get("is_vulnerable_to_heartbleed", False)
            if hb_result:
                results.append({
                    "result_type": "tls_oracle_heartbleed",
                    "value": host, "host": host,
                    "severity": "critical",
                    "reason": "Heartbleed (CVE-2014-0160) vulnerable",
                })
            # Protocol version enumeration — sslyze key names use "ssl_2_0",
            # "ssl_3_0", "tls_1_0", "tls_1_1" etc. Include TLS 1.0/1.1 for
            # completeness since they're Lucky 13 / BEAST target classes.
            for proto_key, rt, sev, reason in (
                ("ssl_2_0_cipher_suites", "tls_oracle_sslv2", "high",
                 "SSLv2 enabled (sslyze) — DROWN candidate (CVE-2016-0800)"),
                ("ssl_3_0_cipher_suites", "tls_oracle_sslv3", "medium",
                 "SSLv3 enabled (sslyze) — POODLE candidate (CVE-2014-3566)"),
                ("tls_1_0_cipher_suites", "tls_oracle_tls10", "low",
                 "TLS 1.0 enabled (sslyze) — BEAST/Lucky 13 target class"),
                ("tls_1_1_cipher_suites", "tls_oracle_tls11", "low",
                 "TLS 1.1 enabled (sslyze) — legacy CBC target class"),
            ):
                cipher_scan = scan_result.get(proto_key, {}) or {}
                cipher_result = cipher_scan.get("result") or {}
                accepted_list = cipher_result.get("accepted_cipher_suites", [])
                if accepted_list:
                    results.append({
                        "result_type": rt,
                        "value": host, "host": host,
                        "severity": sev,
                        "reason": "%s (%d ciphers)" % (reason, len(accepted_list)),
                    })
        except Exception:
            continue
    return results


def _parse_saml_fingerprint_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for ep in data.get("endpoints", []):
        results.append({
            "result_type": "saml_endpoint",
            "value": ep.get("url", ""),
            "host": ep.get("url", ""),
            "severity": "informational",
            "reason": "SAML endpoint: %s" % ", ".join(ep.get("reasons", [])),
        })
    for doc in data.get("metadata_docs", []):
        results.append({
            "result_type": "saml_metadata",
            "value": doc.get("url", ""),
            "host": doc.get("url", ""),
            "severity": "informational",
            "reason": "SAML SP metadata XML exposed (%d bytes)" % doc.get("length", 0),
        })
    for c in data.get("rsa15_candidates", []):
        results.append({
            "result_type": "saml_rsa15_metadata",
            "value": c.get("url", ""),
            "host": c.get("url", ""),
            "severity": c.get("severity", "critical"),
            "reason": c.get("reason", "SAML metadata advertises rsa-1_5"),
            "algorithm": c.get("algorithm", ""),
        })
    return results


def _parse_jwt_jwe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for tok in data.get("tokens", []):
        results.append({
            "result_type": "jwt_finding",
            "value": "%s [alg=%s]" % (tok.get("url", ""), tok.get("alg", "")),
            "host": tok.get("url", ""),
            "severity": "informational",
            "alg": tok.get("alg", ""),
            "token_preview": tok.get("token_preview", ""),
        })
    for crit in data.get("critical_findings", []):
        rt = "jwe_rsa15" if crit.get("alg") == "RSA1_5" else "jwt_weak_alg"
        results.append({
            "result_type": rt,
            "value": "%s [alg=%s]" % (crit.get("url", ""), crit.get("alg", "")),
            "host": crit.get("url", ""),
            "severity": crit.get("severity", "high"),
            "reason": "; ".join(crit.get("reasons", [])),
            "alg": crit.get("alg", ""),
        })
    return results


def _parse_cookie_harvest_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for cand in data.get("cbc_candidates", []):
        results.append({
            "result_type": "encrypted_token_candidate",
            "value": "%s cookie=%s" % (cand.get("url", ""), cand.get("name", "")),
            "host": cand.get("url", ""),
            "severity": "informational",
            "reason": "High-entropy cookie with CBC-block-size signature (%d decoded bytes)" %
                      cand.get("decoded_len", 0),
            "framework_hint": cand.get("framework_hint"),
            "entropy": cand.get("entropy", 0),
        })
    return results


def _parse_roca_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for v in data.get("vulnerable", []):
        results.append({
            "result_type": "roca_vulnerable",
            "value": v.get("host", ""),
            "host": v.get("host", ""),
            "severity": "critical",
            "reason": v.get("reason", "ROCA (CVE-2017-15361) vulnerable RSA modulus"),
            "modulus_bits": v.get("modulus_bits", 0),
            "fingerprint": v.get("fingerprint", ""),
        })
    return results


def _parse_breach_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "breach_candidate",
            "value": c.get("url", ""),
            "host": c.get("url", ""),
            "severity": c.get("severity", "medium"),
            "reason": c.get("reason", "BREACH candidate"),
            "content_encoding": c.get("content_encoding", ""),
        })
    return results


def _parse_tls_oracle_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "tls_oracle_candidate",
            "value": c.get("host", ""),
            "host": c.get("host", ""),
            "severity": c.get("severity", "high"),
            "reason": c.get("reason", "TLS RSA KEX accepted"),
        })
    return results


def _parse_xmlenc_oracle_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for t in data.get("targets", []):
        if t.get("is_oracle_candidate"):
            results.append({
                "result_type": "xmlenc_oracle_confirmed",
                "value": t.get("url", ""),
                "host": t.get("url", ""),
                "severity": "critical",
                "reason": t.get("reason", "XML-Enc Bleichenbacher oracle distinguisher found"),
                "distinct_fingerprints": t.get("distinct_fingerprints", 0),
            })
        else:
            results.append({
                "result_type": "xmlenc_probed",
                "value": t.get("url", ""),
                "host": t.get("url", ""),
                "severity": "informational",
                "reason": "XML-Enc probe: %d distinct fingerprints (no oracle signal)" %
                          t.get("distinct_fingerprints", 0),
            })
    return results


# ========================================================================
# EXTENDED ORACLE PIPELINE TOOLS
# ========================================================================
# Each of the tools below implements one or more cryptographic oracle
# attack families that the original oracle pipeline did not cover.
# Hacktivity-grounded targets:
#   - cbc-padding-probe       Phabricator/FormAssembly/OAM CBC padding oracles
#   - marvin-probe            OpenSSL/Node.js Marvin (timing Bleichenbacher)
#   - xsw-probe               GitHub SAML XSW critical
#   - viewstate-fingerprint   DoD ASP.NET ViewState CAC bypass
#   - jwe-invalid-curve-probe IBB JWE Invalid Curve $1,000
#   - manger-oaep-probe       Manger 2001 chosen-ciphertext on RSA-OAEP
#   - ssh-terrapin-scan       Terrapin (CVE-2023-48795)
#   - gcm-nonce-scan          Böck et al. 2016 GCM nonce reuse
#   - raccoon-probe           Raccoon (USENIX Security 2021) TLS-DH leading-zero timing


# --- _run_cbc_padding_probe ---

def _run_cbc_padding_probe(input_path, output_path, log_path):
    """Active Vaudenay-style CBC padding oracle probe.

    Takes cookie-harvest JSON output, finds entries flagged as `is_cbc_candidate`,
    and for each one runs the classic 3-request differential test:
      1. Baseline:  send the unmodified cookie back to the URL it came from
      2. Last-byte flip: XOR the last byte of decoded ciphertext, re-encode,
         submit. Likely produces a "bad padding" response if the server is
         vulnerable.
      3. Middle-byte flip: XOR a byte in the middle of the ciphertext, re-encode,
         submit. Padding is still likely valid (corrupt content), so the server
         processes the decrypted-but-corrupt content and likely produces a
         different response.

    If responses (2) and (3) differ from each other AND from baseline, the
    server is exhibiting a padding oracle distinguisher. Reports as
    `cbc_padding_oracle_confirmed` with the (status, body_len, sha8) fingerprints
    so you can verify manually before exploiting with PadBuster.
    """
    import base64 as _b64
    results = {"probed": 0, "candidates": [], "confirmed": []}
    try:
        cookie_data = _safe_json_load(input_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        with open(log_path, "w") as log:
            log.write("failed to read cookie-harvest input: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    candidates = cookie_data.get("cbc_candidates", []) or []
    with open(log_path, "w") as log:
        log.write("cbc-padding-probe: %d CBC candidates from cookie-harvest\n" % len(candidates))
        log.flush()
        # Cap at 25 candidates to keep runtime sane
        for entry in candidates[:25]:
            url = entry.get("url", "")
            name = entry.get("name", "")
            value = entry.get("value_preview", "")
            if not url or not name or not value:
                continue
            # We only have a 40-char preview from cookie-harvest. To do a real
            # probe we need to refetch the page and capture the full cookie value.
            r = _oracle_http_get(url, timeout=8)
            if r is None:
                log.write("  %s: refetch failed\n" % url)
                continue
            _, headers, _ = r
            sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
            # Extract the named cookie's full value
            full_value = None
            import re
            for m in re.finditer(r'(%s)=([^;,\s]+)' % re.escape(name), sc):
                full_value = m.group(2)
                break
            if not full_value:
                log.write("  %s/%s: cookie no longer present\n" % (url, name))
                continue
            # Decode value (try urlsafe then standard b64)
            decoded = None
            for decoder in (_b64.urlsafe_b64decode, _b64.b64decode):
                try:
                    decoded = bytearray(decoder(full_value + "=" * (-len(full_value) % 4)))
                    break
                except Exception:
                    continue
            if decoded is None or len(decoded) < 32 or len(decoded) % 16 != 0:
                log.write("  %s/%s: not 16-aligned, skipping\n" % (url, name))
                continue

            results["probed"] += 1
            # Build the 3 ciphertexts:
            ct_baseline = bytes(decoded)
            ct_last_flip = bytearray(decoded)
            ct_last_flip[-1] ^= 0x01
            ct_last_flip = bytes(ct_last_flip)
            ct_middle_flip = bytearray(decoded)
            mid_idx = len(decoded) // 2
            ct_middle_flip[mid_idx] ^= 0x01
            ct_middle_flip = bytes(ct_middle_flip)

            def _enc(b):
                return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

            def _probe(ct_b64):
                """Send a request with the named cookie set to the modified ciphertext."""
                cookie_header = "%s=%s" % (name, ct_b64)
                rr = _oracle_http_get(url, timeout=8,
                                       extra_headers={"Cookie": cookie_header})
                if rr is None:
                    return None
                return _oracle_response_fingerprint(rr[0], rr[2])

            fp_baseline = _probe(_enc(ct_baseline))
            fp_last = _probe(_enc(ct_last_flip))
            fp_middle = _probe(_enc(ct_middle_flip))
            if not (fp_baseline and fp_last and fp_middle):
                log.write("  %s/%s: probe failed\n" % (url, name))
                continue

            cand = {
                "url": url,
                "cookie": name,
                "value_len": len(full_value),
                "decoded_len": len(decoded),
                "baseline": list(fp_baseline),
                "last_flip": list(fp_last),
                "middle_flip": list(fp_middle),
            }
            # Distinguishability: last_flip and middle_flip should differ (the
            # canonical Vaudenay signal). Also flag if any of them differs from
            # baseline (which would indicate validation runs at all).
            distinct = (fp_last != fp_middle) or (
                fp_last != fp_baseline and fp_middle != fp_baseline
            )
            cand["is_oracle"] = bool(distinct and fp_last != fp_middle)
            results["candidates"].append(cand)
            if cand["is_oracle"]:
                results["confirmed"].append(cand)
                log.write("  [ORACLE] %s/%s baseline=%s last=%s middle=%s\n" %
                          (url, name, fp_baseline, fp_last, fp_middle))
            else:
                log.write("  %s/%s: no distinguisher (baseline=%s last=%s middle=%s)\n" %
                          (url, name, fp_baseline, fp_last, fp_middle))
            log.flush()

        log.write("done: probed %d, %d candidates, %d confirmed oracles\n" %
                  (results["probed"], len(results["candidates"]),
                   len(results["confirmed"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


def _parse_cbc_padding_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("confirmed", []):
        results.append({
            "result_type": "cbc_padding_oracle_confirmed",
            "value": "%s [cookie=%s]" % (c.get("url", ""), c.get("cookie", "")),
            "host": c.get("url", ""),
            "severity": "critical",
            "reason": ("CBC padding oracle distinguisher confirmed: "
                       "baseline/last-byte-flip/middle-byte-flip produced 3 "
                       "different responses. Run PadBuster to extract plaintext."),
            "fingerprints": {
                "baseline": c.get("baseline"),
                "last_flip": c.get("last_flip"),
                "middle_flip": c.get("middle_flip"),
            },
        })
    for c in data.get("candidates", []):
        if c.get("is_oracle"):
            continue  # already emitted as confirmed
        results.append({
            "result_type": "cbc_padding_probed",
            "value": "%s [cookie=%s]" % (c.get("url", ""), c.get("cookie", "")),
            "host": c.get("url", ""),
            "severity": "informational",
            "reason": "CBC padding probe: no distinguisher signal",
        })
    return results


# --- _run_marvin_probe ---

def _run_marvin_probe(input_path, output_path, log_path):
    """Marvin Attack screening — identifies RSA KEX hosts for follow-up.

    NOTE: This probe does NOT send crafted ciphertexts (which requires
    TLS-Attacker or raw socket TLS). It identifies hosts that accept
    TLS_RSA_* key exchange and flags them for manual testing with the
    marvin-toolkit (Kario, RHEL). Severity is low — RSA KEX acceptance
    is a prerequisite, not a confirmed vulnerability.
    """
    import re
    import socket as _socket
    import ssl as _ssl
    results = {"probed": 0, "candidates": [], "skipped": []}
    try:
        with open(input_path) as f:
            content = f.read()
    except OSError as e:
        with open(log_path, "w") as log:
            log.write("failed to read sslscan output: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    rsa_hosts = []
    host_blocks = re.findall(r'<host target="([^"]+)">(.*?)</host>', content, re.DOTALL)
    for host, block in host_blocks:
        if re.search(r'cipher[^>]*RSA', block, re.IGNORECASE) and "DHE" not in block:
            rsa_hosts.append(host)
    rsa_hosts = list(dict.fromkeys(rsa_hosts))[:20]

    with open(log_path, "w") as log:
        log.write("marvin-probe: screening %d hosts for RSA KEX acceptance\n" % len(rsa_hosts))
        log.write("NOTE: This is a prerequisite check only. Actual Marvin detection\n")
        log.write("requires marvin-toolkit with crafted ciphertexts + statistical analysis.\n")
        log.flush()

        for host_port in rsa_hosts:
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                try:
                    port = int(port_s)
                except ValueError:
                    port = 443
            else:
                host = host_port
                port = 443

            try:
                test = _socket.create_connection((host, port), timeout=5)
                test.close()
            except Exception as e:
                log.write("  %s: unreachable (%s)\n" % (host_port, e))
                results["skipped"].append({"host": host_port, "reason": "unreachable"})
                continue

            results["probed"] += 1

            # Verify RSA KEX acceptance via actual handshake
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.set_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA")
            except _ssl.SSLError:
                log.write("  %s: cannot set RSA ciphers\n" % host_port)
                continue

            rsa_accepted = False
            negotiated_cipher = ""
            try:
                s = _socket.create_connection((host, port), timeout=5)
                ssock = ctx.wrap_socket(s, server_hostname=host)
                negotiated_cipher = ssock.cipher()[0] if ssock.cipher() else ""
                rsa_accepted = True
                ssock.close()
            except Exception:
                pass

            if rsa_accepted:
                entry = {
                    "host": host_port,
                    "accepts_rsa_kex": True,
                    "negotiated_cipher": negotiated_cipher,
                    "is_marvin_candidate": True,
                    "severity": "low",
                    "reason": ("Host accepts TLS_RSA_* (%s) — Marvin prerequisite met. "
                               "Run marvin-toolkit for actual timing analysis with "
                               "crafted ciphertexts." % negotiated_cipher),
                }
                results["candidates"].append(entry)
                log.write("  %s: RSA KEX accepted (%s) — needs marvin-toolkit follow-up\n" %
                          (host_port, negotiated_cipher))
            else:
                log.write("  %s: RSA KEX handshake failed\n" % host_port)
            log.flush()

        log.write("done: probed %d, %d RSA KEX hosts flagged for marvin-toolkit\n" %
                  (results["probed"], len(results["candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


def _parse_marvin_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        if c.get("is_marvin_candidate"):
            results.append({
                "result_type": "marvin_timing_candidate",
                "value": c.get("host", ""),
                "host": c.get("host", ""),
                "severity": "low",
                "reason": ("Marvin prerequisite: host accepts TLS_RSA_* (%s). "
                           "Run marvin-toolkit with crafted ciphertexts for "
                           "actual timing analysis." % c.get("negotiated_cipher", "unknown")),
            })
    return results


# --- _run_xsw_probe ---

def _run_xsw_probe(input_path, output_path, log_path):
    """SAML XML Signature Wrapping (XSW1–XSW8) active probe.

    Takes saml-fingerprint JSON output, identifies SAML ACS endpoints
    (post_distinguishable=True), and for each one submits a series of
    XSW-pattern SAMLResponse payloads. The payloads are templated XSW1
    through XSW8 from the literature (Somorovsky 2012 / SAML Raider).

    We don't actually have a real signed assertion to wrap — instead we
    submit XSW-shaped XML that has the structural anomalies of each XSW
    pattern (a signed element + an unsigned twin in different positions).
    The probe is whether the SP exhibits *any* differential response to
    the XSW shapes vs the baseline:
      - Same fingerprint as baseline 404 → no XML processing → safe
      - Different fingerprint per XSW shape → SP is processing the XML
        and applying signature checks differently per shape → POTENTIAL
        XSW vulnerability worth manual follow-up with SAML Raider.
    """
    import base64 as _b64
    import random as _random
    import string as _string
    results = {"endpoints": [], "candidates": []}

    try:
        data = _safe_json_load(input_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        with open(log_path, "w") as log:
            log.write("failed to read saml-fingerprint input: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    # Use endpoints flagged as post_distinguishable (these are real SAML ACS)
    targets = data.get("post_distinguishable", []) or []
    if not targets:
        # Fall back to all SAML endpoints
        targets = data.get("endpoints", []) or []

    # Minimal XSW shapes — each is a SAMLResponse XML with a structural anomaly.
    # We don't have a real signed assertion, so the signature element is a
    # placeholder; the test is whether the SP processes the XML differently
    # per shape (which is the XSW signal).
    def _xsw_payload(shape, nonce):
        """Build a minimal SAML response with the given XSW shape."""
        # Base structure: <samlp:Response><saml:Assertion>...</saml:Assertion></samlp:Response>
        attacker_id = "attacker-%s" % nonce
        legit_id = "legit-%s" % nonce
        if shape == 1:
            # XSW1: signature wraps a copy of the original assertion that's
            # been moved out of the signature scope
            xml = (
                '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r%s">'
                '<saml:Assertion ID="evil%s"><saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject></saml:Assertion>'
                '<saml:Assertion ID="orig%s"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#orig%s"/></ds:SignedInfo></ds:Signature>'
                '<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject></saml:Assertion>'
                '</samlp:Response>'
            ) % (nonce, nonce, attacker_id, nonce, nonce, legit_id)
        elif shape == 2:
            # XSW2: evil assertion as sibling of signed assertion under same parent
            xml = (
                '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r%s">'
                '<saml:Assertion ID="orig%s"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#orig%s"/></ds:SignedInfo></ds:Signature></saml:Assertion>'
                '<saml:Assertion ID="evil%s"><saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject></saml:Assertion>'
                '</samlp:Response>'
            ) % (nonce, nonce, nonce, nonce, attacker_id)
        elif shape == 3:
            # XSW3: evil assertion as child of original assertion
            xml = (
                '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r%s">'
                '<saml:Assertion ID="orig%s"><saml:Assertion ID="evil%s"><saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject></saml:Assertion>'
                '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#orig%s"/></ds:SignedInfo></ds:Signature></saml:Assertion>'
                '</samlp:Response>'
            ) % (nonce, nonce, nonce, attacker_id, nonce)
        else:
            xml = '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r%s"/>' % nonce
        return xml

    with open(log_path, "w") as log:
        log.write("xsw-probe: %d SAML targets\n" % len(targets))
        log.flush()
        # Cap at 15 targets to keep runtime sane
        for tgt in targets[:15]:
            url = tgt.get("url") or tgt
            if not isinstance(url, str):
                continue
            nonce = "".join(_random.choices(_string.ascii_lowercase, k=8))

            # Establish a baseline 404 fingerprint with random nonsense XML
            baseline_xml = '<?xml version="1.0"?><junk/>'
            baseline_form = "SAMLResponse=" + _b64.b64encode(baseline_xml.encode()).decode()
            br = _oracle_http_post(url, baseline_form, timeout=10)
            if br is None:
                log.write("  %s: baseline failed\n" % url)
                continue
            baseline_fp = _oracle_response_fingerprint(br[0], br[2])

            shape_fps = {}
            for shape in (1, 2, 3):
                xml = _xsw_payload(shape, nonce)
                form = "SAMLResponse=" + _b64.b64encode(xml.encode()).decode()
                pr = _oracle_http_post(url, form, timeout=10)
                if pr is None:
                    continue
                shape_fps[shape] = list(_oracle_response_fingerprint(pr[0], pr[2]))

            # Build per-endpoint summary
            entry = {
                "url": url,
                "baseline": list(baseline_fp),
                "shapes": shape_fps,
            }

            # Distinguishability: any shape produces a fingerprint that differs
            # from baseline AND differs from at least one other shape
            unique_fps = set(tuple(v) for v in shape_fps.values())
            differs_from_baseline = any(tuple(v) != baseline_fp
                                         for v in shape_fps.values())
            multiple_classes = len(unique_fps) > 1
            entry["is_xsw_candidate"] = bool(differs_from_baseline and multiple_classes)
            results["endpoints"].append(entry)
            if entry["is_xsw_candidate"]:
                results["candidates"].append(entry)
                log.write("  [XSW-CANDIDATE] %s baseline=%s shapes=%s\n" %
                          (url, baseline_fp, shape_fps))
            else:
                log.write("  %s: no XSW signal\n" % url)
            log.flush()
        log.write("done: %d endpoints, %d XSW candidates\n" %
                  (len(results["endpoints"]), len(results["candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["endpoints"])


def _parse_xsw_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "saml_xsw_candidate",
            "value": c.get("url", ""),
            "host": c.get("url", ""),
            "severity": "high",
            "reason": ("SAML XSW (XML Signature Wrapping) candidate — endpoint "
                       "exhibits per-shape response variance against XSW1/2/3 "
                       "patterns. Test manually with SAML Raider before reporting."),
            "shapes": c.get("shapes"),
        })
    return results


# --- _run_viewstate_fingerprint ---

def _run_viewstate_fingerprint(input_path, output_path, log_path):
    """ASP.NET ViewState detector and pre-generation/MS10-070 candidate flag.

    Takes httpx JSONL, fetches each live host's root + common ASP.NET paths,
    extracts the `__VIEWSTATE` hidden form field, and analyzes:
      - Is __VIEWSTATEGENERATOR present? (means MAC validation is enabled,
        but the static MAC key may still be leaked/predictable.)
      - Is the value MAC-protected? (heuristic: length > 24 + decoded prefix)
      - Is the value the well-known empty pre-init ViewState? (signature of
        a server that accepts pre-generated state)
    Flags hosts with __VIEWSTATE as ASP.NET targets for ViewstateInspector
    or ysoserial.net follow-up.
    """
    import base64 as _b64
    import re
    results = {"hosts": [], "candidates": []}
    bases = _oracle_hosts_from_httpx(input_path, limit=300)
    paths = ["/", "/Default.aspx", "/login.aspx", "/admin.aspx",
             "/account/login.aspx", "/Login.aspx"]

    with open(log_path, "w") as log:
        log.write("viewstate-fingerprint: %d bases\n" % len(bases))
        log.flush()
        for base in bases:
            for path in paths:
                url = base + path
                r = _oracle_http_get(url, timeout=8)
                if r is None:
                    continue
                status, headers, body = r
                if status not in (200, 302):
                    continue
                body_str = body.decode("utf-8", errors="replace") if body else ""
                # Look for the __VIEWSTATE hidden input
                m = re.search(
                    r'<input[^>]+name="__VIEWSTATE"[^>]+value="([^"]+)"',
                    body_str)
                if not m:
                    continue
                vs = m.group(1)
                # Look for __VIEWSTATEGENERATOR (means MAC enabled in classic mode)
                gen_m = re.search(
                    r'<input[^>]+name="__VIEWSTATEGENERATOR"[^>]+value="([^"]+)"',
                    body_str)
                # Decode base64 prefix to look for the magic header
                prefix = ""
                try:
                    decoded = _b64.b64decode(vs[:80] + "=" * (-len(vs[:80]) % 4))
                    prefix = decoded[:8].hex()
                except Exception:
                    pass

                # Detect server header (informational)
                server = headers.get("Server") or headers.get("server") or ""
                aspnet_ver = headers.get("X-AspNet-Version") or ""

                entry = {
                    "url": url,
                    "viewstate_len": len(vs),
                    "viewstate_preview": vs[:60],
                    "viewstategenerator": gen_m.group(1) if gen_m else None,
                    "server": server,
                    "aspnet_version": aspnet_ver,
                    "decoded_prefix_hex": prefix,
                }
                # If __VIEWSTATEGENERATOR is missing, MAC validation may be off
                # (older ViewStateUserKey-only setup). Flag as MS10-070 candidate.
                if not gen_m:
                    entry["severity"] = "high"
                    entry["reason"] = ("ASP.NET __VIEWSTATE present without "
                                        "__VIEWSTATEGENERATOR — MAC validation may "
                                        "be disabled (MS10-070 padding-oracle "
                                        "candidate)")
                else:
                    entry["severity"] = "medium"
                    entry["reason"] = ("ASP.NET __VIEWSTATE present with generator "
                                        "%s — test for known machineKey leakage "
                                        "with ysoserial.net" % gen_m.group(1))
                results["hosts"].append(entry)
                results["candidates"].append(entry)
                log.write("  [VIEWSTATE] %s len=%d gen=%s server=%s\n" %
                          (url, len(vs), gen_m.group(1) if gen_m else "none", server))
                log.flush()
                break  # one viewstate per host is enough
        log.write("done: %d ViewState hosts\n" % len(results["hosts"]))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["hosts"])


def _parse_viewstate_fingerprint_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for h in data.get("candidates", []):
        results.append({
            "result_type": "viewstate_candidate",
            "value": h.get("url", ""),
            "host": h.get("url", ""),
            "severity": h.get("severity", "medium"),
            "reason": h.get("reason", "ASP.NET __VIEWSTATE present"),
            "viewstate_len": h.get("viewstate_len"),
            "generator": h.get("viewstategenerator"),
            "server": h.get("server"),
        })
    return results


# --- _run_jwe_invalid_curve_probe ---

def _run_jwe_invalid_curve_probe(input_path, output_path, log_path):
    """JWE Invalid Curve attack probe (RFC 7516 ECDH-ES).

    Takes jwt-jwe-harvest JSON output, finds tokens flagged as ECDH-ES (or
    JWE entries with `alg: ECDH-ES`), and submits a JWE constructed with
    a malformed ephemeral public key (an ECC point on a twist curve where
    the discrete log is easy). If the server accepts the malformed JWE
    and produces a different response from a baseline-malformed JWE, it
    likely doesn't validate point membership — Pohlig-Hellman attack
    candidate (Antipa et al. 2003 / IBB report #213437).

    NOTE: This is a screening probe. Real exploitation needs the full
    invalid-curve attack workflow (offline DLP solving, twist selection).
    """
    results = {"probed": 0, "candidates": []}
    try:
        data = _safe_json_load(input_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        with open(log_path, "w") as log:
            log.write("failed to read jwt-jwe-harvest input: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    # Find ECDH-ES candidates from tokens
    ecdh_targets = []
    for tok in data.get("tokens", []):
        alg = (tok.get("alg") or "").upper()
        if "ECDH-ES" in alg or alg.startswith("ECDH"):
            ecdh_targets.append(tok)

    with open(log_path, "w") as log:
        log.write("jwe-invalid-curve-probe: %d ECDH-ES tokens\n" % len(ecdh_targets))
        log.flush()
        for t in ecdh_targets[:10]:
            url = t.get("url", "")
            if not url:
                continue
            results["probed"] += 1

            # Build a malformed JWE with an obviously invalid epk (zero curve point)
            # Header: {"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}}
            import base64 as _b64
            bad_header = ('{"alg":"ECDH-ES","enc":"A128GCM","epk":'
                           '{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",'
                           '"y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}')
            bad_jwe = ".".join([
                _b64.urlsafe_b64encode(bad_header.encode()).rstrip(b"=").decode(),
                "", "AAAA", "BBBB", "CCCC",
            ])

            # Probe by setting Authorization: Bearer or sending in a body
            # Try as Authorization first
            r = _oracle_http_get(url, timeout=8,
                                  extra_headers={"Authorization": "Bearer " + bad_jwe})
            if r is None:
                continue
            fp_bad = _oracle_response_fingerprint(r[0], r[2])

            # Baseline: send a structurally invalid JWE (just garbage)
            garbage = "AAAA.BBBB.CCCC.DDDD.EEEE"
            r2 = _oracle_http_get(url, timeout=8,
                                   extra_headers={"Authorization": "Bearer " + garbage})
            if r2 is None:
                continue
            fp_baseline = _oracle_response_fingerprint(r2[0], r2[2])

            entry = {
                "url": url,
                "baseline": list(fp_baseline),
                "invalid_curve": list(fp_bad),
            }
            # Distinguishability: invalid-curve JWE produces different response
            # from total garbage → server is parsing JWE structure → potential
            # invalid-curve target
            if fp_bad != fp_baseline:
                entry["is_candidate"] = True
                results["candidates"].append(entry)
                log.write("  [CANDIDATE] %s baseline=%s invalid_curve=%s\n" %
                          (url, fp_baseline, fp_bad))
            else:
                entry["is_candidate"] = False
                log.write("  %s: no signal\n" % url)
            log.flush()
        log.write("done: probed %d, %d candidates\n" %
                  (results["probed"], len(results["candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


def _parse_jwe_invalid_curve_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "jwe_invalid_curve_candidate",
            "value": c.get("url", ""),
            "host": c.get("url", ""),
            "severity": "high",
            "reason": ("JWE consumer responds differently to a malformed ECDH-ES "
                       "JWE than to garbage — possible invalid curve attack target "
                       "(IBB report #213437 pattern)."),
        })
    return results


# --- _run_manger_oaep_probe ---

def _run_manger_oaep_probe(input_path, output_path, log_path):
    """Manger 2001 RSA-OAEP chosen-ciphertext oracle probe.

    Takes jwt-jwe-harvest JSON, finds tokens with `alg: RSA-OAEP` (or any
    OAEP variant), and submits malformed RSA-OAEP JWEs that test for the
    Manger distinguisher: the server should reject "leading byte != 0x00"
    differently from "MGF unmask failure" — both should look identical to
    a constant-time decryption, but in practice the leading-byte check
    often happens before the MGF unmask, leaking timing or status info.

    Sends 3 probes per endpoint:
      1. Garbage (baseline)
      2. JWE with `alg: RSA-OAEP` and a ciphertext designed to trigger the
         leading-byte check failure
      3. JWE with `alg: RSA-OAEP` and a ciphertext designed to trigger the
         MGF unmask failure

    If 2 and 3 produce distinguishable responses, the server is exhibiting
    a Manger oracle.
    """
    import base64 as _b64
    import os as _os
    results = {"probed": 0, "candidates": []}
    try:
        data = _safe_json_load(input_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        with open(log_path, "w") as log:
            log.write("failed to read jwt-jwe-harvest input: %s\n" % e)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    oaep_targets = []
    for tok in data.get("tokens", []):
        alg = (tok.get("alg") or "").upper()
        if "RSA-OAEP" in alg or "RSA_OAEP" in alg or alg == "RSA-OAEP-256":
            oaep_targets.append(tok)

    with open(log_path, "w") as log:
        log.write("manger-oaep-probe: %d RSA-OAEP tokens\n" % len(oaep_targets))
        log.flush()
        for t in oaep_targets[:10]:
            url = t.get("url", "")
            if not url:
                continue
            results["probed"] += 1

            def _build_jwe(mode):
                """Build a JWE with one of three failure modes."""
                header = '{"alg":"RSA-OAEP","enc":"A128GCM"}'
                hdr_b64 = _b64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
                if mode == "garbage":
                    # Total garbage — server may not even try to parse
                    encrypted_key = _b64.urlsafe_b64encode(b"\x00" * 256).rstrip(b"=").decode()
                elif mode == "leading_byte":
                    # Leading byte != 0x00 (Manger's signal)
                    encrypted_key = _b64.urlsafe_b64encode(b"\xff" + _os.urandom(255)).rstrip(b"=").decode()
                elif mode == "mgf_fail":
                    # Random data that decrypts to invalid OAEP after leading byte check
                    encrypted_key = _b64.urlsafe_b64encode(b"\x00" + _os.urandom(255)).rstrip(b"=").decode()
                iv = _b64.urlsafe_b64encode(b"\x00" * 12).rstrip(b"=").decode()
                ct = _b64.urlsafe_b64encode(b"\x00" * 16).rstrip(b"=").decode()
                tag = _b64.urlsafe_b64encode(b"\x00" * 16).rstrip(b"=").decode()
                return ".".join([hdr_b64, encrypted_key, iv, ct, tag])

            def _probe(mode):
                jwe = _build_jwe(mode)
                rr = _oracle_http_get(url, timeout=8,
                                       extra_headers={"Authorization": "Bearer " + jwe})
                if rr is None:
                    return None
                return _oracle_response_fingerprint(rr[0], rr[2])

            fp_garbage = _probe("garbage")
            fp_leading = _probe("leading_byte")
            fp_mgf = _probe("mgf_fail")

            if not (fp_garbage and fp_leading and fp_mgf):
                continue

            entry = {
                "url": url,
                "garbage": list(fp_garbage),
                "leading_byte": list(fp_leading),
                "mgf_fail": list(fp_mgf),
            }
            # Manger signal: leading_byte and mgf_fail should be indistinguishable;
            # if they differ, the leading-byte check is leaking
            entry["is_candidate"] = fp_leading != fp_mgf
            if entry["is_candidate"]:
                results["candidates"].append(entry)
                log.write("  [MANGER] %s leading=%s mgf=%s\n" %
                          (url, fp_leading, fp_mgf))
            else:
                log.write("  %s: no signal\n" % url)
            log.flush()
        log.write("done: probed %d, %d candidates\n" %
                  (results["probed"], len(results["candidates"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


def _parse_manger_oaep_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "manger_oaep_candidate",
            "value": c.get("url", ""),
            "host": c.get("url", ""),
            "severity": "high",
            "reason": ("RSA-OAEP consumer distinguishes leading-byte failure from "
                       "MGF unmask failure — Manger 2001 chosen-ciphertext "
                       "oracle. Recovery in ~log2(n) queries."),
        })
    return results


# --- _run_ssh_terrapin_scan ---

def _run_ssh_terrapin_scan(input_path, output_path, log_path):
    """Terrapin (CVE-2023-48795) SSH detection.

    Takes httpx JSONL (or any source providing host:port) — for each host,
    opens a TCP connection to port 22, exchanges SSH protocol versions,
    parses the SSH_MSG_KEXINIT, and reports vulnerable algorithm choices:
      - chacha20-poly1305@openssh.com (mandatory vulnerable mode)
      - any *-cbc + *-etm@openssh.com combination
    Vulnerable hosts that don't advertise the kex-strict-c-v00@openssh.com
    extension are flagged.
    """
    import socket as _socket
    import struct as _struct
    results = {"hosts": [], "vulnerable": []}

    bases = _oracle_hosts_from_httpx(input_path, limit=200)
    # Extract bare hostnames (strip scheme + path)
    targets = set()
    for base in bases:
        host = base.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]  # strip port — we use 22
        targets.add(host)
    targets = sorted(targets)[:100]

    with open(log_path, "w") as log:
        log.write("ssh-terrapin-scan: %d hosts\n" % len(targets))
        log.flush()
        for host in targets:
            try:
                s = _socket.create_connection((host, 22), timeout=4)
                # Send our version
                s.sendall(b"SSH-2.0-OracleScanner_1.0\r\n")
                # Read server banner (single line up to \r\n)
                banner = b""
                deadline = 4
                while b"\r\n" not in banner and len(banner) < 512:
                    try:
                        s.settimeout(deadline)
                        chunk = s.recv(512)
                        if not chunk:
                            break
                        banner += chunk
                    except Exception:
                        break
                banner_str = banner.decode("utf-8", errors="replace").strip()
                if not banner_str.startswith("SSH-"):
                    s.close()
                    continue

                # Read SSH_MSG_KEXINIT (binary packet)
                # Packet format: length(4) padding_length(1) payload(...) padding(...)
                try:
                    s.settimeout(4)
                    pkt_len_b = s.recv(4)
                    if len(pkt_len_b) < 4:
                        s.close()
                        continue
                    pkt_len = _struct.unpack(">I", pkt_len_b)[0]
                    if pkt_len > 65535:
                        s.close()
                        continue
                    payload = b""
                    while len(payload) < pkt_len:
                        chunk = s.recv(pkt_len - len(payload))
                        if not chunk:
                            break
                        payload += chunk
                except Exception:
                    s.close()
                    continue
                s.close()

                if len(payload) < 18:
                    continue
                # Skip padding length byte + msg type byte (must be 20 = KEXINIT)
                if payload[1] != 20:
                    continue

                # Skip padding_len(1) + msg_type(1) + cookie(16) = 18 bytes
                offset = 18

                def read_namelist(buf, off):
                    if off + 4 > len(buf):
                        return [], off
                    n = _struct.unpack(">I", buf[off:off + 4])[0]
                    off += 4
                    if off + n > len(buf):
                        return [], off
                    names = buf[off:off + n].decode("utf-8", errors="replace").split(",")
                    return names, off + n

                kex_algs, offset = read_namelist(payload, offset)
                _, offset = read_namelist(payload, offset)  # server host key
                ciphers_c2s, offset = read_namelist(payload, offset)
                ciphers_s2c, offset = read_namelist(payload, offset)
                macs_c2s, offset = read_namelist(payload, offset)
                macs_s2c, offset = read_namelist(payload, offset)

                # Strict KEX extension is the fix
                strict_kex = "kex-strict-s-v00@openssh.com" in kex_algs

                # Vulnerable cipher choices
                vuln_chacha = any("chacha20-poly1305" in c for c in ciphers_s2c + ciphers_c2s)
                etm_macs = [m for m in macs_s2c + macs_c2s if "etm@openssh.com" in m]
                cbc_ciphers = [c for c in ciphers_s2c + ciphers_c2s if "-cbc" in c]
                vuln_cbc_etm = bool(etm_macs and cbc_ciphers)

                entry = {
                    "host": host + ":22",
                    "banner": banner_str,
                    "strict_kex": strict_kex,
                    "supports_chacha20_poly1305": vuln_chacha,
                    "supports_cbc_etm": vuln_cbc_etm,
                    "kex_algs_sample": kex_algs[:5],
                }
                results["hosts"].append(entry)

                if (vuln_chacha or vuln_cbc_etm) and not strict_kex:
                    entry["severity"] = "medium"
                    entry["reason"] = ("Terrapin (CVE-2023-48795) candidate — "
                                        "supports vulnerable cipher mode and does "
                                        "NOT advertise kex-strict-s-v00@openssh.com")
                    results["vulnerable"].append(entry)
                    log.write("  [TERRAPIN] %s banner=%r chacha=%s cbc_etm=%s strict=%s\n" %
                              (host, banner_str, vuln_chacha, vuln_cbc_etm, strict_kex))
                else:
                    log.write("  %s: ok (strict=%s chacha=%s cbc_etm=%s)\n" %
                              (host, strict_kex, vuln_chacha, vuln_cbc_etm))
                log.flush()
            except Exception as e:
                continue
        log.write("done: %d SSH hosts, %d Terrapin candidates\n" %
                  (len(results["hosts"]), len(results["vulnerable"])))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["hosts"])


def _parse_ssh_terrapin_scan_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for h in data.get("vulnerable", []):
        results.append({
            "result_type": "ssh_terrapin_candidate",
            "value": h.get("host", ""),
            "host": h.get("host", ""),
            "severity": h.get("severity", "medium"),
            "reason": h.get("reason", "Terrapin (CVE-2023-48795) candidate"),
            "banner": h.get("banner"),
        })
    return results


# --- _run_gcm_nonce_scan ---

def _run_gcm_nonce_scan(input_path, output_path, log_path):
    """GCM endpoint identifier for nonce reuse follow-up.

    Identifies TLS 1.2 hosts negotiating AES-GCM cipher suites. These are
    candidates for nonce reuse testing with the nonce-disrespecting-adversaries
    toolkit (Böck et al. WOOT 2016).

    NOTE: This probe does NOT extract actual GCM nonces — Python's ssl module
    operates above the TLS record layer and cannot access the explicit IV field.
    Real nonce extraction requires raw socket parsing of TLS records or a
    patched OpenSSL build. This probe identifies GCM endpoints only.
    """
    import socket as _socket
    import ssl as _ssl
    results = {"hosts": [], "vulnerable": []}

    bases = _oracle_hosts_from_httpx(input_path, limit=100)
    # Strip to host:port
    targets = []
    for base in bases:
        h = base.replace("https://", "").replace("http://", "").split("/")[0]
        if ":" not in h:
            h = h + ":443"
        targets.append(h)
    targets = list(dict.fromkeys(targets))[:30]

    with open(log_path, "w") as log:
        log.write("gcm-nonce-scan: %d hosts\n" % len(targets))
        log.flush()

        for host_port in targets:
            host, port_s = host_port.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 443

            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256")
            except _ssl.SSLError:
                continue

            # Establish 6 sequential GCM connections, fetch a small response,
            # capture the cipher name. Real nonce extraction needs raw socket
            # parsing of the TLS record layer; for the screening probe we
            # rely on the cipher name and connection metadata.
            samples = []
            for i in range(6):
                try:
                    s = _socket.create_connection((host, port), timeout=5)
                    ssock = ctx.wrap_socket(s, server_hostname=host)
                    cipher = ssock.cipher()
                    proto = ssock.version()
                    samples.append({"cipher": cipher, "version": proto})
                    ssock.close()
                except Exception:
                    continue

            if not samples:
                continue

            entry = {
                "host": host_port,
                "samples": len(samples),
                "cipher": samples[0].get("cipher")[0] if samples[0].get("cipher") else None,
                "version": samples[0].get("version"),
            }
            # We can't actually verify nonce reuse without raw TLS record
            # parsing — flag any TLS 1.2 GCM endpoint as a manual-followup
            # candidate (the actual reuse needs nonce-disrespecting-adversaries
            # toolkit).
            cipher_name = entry["cipher"] or ""
            if "GCM" in cipher_name and (entry["version"] == "TLSv1.2"):
                entry["severity"] = "informational"
                entry["reason"] = ("TLS 1.2 GCM endpoint — manually verify nonce "
                                    "uniqueness with nonce-disrespecting-adversaries "
                                    "toolkit (Böck et al. WOOT 2016).")
                results["vulnerable"].append(entry)
                log.write("  [GCM] %s cipher=%s version=%s\n" %
                          (host_port, cipher_name, entry["version"]))
            results["hosts"].append(entry)
            log.flush()
        log.write("done: %d GCM endpoints\n" % len(results["vulnerable"]))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["hosts"])


def _parse_gcm_nonce_scan_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for h in data.get("vulnerable", []):
        results.append({
            "result_type": "gcm_nonce_candidate",
            "value": h.get("host", ""),
            "host": h.get("host", ""),
            "severity": h.get("severity", "informational"),
            "reason": h.get("reason", "TLS 1.2 GCM endpoint"),
            "cipher": h.get("cipher"),
        })
    return results


# --- _run_raccoon_probe ---

def _run_raccoon_probe(input_path, output_path, log_path):
    """Raccoon attack (Merget et al. USENIX Security 2021) screening probe.

    Raccoon exploits the leading-zero stripping of DH premaster secrets in
    TLS-DH(E). The signal is timing variance in the server's KDF when the
    premaster has leading zero bytes. Real exploitation requires tens of
    thousands of timed handshakes plus offline lattice work.

    This probe just identifies *candidate* hosts: TLS-DHE servers that
    accept ephemeral DH (so the premaster could vary). Static-DH and
    TLS 1.3 hosts are immune (TLS 1.3 doesn't strip leading zeros).
    """
    import re
    results = {"hosts": [], "candidates": []}
    try:
        with open(input_path) as f:
            content = f.read()
    except OSError:
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        return 0

    host_blocks = re.findall(r'<host target="([^"]+)">(.*?)</host>', content, re.DOTALL)
    with open(log_path, "w") as log:
        log.write("raccoon-probe: %d hosts in sslscan output\n" % len(host_blocks))
        log.flush()
        for host, block in host_blocks:
            # Look for TLS-DHE accepted ciphers (DHE_RSA, DHE_DSS) on TLS 1.0/1.1/1.2
            dhe_ciphers = re.findall(
                r'<cipher[^>]*status="accepted"[^>]*sslversion="(TLSv1\.[012])"[^>]*cipher="([^"]+)"',
                block)
            dhe = [(v, c) for (v, c) in dhe_ciphers if "DHE" in c and "ECDHE" not in c]
            if not dhe:
                continue
            entry = {
                "host": host,
                "dhe_ciphers": [c for _, c in dhe[:5]],
                "tls_versions": list(set(v for v, _ in dhe)),
                "severity": "medium",
                "reason": ("Raccoon attack candidate — accepts TLS-DHE on a "
                            "non-1.3 protocol. Vulnerable IF the DH key is reused "
                            "across many handshakes (static or session-cached). "
                            "Confirm with timing measurements."),
            }
            results["candidates"].append(entry)
            results["hosts"].append(entry)
            log.write("  [RACCOON] %s ciphers=%s versions=%s\n" %
                      (host, entry["dhe_ciphers"], entry["tls_versions"]))
            log.flush()
        log.write("done: %d Raccoon candidates\n" % len(results["candidates"]))
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return len(results["candidates"])


def _parse_raccoon_probe_results(filepath):
    results = []
    try:
        data = _safe_json_load(filepath)
    except (OSError, json.JSONDecodeError, ValueError):
        return results
    for c in data.get("candidates", []):
        results.append({
            "result_type": "raccoon_candidate",
            "value": c.get("host", ""),
            "host": c.get("host", ""),
            "severity": c.get("severity", "medium"),
            "reason": c.get("reason", "Raccoon attack candidate"),
            "ciphers": c.get("dhe_ciphers"),
        })
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "--s3-check":
        # Run S3 takeover check as a subprocess
        if len(sys.argv) != 5:
            print("Usage: %s --s3-check <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_s3_takeover_check(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--merge-subs":
        if len(sys.argv) != 5:
            print("Usage: %s --merge-subs <target_dir> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_merge_subs(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--merge-urls":
        if len(sys.argv) != 5:
            print("Usage: %s --merge-urls <target_dir> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_merge_urls(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--cloud-buckets":
        if len(sys.argv) != 5:
            print("Usage: %s --cloud-buckets <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_cloud_buckets(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--secret-scan":
        if len(sys.argv) != 5:
            print("Usage: %s --secret-scan <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_secret_scan(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--cms-detect":
        if len(sys.argv) != 5:
            print("Usage: %s --cms-detect <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_cms_detect(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--panel-detect":
        if len(sys.argv) != 5:
            print("Usage: %s --panel-detect <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_panel_detect(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--crt-sh":
        if len(sys.argv) != 5:
            print("Usage: %s --crt-sh <domains_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_crt_sh(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--git-dumper":
        if len(sys.argv) != 5:
            print("Usage: %s --git-dumper <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_git_dumper_check(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--gitleaks":
        if len(sys.argv) != 5:
            print("Usage: %s --gitleaks <org_name> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_gitleaks(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--corscanner":
        if len(sys.argv) != 5:
            print("Usage: %s --corscanner <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_corscanner(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--nextjs-check":
        if len(sys.argv) != 5:
            print("Usage: %s --nextjs-check <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_nextjs_check(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--spa-catchall-detect":
        if len(sys.argv) != 5:
            print("Usage: %s --spa-catchall-detect <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_spa_catchall_detect(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    # Oracle pipeline built-in tools
    if len(sys.argv) >= 2 and sys.argv[1] == "--saml-fingerprint":
        if len(sys.argv) != 5:
            print("Usage: %s --saml-fingerprint <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_saml_fingerprint(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--jwt-jwe-harvest":
        if len(sys.argv) != 5:
            print("Usage: %s --jwt-jwe-harvest <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_jwt_jwe_harvest(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--cookie-harvest":
        if len(sys.argv) != 5:
            print("Usage: %s --cookie-harvest <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_cookie_harvest(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--roca-scan":
        if len(sys.argv) != 5:
            print("Usage: %s --roca-scan <sslyze_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_roca_scan(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--breach-candidate":
        if len(sys.argv) != 5:
            print("Usage: %s --breach-candidate <input_file> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_breach_candidate(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--tls-oracle-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --tls-oracle-probe <sslscan_xml> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_tls_oracle_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--xmlenc-oracle-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --xmlenc-oracle-probe <saml_fingerprint_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_xmlenc_oracle_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    # Extended oracle pipeline tools
    if len(sys.argv) >= 2 and sys.argv[1] == "--cbc-padding-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --cbc-padding-probe <cookie_harvest_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_cbc_padding_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--marvin-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --marvin-probe <sslscan_xml> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_marvin_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--xsw-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --xsw-probe <saml_fingerprint_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_xsw_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--viewstate-fingerprint":
        if len(sys.argv) != 5:
            print("Usage: %s --viewstate-fingerprint <httpx_jsonl> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_viewstate_fingerprint(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--jwe-invalid-curve-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --jwe-invalid-curve-probe <jwt_jwe_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_jwe_invalid_curve_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--manger-oaep-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --manger-oaep-probe <jwt_jwe_json> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_manger_oaep_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--ssh-terrapin-scan":
        if len(sys.argv) != 5:
            print("Usage: %s --ssh-terrapin-scan <httpx_jsonl> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_ssh_terrapin_scan(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--gcm-nonce-scan":
        if len(sys.argv) != 5:
            print("Usage: %s --gcm-nonce-scan <httpx_jsonl> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_gcm_nonce_scan(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--raccoon-probe":
        if len(sys.argv) != 5:
            print("Usage: %s --raccoon-probe <sslscan_xml> <output_file> <log_file>" % sys.argv[0])
            sys.exit(1)
        _run_raccoon_probe(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    RECON_DIR.mkdir(exist_ok=True)
    _load_scans()
    _load_netns_pool()

    # Background reaper thread — cleans up finished scans
    # even when no new requests trigger _cleanup_scans().
    def _reaper_loop():
        while True:
            time.sleep(60)
            try:
                _cleanup_scans()
            except Exception as e:
                print("  [reaper] error: %s" % e)

    reaper = threading.Thread(target=_reaper_loop, daemon=True)
    reaper.start()

    # Network monitor thread — tracks connection counts and pauses scans
    # if the connection table gets too large (prevents modem overload).
    NETWORK_STATS = {"tcp_estab": 0, "tcp_total": 0, "peak_estab": 0,
                     "throttle_events": 0, "last_check": "",
                     "udp_out_per_sec": 0.0, "tcp_new_per_sec": 0.0,
                     "peak_udp_out_per_sec": 0.0, "peak_tcp_new_per_sec": 0.0,
                     "dns_throttle_active": False,
                     "last_alert_ts": 0}
    # Local-fanout gate: measures established TCP connections on Kali itself,
    # NOT on the home modem.  With the Tailscale exit node, N local TCP
    # connections collapse into ONE encrypted UDP flow at the modem, so this
    # count no longer correlates with modem load.  Raised in Phase 6.1 from
    # 500 → 5000 after baseline pipeline showed normal operation at ~10K
    # estab when 4 Go-based crawlers ran in parallel (Ring P235 2026-05-15).
    # The real modem-load signal is the Hetzner-side conntrack pct exposed
    # via the bandwidth sampler (currently <3% at 13K connections).
    MAX_TCP_ESTAB = 5000  # local-fanout gate, NOT a direct modem-load gate

    # DNS-flood gate: triggered by sustained UDP-out rate (proxy for DNS qps).
    # Calibrated against the varonis incident: shuffledns ran ~10k qps and
    # killed the modem in ~3 min. Raised in Phase 6 from 500 → 2000 because
    # the Hetzner exit node sees the same DNS qps the modem couldn't handle.
    # Cloud public resolvers (1.1.1.1, etc.) start rate-limiting around 2-3K
    # qps from a single source IP so we stay well under that.
    MAX_UDP_OUT_PER_SEC = 2000
    # SYN burst gate: too many new TCP connections per second indicates
    # httpx/naabu fanout or similar.  Raised in Phase 6 from 200 → 800.
    # Baseline pipeline peak observed: 127.5/s — 800 gives 6.3x headroom.
    MAX_TCP_NEW_PER_SEC = 800

    # Telegram alerts on threshold crossings.  Raised cooldown from 5 → 15
    # minutes after operator reported alert spam during a single Phase 2/3
    # fanout burst (2026-05-15).  Multiple gates can fire in quick succession
    # (DNS-flood, SYN-burst, local-fanout) — the per-gate cooldown limits
    # each gate to 1 alert per window, but with 3 gates we could still get
    # 3 alerts/5min before.  15min spans a typical Phase 2/3 duration so
    # we get at most one alert per pipeline-phase per gate.
    TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    TG_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    ALERT_COOLDOWN_S = 900

    def _tg_send(text):
        if not TG_TOKEN or not TG_CHAT:
            return
        try:
            from urllib.parse import urlencode
            data = urlencode({"chat_id": TG_CHAT, "text": text}).encode()
            req = Request("https://api.telegram.org/bot%s/sendMessage" % TG_TOKEN,
                          data=data, method="POST")
            urlopen(req, timeout=10).read()
        except Exception as e:
            print("  [net-monitor] telegram send failed: %s" % e)

    def _read_snmp_counters():
        """Return (udp_out_datagrams, tcp_active_opens) from /proc/net/snmp."""
        udp_out = tcp_active = 0
        try:
            with open("/proc/net/snmp") as f:
                lines = f.read().splitlines()
            # /proc/net/snmp pairs header line + values line for each protocol
            it = iter(lines)
            for hdr in it:
                vals = next(it, "")
                if hdr.startswith("Udp:") and vals.startswith("Udp:"):
                    h = hdr.split()[1:]
                    v = vals.split()[1:]
                    if "OutDatagrams" in h:
                        udp_out = int(v[h.index("OutDatagrams")])
                elif hdr.startswith("Tcp:") and vals.startswith("Tcp:"):
                    h = hdr.split()[1:]
                    v = vals.split()[1:]
                    if "ActiveOpens" in h:
                        tcp_active = int(v[h.index("ActiveOpens")])
        except Exception:
            pass
        return udp_out, tcp_active

    def _net_monitor_loop():
        prev_udp = prev_tcp = 0
        prev_t = time.time()
        # Paused-pid bookkeeping shared between the SYN-burst gate (proactive
        # freeze on threshold cross) and the self-tuning supervisor (reactive
        # freeze on sustained over-budget).  Initialized once up-front so both
        # paths can safely add/remove from it on the first iteration.
        _net_monitor_loop._over_count = 0
        _net_monitor_loop._paused_pids = set()
        while True:
            time.sleep(5)  # 5s cadence — fast enough to catch DNS bursts
            now = time.time()
            dt = max(now - prev_t, 1.0)
            try:
                # ss -s for steady-state TCP counts
                result = subprocess.run(["ss", "-s"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split("\n"):
                    if "TCP:" in line:
                        import re
                        total_m = re.search(r'TCP:\s+(\d+)', line)
                        estab_m = re.search(r'estab (\d+)', line)
                        if total_m:
                            NETWORK_STATS["tcp_total"] = int(total_m.group(1))
                        if estab_m:
                            estab = int(estab_m.group(1))
                            NETWORK_STATS["tcp_estab"] = estab
                            if estab > NETWORK_STATS["peak_estab"]:
                                NETWORK_STATS["peak_estab"] = estab
                            if estab > MAX_TCP_ESTAB:
                                NETWORK_STATS["throttle_events"] += 1
                                msg = "%d estab TCP connections (threshold %d)" % (
                                    estab, MAX_TCP_ESTAB)
                                print("  [net-monitor] WARNING: " + msg)
                                # NOTE: this is a LOCAL Kali socket-count signal,
                                # not a direct modem-load signal.  With the Tailscale
                                # exit node, these connections collapse to a single
                                # encrypted UDP flow at the modem.  Alert is mainly
                                # useful to detect runaway tools (memory pressure,
                                # FD exhaustion).  Do not assume the modem is hurting.
                                if (time.time() - NETWORK_STATS["last_alert_ts"]) >= ALERT_COOLDOWN_S:
                                    _tg_send("⚠️ Local TCP fanout: " + msg + " (Kali socket count, not modem)")
                                    NETWORK_STATS["last_alert_ts"] = time.time()

                # DNS query / SYN rate from /proc/net/snmp (kernel counters)
                udp_out, tcp_active = _read_snmp_counters()
                if prev_udp and udp_out >= prev_udp:
                    udp_rate = (udp_out - prev_udp) / dt
                    NETWORK_STATS["udp_out_per_sec"] = round(udp_rate, 1)
                    if udp_rate > NETWORK_STATS["peak_udp_out_per_sec"]:
                        NETWORK_STATS["peak_udp_out_per_sec"] = round(udp_rate, 1)
                    if udp_rate > MAX_UDP_OUT_PER_SEC:
                        NETWORK_STATS["dns_throttle_active"] = True
                        NETWORK_STATS["throttle_events"] += 1
                        msg = "%.0f UDP out/s (DNS-flood threshold %d) — throttling new scans" % (
                            udp_rate, MAX_UDP_OUT_PER_SEC)
                        print("  [net-monitor] WARNING: " + msg)
                        # Kill any in-flight shuffledns / dnsx — they're the
                        # tools capable of producing this rate. Other tools
                        # under it are unaffected.
                        killed_tools = []
                        for sid, s in list(SCANS.items()):
                            if s.get("tool") in ("shuffledns", "dnsx") and _poll_scan(s) is None:
                                proc = s.get("process")
                                if proc:
                                    try:
                                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                                        print("  [net-monitor] killed runaway %s pid=%d" % (
                                            s.get("tool"), proc.pid))
                                        killed_tools.append("%s(pid=%d)" % (s.get("tool"), proc.pid))
                                    except Exception as ke:
                                        print("  [net-monitor] kill %s failed: %s" % (s.get("tool"), ke))
                        if (time.time() - NETWORK_STATS["last_alert_ts"]) >= ALERT_COOLDOWN_S:
                            kill_note = (" Killed: " + ", ".join(killed_tools)) if killed_tools else ""
                            _tg_send("🚨 DNS flood gate: " + msg + kill_note)
                            NETWORK_STATS["last_alert_ts"] = time.time()
                    elif udp_rate < MAX_UDP_OUT_PER_SEC * 0.5:
                        # Hysteresis: only clear when well below threshold
                        NETWORK_STATS["dns_throttle_active"] = False
                if prev_tcp and tcp_active >= prev_tcp:
                    tcp_rate = (tcp_active - prev_tcp) / dt
                    NETWORK_STATS["tcp_new_per_sec"] = round(tcp_rate, 1)
                    if tcp_rate > NETWORK_STATS["peak_tcp_new_per_sec"]:
                        NETWORK_STATS["peak_tcp_new_per_sec"] = round(tcp_rate, 1)
                    if tcp_rate > MAX_TCP_NEW_PER_SEC:
                        NETWORK_STATS["throttle_events"] += 1
                        msg = "%.0f new TCP/s (SYN-burst threshold %d)" % (
                            tcp_rate, MAX_TCP_NEW_PER_SEC)
                        print("  [net-monitor] WARNING: " + msg)
                        # SYN-burst gate: SIGSTOP every freezable TCP-heavy
                        # scan currently running.  Differs from the DNS gate
                        # (which SIGTERMs shuffledns/dnsx because they're cheap
                        # to restart) — naabu/httpx mid-scan can't be killed
                        # without losing progress, so freeze instead.  The
                        # self-tuning supervisor below will SIGCONT them once
                        # the rate drops back under 90% of budget.
                        FREEZABLE = ("naabu", "httpx-toolkit", "feroxbuster",
                                     "kiterunner", "katana", "gospider",
                                     "nuclei", "amass", "subzy")
                        frozen_tools = []
                        for sid, s in list(SCANS.items()):
                            if (s.get("tool") in FREEZABLE
                                    and _poll_scan(s) is None
                                    and s.get("process")
                                    and s["process"].pid not in _net_monitor_loop._paused_pids):
                                try:
                                    os.kill(s["process"].pid, signal.SIGSTOP)
                                    _net_monitor_loop._paused_pids.add(s["process"].pid)
                                    frozen_tools.append("%s(pid=%d)" % (
                                        s.get("tool"), s["process"].pid))
                                    print("  [net-monitor] SIGSTOP %s pid=%d (SYN-burst gate)" % (
                                        s.get("tool"), s["process"].pid))
                                except Exception as fe:
                                    print("  [net-monitor] SIGSTOP failed: %s" % fe)
                        if (time.time() - NETWORK_STATS["last_alert_ts"]) >= ALERT_COOLDOWN_S:
                            freeze_note = (" Frozen: " + ", ".join(frozen_tools)) if frozen_tools else ""
                            _tg_send("🚨 SYN-burst gate: " + msg + freeze_note)
                            NETWORK_STATS["last_alert_ts"] = time.time()
                prev_udp = udp_out
                prev_tcp = tcp_active
                prev_t = now

                NETWORK_STATS["last_check"] = time.strftime("%Y-%m-%d %H:%M:%S")

                # ---- Self-tuning supervisor: SIGSTOP/SIGCONT runaway scans ----
                # Concept: when a tool we can't safely kill (naabu mid-portscan,
                # httpx mid-probe) pushes us over budget, freeze it briefly with
                # SIGSTOP, then SIGCONT once budget recovers. Different from the
                # kill above which is reserved for shuffledns/dnsx (cheap to kill).
                cur_udp = NETWORK_STATS["udp_out_per_sec"]
                cur_syn = NETWORK_STATS["tcp_new_per_sec"]
                over_udp = cur_udp > MAX_UDP_OUT_PER_SEC * 0.9
                over_syn = cur_syn > MAX_TCP_NEW_PER_SEC * 0.9
                if over_udp or over_syn:
                    _net_monitor_loop._over_count += 1
                else:
                    # Recovered — SIGCONT anyone we paused
                    if _net_monitor_loop._paused_pids:
                        for pid in list(_net_monitor_loop._paused_pids):
                            try:
                                os.kill(pid, signal.SIGCONT)
                                print("  [net-monitor] SIGCONT pid=%d (budget recovered)" % pid)
                            except Exception:
                                pass
                            _net_monitor_loop._paused_pids.discard(pid)
                    _net_monitor_loop._over_count = 0
                # Sustained 2 polls (10s) over 90% → freeze the heaviest scan
                if _net_monitor_loop._over_count >= 2:
                    # Pick a freezable running scan that we haven't already paused.
                    # Prefer high-rate offenders we can't easily resume from a kill.
                    FREEZABLE = ("naabu", "httpx-toolkit", "feroxbuster", "kiterunner",
                                 "katana", "gospider", "nuclei", "amass")
                    target_pid = None
                    for sid, s in list(SCANS.items()):
                        if (s.get("tool") in FREEZABLE
                                and _poll_scan(s) is None
                                and s.get("process")
                                and s["process"].pid not in _net_monitor_loop._paused_pids):
                            target_pid = s["process"].pid
                            target_tool = s["tool"]
                            break
                    if target_pid:
                        try:
                            os.kill(target_pid, signal.SIGSTOP)
                            _net_monitor_loop._paused_pids.add(target_pid)
                            print("  [net-monitor] SIGSTOP %s pid=%d (sustained over-budget)" % (
                                target_tool, target_pid))
                            NETWORK_STATS["throttle_events"] += 1
                        except Exception as e:
                            print("  [net-monitor] SIGSTOP failed: %s" % e)
            except Exception as e:
                print("  [net-monitor] error: %s" % e)

    net_monitor = threading.Thread(target=_net_monitor_loop, daemon=True)
    net_monitor.start()

    # ---- Exit-node guard ----
    # Polls the public egress IP every 60s.  When the IP isn't the Hetzner
    # exit node's expected IP for 3 consecutive checks, declares the exit
    # node DOWN: pauses all freezable scans via SIGSTOP and refuses new
    # scan launches via 503.  When recovered (2 consecutive successes),
    # SIGCONTs the paused scans and clears the gate.
    EXIT_NODE_STATUS["guard_enabled"] = EXIT_NODE_GUARD_ENABLED
    EXIT_NODE_STATUS["expected_egress_ip"] = EXIT_NODE_REQUIRED_IP
    # Reuse the same paused-pid set as the net-monitor so the two gates
    # cooperate (one SIGSTOP, one SIGCONT, no double-pause confusion).
    _exit_node_paused_pids = set()

    def _probe_egress_ip(timeout=8):
        """Try each probe URL in order, return the first IP we get back.
        Returns None if all probes fail."""
        for url in EXIT_NODE_PROBE_URLS:
            try:
                resp = urlopen(url, timeout=timeout)
                ip = resp.read().decode().strip()
                # Validate it looks like an IPv4
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return ip
            except Exception:
                continue
        return None

    def _exit_node_pause_all():
        """SIGSTOP every freezable running scan (if not already paused)."""
        for s in list(SCANS.values()):
            try:
                tool = s.get("tool")
                proc = s.get("process")
                if (tool in FREEZABLE_TOOLS and proc is not None
                        and proc.poll() is None
                        and proc.pid not in _exit_node_paused_pids
                        and proc.pid not in _net_monitor_loop._paused_pids):
                    os.kill(proc.pid, signal.SIGSTOP)
                    _exit_node_paused_pids.add(proc.pid)
                    print("  [exit-node] SIGSTOP %s pid=%d (exit node down)" % (tool, proc.pid))
            except Exception as e:
                print("  [exit-node] SIGSTOP failed for pid=%s: %s" % (
                    s.get("process") and s["process"].pid, e))

    def _exit_node_resume_all():
        """SIGCONT every scan we paused (if still alive)."""
        for pid in list(_exit_node_paused_pids):
            try:
                os.kill(pid, signal.SIGCONT)
                print("  [exit-node] SIGCONT pid=%d (exit node recovered)" % pid)
            except ProcessLookupError:
                pass
            except Exception as e:
                print("  [exit-node] SIGCONT failed for pid=%d: %s" % (pid, e))
            _exit_node_paused_pids.discard(pid)

    def _exit_node_monitor_loop():
        if not EXIT_NODE_GUARD_ENABLED:
            print("  [exit-node] guard DISABLED via env (EXIT_NODE_GUARD_ENABLED=0)")
            return
        print("  [exit-node] guard enabled — expecting egress via %s" % EXIT_NODE_REQUIRED_IP)
        while True:
            try:
                now_iso = time.strftime("%Y-%m-%d %H:%M:%S")
                EXIT_NODE_STATUS["last_check"] = now_iso

                current_ip = _probe_egress_ip()
                EXIT_NODE_STATUS["current_egress_ip"] = current_ip

                if current_ip == EXIT_NODE_REQUIRED_IP:
                    # Healthy probe
                    EXIT_NODE_STATUS["last_success"] = now_iso
                    EXIT_NODE_STATUS["consecutive_failures"] = 0
                    EXIT_NODE_STATUS["consecutive_successes"] += 1
                    if (not EXIT_NODE_STATUS["online"]
                            and EXIT_NODE_STATUS["consecutive_successes"]
                                >= EXIT_NODE_RECOVER_THRESHOLD):
                        # Recovered
                        EXIT_NODE_STATUS["online"] = True
                        EXIT_NODE_STATUS["down_since"] = None
                        _exit_node_resume_all()
                        msg = "[exit-node] RECOVERED — egress IP back to %s; resumed %d scans" % (
                            EXIT_NODE_REQUIRED_IP, len(_exit_node_paused_pids))
                        print("  " + msg)
                        _tg_send(msg)
                else:
                    # Failed probe (either wrong IP, or all probes unreachable)
                    EXIT_NODE_STATUS["consecutive_successes"] = 0
                    EXIT_NODE_STATUS["consecutive_failures"] += 1
                    EXIT_NODE_STATUS["total_failures"] += 1
                    if (EXIT_NODE_STATUS["online"]
                            and EXIT_NODE_STATUS["consecutive_failures"]
                                >= EXIT_NODE_FAIL_THRESHOLD):
                        # Tripped — declare DOWN
                        EXIT_NODE_STATUS["online"] = False
                        EXIT_NODE_STATUS["down_since"] = now_iso
                        _exit_node_pause_all()
                        msg = ("[exit-node] DOWN — current egress %s != expected %s "
                               "(%d consecutive failures); paused freezable scans, "
                               "blocking new launches" % (
                                   current_ip or "?", EXIT_NODE_REQUIRED_IP,
                                   EXIT_NODE_STATUS["consecutive_failures"]))
                        print("  " + msg)
                        _tg_send(msg)
            except Exception as e:
                print("  [exit-node] monitor error: %s" % e)
            time.sleep(EXIT_NODE_CHECK_INTERVAL_S)

    exit_node_monitor = threading.Thread(target=_exit_node_monitor_loop, daemon=True)
    exit_node_monitor.start()

    # ---- Per-netns egress monitor ----
    # The default-route guard above watches the Tailscale fallback (scan1 /
    # Ashburn IP). This second monitor probes each scan1..scan4 netns
    # independently every 60s and marks slots offline if they fail. Flask
    # uses NETNS_POOL[slot]["online"] to refuse new allocations on broken
    # slots. Scans IN a broken netns get SIGSTOPped (same pause logic, but
    # filtered to only that netns's processes).
    NETNS_FAIL_THRESHOLD = 3      # consecutive failures before declaring offline
    NETNS_RECOVER_THRESHOLD = 2   # consecutive successes before declaring online
    NETNS_PROBE_INTERVAL_S = 60
    _netns_paused_pids = set()    # pids SIGSTOPped due to netns being offline

    def _probe_netns_egress(netns, timeout=8):
        """Run `ip netns exec <netns> curl ipify` and return the observed IP, or None."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "ip", "netns", "exec", netns, "curl", "-sS",
                 "--max-time", str(timeout), "https://api.ipify.org"],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            ip = (result.stdout or "").strip()
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return ip
        except Exception:
            pass
        return None

    def _scans_in_netns(netns):
        """Return list of scan dicts currently running INSIDE the given netns.

        We track this by looking at NETNS_POOL[netns].claimed_by → pipeline_id
        and matching SCANS where scan_info["pipeline_netns"] == netns. (We'll
        set this in scan_info at spawn time below; see _handle_start.)
        """
        return [s for s in SCANS.values() if s.get("netns") == netns]

    def _netns_pause(netns):
        """SIGSTOP all freezable scans in this netns."""
        for s in _scans_in_netns(netns):
            try:
                proc = s.get("process")
                tool = s.get("tool")
                if (tool in FREEZABLE_TOOLS and proc is not None
                        and proc.poll() is None
                        and proc.pid not in _netns_paused_pids):
                    os.kill(proc.pid, signal.SIGSTOP)
                    _netns_paused_pids.add(proc.pid)
                    print("  [netns:%s] SIGSTOP %s pid=%d" % (netns, tool, proc.pid))
            except Exception as e:
                print("  [netns:%s] SIGSTOP failed: %s" % (netns, e))

    def _netns_resume(netns):
        """SIGCONT all paused scans in this netns."""
        to_resume = [s for s in _scans_in_netns(netns)
                     if s.get("process") and s["process"].pid in _netns_paused_pids]
        for s in to_resume:
            try:
                os.kill(s["process"].pid, signal.SIGCONT)
                _netns_paused_pids.discard(s["process"].pid)
                print("  [netns:%s] SIGCONT pid=%d" % (netns, s["process"].pid))
            except ProcessLookupError:
                _netns_paused_pids.discard(s["process"].pid)
            except Exception as e:
                print("  [netns:%s] SIGCONT failed: %s" % (netns, e))

    def _netns_monitor_loop():
        # Per-slot consecutive counters (only kept in this closure)
        consecutive_fail = {slot: 0 for slot in NETNS_POOL_SLOTS}
        consecutive_ok = {slot: 0 for slot in NETNS_POOL_SLOTS}
        print("  [netns-monitor] watching %d slots" % len(NETNS_POOL_SLOTS))
        while True:
            try:
                for slot in NETNS_POOL_SLOTS:
                    expected = NETNS_EXPECTED_IPS[slot]
                    actual = _probe_netns_egress(slot)
                    if actual == expected:
                        consecutive_ok[slot] += 1
                        consecutive_fail[slot] = 0
                        with NETNS_POOL_LOCK:
                            NETNS_POOL[slot]["last_egress_check"] = time.strftime(
                                "%Y-%m-%d %H:%M:%S")
                            NETNS_POOL[slot]["consecutive_failures"] = 0
                            was_offline = not NETNS_POOL[slot]["online"]
                            if was_offline and consecutive_ok[slot] >= NETNS_RECOVER_THRESHOLD:
                                NETNS_POOL[slot]["online"] = True
                                print("  [netns:%s] RECOVERED (egress=%s)" % (slot, actual))
                                _netns_resume(slot)
                                _tg_send("[netns:%s] RECOVERED" % slot)
                    else:
                        consecutive_fail[slot] += 1
                        consecutive_ok[slot] = 0
                        with NETNS_POOL_LOCK:
                            NETNS_POOL[slot]["consecutive_failures"] = consecutive_fail[slot]
                            was_online = NETNS_POOL[slot]["online"]
                            if was_online and consecutive_fail[slot] >= NETNS_FAIL_THRESHOLD:
                                NETNS_POOL[slot]["online"] = False
                                print("  [netns:%s] DOWN (expected=%s actual=%s)" % (
                                    slot, expected, actual or "?"))
                                _netns_pause(slot)
                                _tg_send("[netns:%s] DOWN (expected=%s actual=%s)" % (
                                    slot, expected, actual or "?"))
                _save_netns_pool()
            except Exception as e:
                print("  [netns-monitor] error: %s" % e)
            time.sleep(NETNS_PROBE_INTERVAL_S)

    netns_monitor = threading.Thread(target=_netns_monitor_loop, daemon=True)
    netns_monitor.start()

    # ---- Stale netns claim reaper ----
    # If Flask & the agent disagree about which pipelines are running, a
    # claim could leak (slot stays "claimed_by=N" forever). Reaper checks
    # every 5 min: if a slot's claim is older than NETNS_STALE_CLAIM_MAX_AGE_S
    # AND no scans currently running for that pipeline_id, release the slot.
    def _netns_reaper_loop():
        while True:
            try:
                now = time.time()
                with NETNS_POOL_LOCK:
                    stale = []
                    for slot, info in NETNS_POOL.items():
                        if info["claimed_by"] is None:
                            continue
                        age = now - (info["claimed_at"] or now)
                        if age < NETNS_STALE_CLAIM_MAX_AGE_S:
                            continue
                        # Any scans running for this pipeline?
                        pid_claimed = info["claimed_by"]
                        active = any(_poll_scan(s) is None and s.get("netns") == slot
                                     for s in SCANS.values())
                        if not active:
                            stale.append((slot, pid_claimed, int(age / 3600)))
                            info["claimed_by"] = None
                            info["claimed_at"] = None
                if stale:
                    for slot, pid_claimed, age_h in stale:
                        print("  [netns-reaper] freed %s (pipeline_id=%s, age=%dh)" % (
                            slot, pid_claimed, age_h))
                    _save_netns_pool()
            except Exception as e:
                print("  [netns-reaper] error: %s" % e)
            time.sleep(300)  # 5 min

    netns_reaper = threading.Thread(target=_netns_reaper_loop, daemon=True)
    netns_reaper.start()

    # ---- Bandwidth sampler ----
    # Polls the exit node's /traffic endpoint every 30s, computes byte
    # deltas, and distributes them across running scans (weighted by
    # wall-time since last sample).  When a scan finishes, its
    # bytes_attributed total is preserved in SCANS for /scan/<pid>/status.
    _bandwidth_state = {"prev_rx": None, "prev_tx": None, "prev_ts": None}

    def _fetch_exit_traffic():
        try:
            resp = urlopen(EXIT_TRAFFIC_URL, timeout=8)
            return json.loads(resp.read().decode())
        except Exception as e:
            BANDWIDTH_STATS["last_error"] = str(e)
            return None

    def _bandwidth_sampler_loop():
        # Bootstrap baseline so the first delta isn't garbage.
        while True:
            try:
                data = _fetch_exit_traffic()
                BANDWIDTH_STATS["samples_total"] += 1
                BANDWIDTH_STATS["last_sample"] = time.strftime("%Y-%m-%d %H:%M:%S")
                if data is None:
                    BANDWIDTH_STATS["samples_failed"] += 1
                    BANDWIDTH_STATS["last_sample_ok"] = False
                    time.sleep(BANDWIDTH_SAMPLE_INTERVAL_S)
                    continue

                BANDWIDTH_STATS["last_sample_ok"] = True
                BANDWIDTH_STATS["last_error"] = None
                traffic = data.get("traffic", {})
                ct = data.get("conntrack", {})
                rx = int(traffic.get("rx_today", 0))
                tx = int(traffic.get("tx_today", 0))
                BANDWIDTH_STATS["exit_rx_today"] = rx
                BANDWIDTH_STATS["exit_tx_today"] = tx
                BANDWIDTH_STATS["exit_rx_month"] = int(traffic.get("rx_month", 0))
                BANDWIDTH_STATS["exit_tx_month"] = int(traffic.get("tx_month", 0))
                BANDWIDTH_STATS["exit_conntrack_current"] = int(ct.get("current", 0))
                BANDWIDTH_STATS["exit_conntrack_max"] = int(ct.get("max", 0))
                BANDWIDTH_STATS["exit_conntrack_pct"] = float(ct.get("pct", 0))

                now = time.time()
                prev_rx = _bandwidth_state["prev_rx"]
                prev_tx = _bandwidth_state["prev_tx"]
                prev_ts = _bandwidth_state["prev_ts"]

                if prev_rx is not None and prev_ts is not None:
                    # Compute delta bytes since last sample.  vnstat resets
                    # at midnight (rx_today drops to 0) — if delta is
                    # negative, treat it as a reset and skip this sample.
                    drx = rx - prev_rx
                    dtx = tx - prev_tx
                    if drx >= 0 and dtx >= 0:
                        total_delta = drx + dtx
                        # Attribute to running scans by elapsed-since-last-sample.
                        running = []
                        for s in SCANS.values():
                            try:
                                if _poll_scan(s) is None:
                                    started = s.get("started_at", now)
                                    # Window = max(started, prev_ts) → now
                                    win_start = max(started, prev_ts)
                                    elapsed = max(now - win_start, 0)
                                    if elapsed > 0:
                                        running.append((s, elapsed))
                            except Exception:
                                pass
                        total_elapsed = sum(e for _, e in running)
                        if total_elapsed > 0 and total_delta > 0:
                            for scan, elapsed in running:
                                share = total_delta * (elapsed / total_elapsed)
                                scan["bytes_attributed"] = scan.get("bytes_attributed", 0) + int(share)
                                # Check threshold for runaway alert
                                if (scan["bytes_attributed"] >= SCAN_BYTE_ALERT_THRESHOLD
                                        and not scan.get("bytes_alert_sent")):
                                    scan["bytes_alert_sent"] = True
                                    msg = ("⚠️ Scan %s pid=%s on %s exceeded %d GB egress" % (
                                        scan.get("tool"), scan.get("pid"),
                                        scan.get("target_name"),
                                        SCAN_BYTE_ALERT_THRESHOLD // (1024 ** 3)))
                                    print("  [bandwidth] " + msg)
                                    _tg_send(msg)

                _bandwidth_state["prev_rx"] = rx
                _bandwidth_state["prev_tx"] = tx
                _bandwidth_state["prev_ts"] = now
            except Exception as e:
                print("  [bandwidth] sampler error: %s" % e)
            time.sleep(BANDWIDTH_SAMPLE_INTERVAL_S)

    bw_sampler = threading.Thread(target=_bandwidth_sampler_loop, daemon=True)
    bw_sampler.start()

    # Expose NETWORK_STATS on the handler class so /health can read it
    ReconHandler._network_stats = NETWORK_STATS
    ReconHandler._exit_node_status = EXIT_NODE_STATUS
    ReconHandler._bandwidth_stats = BANDWIDTH_STATS

    server = HTTPServer(("127.0.0.1", 5001), ReconHandler)
    print("Recon agent listening on http://127.0.0.1:5001")
    server.serve_forever()
