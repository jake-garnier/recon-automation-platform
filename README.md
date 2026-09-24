# Recon Automation Platform

A self-hosted security-recon platform that ingests bug-bounty program scopes, runs a dependency-ordered pipeline of ~40 reconnaissance tools against in-scope targets, and organizes the results for systematic analysis. Built as a two-process system — a Flask web app for orchestration/UI and a stdlib-only host agent that manages scan subprocesses — with all scan traffic tunneled through a pool of WireGuard exit nodes for clean, high-capacity egress.

> This is a personal infrastructure/automation project. All target-specific data, findings, and credentials have been removed; the code here is the engine, not the output.

## Highlights

- **Two-process architecture.** A Dockerized Flask app ([`src/app/`](src/app/)) orchestrates pipelines and serves the dashboard; a zero-dependency host agent ([`src/daemons/recon_agent.py`](src/daemons/recon_agent.py)) spawns and supervises the actual security tools. They communicate over a small HTTP protocol, so the agent can run outside the container with direct access to host-installed tooling.
- **Dependency-ordered pipeline.** ~40 tools across 5 phases (discovery → probing → crawling → analysis → exploitation). A `TOOL_DEPS` graph auto-resolves each tool's input from upstream outputs, with fallback when an intermediate step is skipped. Phases advance automatically; tools that can't run are recorded as "skipped" so dependents fire immediately.
- **Parallel WireGuard egress pool.** Scan traffic is routed through a pool of exit nodes, each reached via a dedicated WireGuard tunnel inside its own Linux network namespace ([`hetzner-exit-node/`](hetzner-exit-node/)). This gives ~100× the conntrack headroom of a consumer connection and lets up to 4 pipelines run in parallel, each pinned to its own egress. An exit-node guard refuses to scan if traffic isn't egressing through the expected node.
- **Resilient process supervision.** Per-tool memory limits (RSS reaper), per-tool runtime budgets, concurrency gating for heavy tools, and a network monitor that pauses new scans when connection thresholds are exceeded. Scan state is persisted to disk so running scans are re-adopted after an agent restart.
- **Custom Nuclei templates.** Detection templates ([`nuclei-templates/custom/`](nuclei-templates/custom/)) for bug classes not well-covered by the defaults (GraphQL dangerous mutations, JWT algorithm confusion, OAuth redirect bypass, etc.).
- **CI/CD deploy.** GitHub Actions workflow ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)) rsyncs code to a self-hosted runner, rebuilds the container, conditionally restarts the agent (with an active-scan drain wait), and manages the systemd services.

## Architecture

```
                    ┌─────────────────────────────┐
   browser ───────▶ │  Flask app (Docker)         │   orchestration + dashboard
                    │  src/app/web.py             │   ── HTTP ──┐
                    │  recon_routes.py (pipeline) │             │
                    └─────────────────────────────┘             ▼
                                                    ┌─────────────────────────────┐
                                                    │  Recon agent (host, stdlib) │
                                                    │  src/daemons/recon_agent.py │
                                                    │  spawns nmap/nuclei/httpx/… │
                                                    └──────────────┬──────────────┘
                                                                   │ sudo ip netns exec scanN
                                          ┌────────────────────────┼────────────────────────┐
                                          ▼            ▼            ▼            ▼
                                       scan1        scan2        scan3        scan4   (WireGuard netns)
                                          └────────────┴─── exit-node pool ──┴────────────┘
```

- **`src/app/`** — Flask app (`web.py`), SQLite layer (`db.py`), pipeline orchestration (`recon_routes.py`), disclosed-report browser (`hacktivity_routes.py`), per-program encrypted credential store (`credential_store.py`), HackerOne API client (`h1_client.py`).
- **`src/daemons/`** — the host agent plus two "autopilot" loops that continuously select programs and drive pipelines end-to-end.
- **`src/cli/`** — ingestion and maintenance utilities (program ingest, signal classification, disclosed-report ingest, DB browse).
- **`hetzner-exit-node/`** — cloud-init + systemd for the WireGuard exit nodes, including a small stats endpoint the agent polls for per-tool bandwidth attribution.

## Tech

Python (stdlib-heavy by design on the agent side), Flask, SQLite (WAL), Docker, systemd, WireGuard + Linux network namespaces, GitHub Actions, Nuclei, and the ProjectDiscovery tool ecosystem (subfinder/httpx/naabu/katana/dnsx).

## Quickstart

The only required credential is a HackerOne API token
([hackerone.com/settings/api_token](https://hackerone.com/settings/api_token/edit)).
That alone gets you the dashboard; the security toolchain and egress pool are
layered on after.

```bash
cp .env.example .env          # add H1_API_USERNAME + H1_API_TOKEN
docker compose up -d --build  # dashboard on http://localhost:5000
```

Or run Flask directly:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export PYTHONPATH=src
python -m cli.ingest                 # populate the local DB
python -m app.web                    # dashboard on http://localhost:5000
python src/daemons/recon_agent.py    # scan agent (needs the security tools installed)
```

## Setup & configuration

**[SETUP.md](SETUP.md)** is the full guide — it walks through three tiers (local
dashboard → real scanning → full deployment) and documents every key and
external service the platform can use, all sourced from `.env` (see
[`.env.example`](.env.example)):

| Service | Required? | Used for |
|---|---|---|
| HackerOne API | Yes | Ingesting program scopes |
| Security toolchain (ProjectDiscovery, nmap, nuclei, …) | For scanning | The recon tools themselves |
| Docker | Recommended | Running the web app |
| age | Optional | Encrypting stored credentials at rest |
| Hetzner Cloud + Tailscale + WireGuard | For the egress pool | Parallel, guarded scan egress |
| Telegram | Optional | Run notifications |
| GitHub Actions self-hosted runner | For CI/CD | Push-to-deploy |

## License

[MIT](LICENSE) © 2026 Jake Garnier. For authorized security testing only — scan
only targets you are permitted to test, within the relevant program's scope.
