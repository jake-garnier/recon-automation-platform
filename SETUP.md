# Setup Guide

This platform is designed to run on a Linux host (developed on Kali) with the
security toolchain installed natively, plus a Dockerized Flask app for the UI.
You can run it in three tiers depending on how much you want to stand up:

| Tier | What you get | What you need |
|---|---|---|
| **1 — Local dashboard** | Ingest programs, browse scopes, drive the UI | HackerOne API keys, Python/Docker |
| **2 — Real scanning** | Run the recon pipeline against live targets | Tier 1 + the security toolchain on the host |
| **3 — Full deployment** | Parallel egress, autopilot, CI/CD deploy | Tier 2 + Hetzner, Tailscale, WireGuard, a runner |

Work through them in order. Each tier is usable on its own.

---

## Keys & external services at a glance

| Service | Required? | Cost | Used for | Env vars |
|---|---|---|---|---|
| [HackerOne API](#hackerone-api) | **Yes** | Free | Ingesting program scopes | `H1_API_USERNAME`, `H1_API_TOKEN` |
| [Security toolchain](#security-toolchain) | For scanning | Free (OSS) | The actual recon tools | — |
| [Docker](#docker) | Recommended | Free | Running the web app | — |
| [age](#age-encrypted-credential-store) | Optional | Free | Encrypting stored credentials | `AGE_KEY_PATH` |
| [Hetzner Cloud](#hetzner-cloud-exit-nodes) | Tier 3 | ~$8.51/mo per node | WireGuard egress nodes | `EXIT_NODE_REQUIRED_IP` |
| [Tailscale](#tailscale) | Tier 3 | Free tier | Private mesh to the exit nodes | `EXIT_NODE_TS_IP` |
| [WireGuard](#wireguard--network-namespaces) | Tier 3 | Free | Per-slot egress tunnels | `EXIT_NODE_GUARD_ENABLED` |
| [Telegram bot](#telegram-notifications) | Optional | Free | Run notifications | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| [Caido](#caido-optional) | Optional | Free / paid | Manual HTTP testing after triage | — |
| [GitHub Actions runner](#cicd-self-hosted-runner) | Tier 3 | Free | Push-to-deploy | GitHub Secrets |

None of these keys are baked into the code — every value comes from `.env` or
the environment. Start by copying the template:

```bash
cp .env.example .env
```

---

## Tier 1 — Local dashboard

### HackerOne API

The only required credential. It authenticates the ingestion client that pulls
program and scope data.

1. Go to <https://hackerone.com/settings/api_token/edit>.
2. Create an API token. Note your **HackerOne username** (your handle) and the
   generated **token** — the pair is used as HTTP Basic auth.
3. Put them in `.env`:
   ```
   H1_API_USERNAME=your_handle
   H1_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx
   ```

### Python / Docker

**Option A — Docker (recommended):**

```bash
cp .env.example .env        # fill in the HackerOne keys
docker compose up -d --build
# dashboard → http://localhost:5000
```

The container runs with `network_mode: host` so it can reach a recon agent
running on the same host at `127.0.0.1:5001`. Data persists in the
`bounty_data` volume.

**Option B — Run Flask directly:**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export PYTHONPATH=src
python -m cli.ingest         # populate bounties.db
python -m app.web            # dashboard on http://localhost:5000
```

> **Import style note:** app/cli modules resolve under `src/`, so `PYTHONPATH=src`
> is required. The daemons run as plain script paths (e.g.
> `python src/daemons/recon_agent.py`), *not* with `-m`.

At this point you can ingest programs and browse the UI. Scans will show as
"skipped"/failed until you complete Tier 2.

---

## Tier 2 — Real scanning

The recon agent (`src/daemons/recon_agent.py`) shells out to real security
tools. It's stdlib-only Python by design so it can run on the host, outside
Docker, with direct access to those binaries.

### Security toolchain

Install the tools on the host and make sure they're on `PATH` (Go tools land in
`~/go/bin`). Kali ships most of them; on other distros install per tool.

- **ProjectDiscovery suite** (`subfinder`, `httpx`, `naabu`, `nuclei`, `katana`,
  `dnsx`): install via [pdtm](https://github.com/projectdiscovery/pdtm) or
  `go install`.
- **Discovery/DNS:** `amass`, `shuffledns`, `dnsgen`, `gau`, `gitleaks`,
  `trufflehog`.
- **Crawl/scan:** `gospider`, `paramspider`, `feroxbuster`, `kiterunner` (`kr`),
  `nmap`, `eyewitness`.
- **Exploitation-phase:** `sqlmap`, `commix`, `hydra`, `wpscan`, `joomscan`,
  `nomore403`.

Several tools are pure-Python built-ins (no external binary): crt-sh, git-dumper,
s3-takeover, merge-subs/urls, cloud-buckets, secret-scan, cms-detect,
panel-detect, linkfinder, corscanner, nextjs-check.

Verify what the agent can see:

```bash
python src/daemons/recon_agent.py       # starts the agent on :5001
curl -s http://127.0.0.1:5001/health
# then in the UI: /api/recon/agent/tools/health  → per-tool availability
```

A `failed` scan with an empty error **and** empty log tail almost always means a
`PATH` problem inside the run environment — check that the tool is on the agent's
`PATH`.

### age (encrypted credential store)

Only needed if you use the per-program credential store (for authenticated
recon). Credentials are encrypted at rest with [age](https://github.com/FiloSottile/age).

```bash
sudo apt install age            # or: brew install age
mkdir -p ~/.age && age-keygen -o ~/.age/key.txt && chmod 600 ~/.age/key.txt
```

Point the app at it and bootstrap:

```bash
export AGE_KEY_PATH=~/.age/key.txt        # or set in .env
PYTHONPATH=src python3 -m app.credential_store bootstrap
```

> **Back up `key.txt`.** Losing it makes every stored credential unrecoverable.
> The Python `pyrage` binding is only needed on the credential path; the store
> no-ops gracefully if it isn't installed.

---

## Tier 3 — Full deployment (egress pool + CI/CD)

This is the production shape: scan traffic tunnels out through a pool of cloud
exit nodes, and pushing to `main` redeploys. It's optional — everything above
works without it — but it's what gives the pipeline clean, high-capacity egress.

### Hetzner Cloud (exit nodes)

Each exit node is a small Hetzner VPS (~$8.51/mo for a CPX21) that scan traffic
egresses through, giving ~100× the connection-tracking headroom of a home
connection.

1. Create a [Hetzner Cloud](https://www.hetzner.com/cloud) account and a project.
2. Generate an **API token** with Read & Write (Security → API tokens).
3. Provision nodes from [`hetzner-exit-node/`](hetzner-exit-node/) — see that
   directory's `README.md` for the exact `cloud-init` + API steps. Put each
   node's public IP in `EXIT_NODE_REQUIRED_IP`.

### Tailscale

Provides the private mesh so the app can reach exit nodes over a stable tailnet
IP and the CI runner can SSH to them.

1. Sign up at [tailscale.com](https://tailscale.com) (free tier is plenty).
2. In the tailnet ACLs, add a tag for exit nodes, e.g.
   `tagOwners: { "tag:exit": ["autogroup:admin"] }`, plus an SSH rule allowing
   admin → `tag:exit`.
3. Generate a **reusable, tagged auth key** (`tag:exit`) and feed it into the
   exit-node `cloud-init`. Set `EXIT_NODE_TS_IP` to the node's tailnet IP.

### WireGuard + network namespaces

Each scan "slot" (`scan1`..`scan4`) is a Linux network namespace with its own
WireGuard tunnel to an exit node, so up to four pipelines run in parallel, each
pinned to a distinct egress. Bring-up is host-specific (WireGuard keys + `ip
netns` wiring); the guard refuses to scan unless egress matches the expected IP:

```
EXIT_NODE_GUARD_ENABLED=1
EXIT_NODE_REQUIRED_IP=your.exit.node.ip
```

Set `EXIT_NODE_GUARD_ENABLED=0` to run without the pool (all traffic egresses
your host directly — fine for local testing, not for real scanning).

### CI/CD (self-hosted runner)

The [`deploy.yml`](.github/workflows/deploy.yml) workflow rsyncs code to a
self-hosted runner, rebuilds the container, and conditionally restarts the agent.

1. Repo → Settings → Actions → Runners → **New self-hosted runner**, installed on
   your deploy host.
2. Add repo **Secrets** `H1_API_USERNAME` and `H1_API_TOKEN` (Settings →
   Secrets and variables → Actions).
3. Push to `main` to deploy. A second workflow, `deploy-exit-node.yml`, deploys
   the Hetzner exit-node files independently.

---

## Optional integrations

### Telegram notifications

For run/alert notifications.

1. Message [@BotFather](https://t.me/BotFather), `/newbot`, and copy the token.
2. Message your new bot once, then read the chat ID from
   `https://api.telegram.org/bot<TOKEN>/getUpdates`.
3. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`.

### Caido (optional)

[Caido](https://caido.io) is an intercepting proxy used for manual HTTP testing
after the automated pipeline and triage. See
[`scripts/CAIDO_SESSION_CAPTURE.md`](scripts/CAIDO_SESSION_CAPTURE.md) for the
session-capture flow. Not required to run the platform.

---

## Verifying the install

```bash
# App is up
curl -f http://localhost:5000/

# Agent is up and sees its tools
curl -s http://127.0.0.1:5001/health

# Programs ingested
PYTHONPATH=src python3 -m cli.browse stats
```

If the dashboard shows 0 programs, check that `DB_PATH` points at the DB the
ingest wrote to — a mismatched path is the usual cause.

---

## Security notes

- This is single-operator tooling. The threat model assumes one trusted user on
  the host; anyone with a shell on that host can read decrypted credentials.
- Never commit `.env`, `*.db`, captured session JSON files, or your age key —
  they're all in `.gitignore` for a reason.
- Only scan targets you are authorized to test, within the scope of the relevant
  bug-bounty program.
