# Authenticated session capture + Caido proxy setup (runbook)

How to log into a target in a local Chrome, route that browser through the Kali
Caido proxy (so the **whole login/auth flow is recorded in Caido for review**), and
capture the authenticated session into the per-program credential store on Kali.

This is the runbook for the thing that took ~2 hours of trial-and-error the first
time (2026-05-28, OKX/okg). Every step below has a "why" because each was a wall hit
that day. Follow it in order and it's ~10 minutes.

> **Account-risk caveat:** routing a live login through an intercepting proxy changes
> the browser's TLS fingerprint and looks like a new device. On a KYC'd financial
> target (crypto exchange, bank) this can trip anti-fraud and flag/hold the account.
> If that matters, capture the session WITHOUT the proxy (skip steps 1-3, just do
> 4-5 with a plain debug Chrome) — you lose the auth-flow-in-Caido capture but keep
> the cookies. Decide deliberately.

---

## Prereqs (one-time)

- **Mac dep:** `websocket-client`. macOS system Python is PEP-668 "externally managed",
  so don't `pip install` into it. Use a throwaway venv:
  ```bash
  python3 -m venv /tmp/capture-venv
  /tmp/capture-venv/bin/pip install websocket-client
  ```
  Run the capture script with `/tmp/capture-venv/bin/python` (not bare `python3`).
- **Caido CA trusted in macOS keychain** (so the proxied browser gets no cert errors).
  See step 2 — the CA can't be fetched via Caido's `cacert.caido.io` magic host
  (DNS-blocked on Kali's netns); pull it from GraphQL instead.
- **Kali up.** If the dashboard/Caido are unreachable, the VM may have crashed —
  see "Kali VM down" at the bottom.

---

## Step 1 — Find the live Caido proxy port

Caido on Kali runs **proxy + UI combined on one port**. After a restart it comes up
listening `0.0.0.0:8090 (Proxy, UI)` — confirm the actual port, do NOT assume 8081
(that was a stale binding from an older session and does NOT survive restarts):

```bash
# from the Mac — which port actually relays?
curl -s --max-time 10 -x http://<KALI_TS_IP>:8090 https://example.com/ -o /dev/null -w "%{http_code}\n"
# 200/302 => that's the proxy port. If it fails, check :8081 too, but 8090 is canonical.
```
Caido's listener line in its log (`journalctl -u caido`) says `Listening on 0.0.0.0:8090 (Proxy, UI)` — trust that.

If Caido is up but NO proxy port is listening, it has **no project loaded**. Select one
(proxy listener is project-scoped). Refresh the MCP token first if you get `INVALID_TOKEN`:
```bash
CAIDO_URL=http://<KALI_TS_IP>:8090 ~/.local/bin/caido-mcp-refresh-guest   # writes ~/.caido-mcp/token.json (7-day TTL)
TOK=$(python3 -c "import json;print(json.load(open('$HOME/.caido-mcp/token.json'))['accessToken'])")
# list projects
curl -s http://<KALI_TS_IP>:8090/graphql -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"query":"{ projects { id name } }"}'
# select it (binds the proxy listener)
curl -s http://<KALI_TS_IP>:8090/graphql -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"query":"mutation($id:ID!){selectProject(id:$id){currentProject{__typename} error{__typename}}}","variables":{"id":"<PROJECT_ID>"}}'
```
(OKG project id is `fde49f32-49bc-4c12-a76e-9e69696b8045`, name "HackerOne".)

---

## Step 2 — Trust Caido's CA cert (one-time per CA regen)

**The CA cert is saved in the repo: [`scripts/certs/caido_ca.pem`](certs/caido_ca.pem)**
(public cert, `CN=Caido`, valid through 2030-04-01). Just trust it — no need to refetch:
```bash
# needs YOUR sudo password — Claude can't enter it, run this yourself
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  scripts/certs/caido_ca.pem
# remove later:  sudo security delete-certificate -c "Caido" /Library/Keychains/System.keychain
```

### Only if the saved CA stops working (Caido regenerated its CA)
The magic-host route (`http://cacert.caido.io/ca.crt` via proxy) **does NOT work** here —
Caido tries to resolve it upstream and Kali's netns DNS 502s it. Re-pull from GraphQL
(the `Certificate` type only exposes a `p12` field; the p12 password is EMPTY):
```bash
TOK=$(python3 -c "import json;print(json.load(open('$HOME/.caido-mcp/token.json'))['accessToken'])")
curl -s http://<KALI_TS_IP>:8090/graphql -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"query":"{runtime{certificate{p12}}}"}' \
  | python3 -c "import sys,json,base64;d=json.load(sys.stdin);open('/tmp/caido.p12','wb').write(base64.b64decode(d['data']['runtime']['certificate']['p12']))"
openssl pkcs12 -in /tmp/caido.p12 -clcerts -nokeys -passin pass: -out scripts/certs/caido_ca.pem
openssl pkcs12 -in /tmp/caido.p12 -cacerts -nokeys -passin pass: >> scripts/certs/caido_ca.pem
openssl x509 -in scripts/certs/caido_ca.pem -noout -subject -dates   # sanity check, then re-trust (above)
```
> Save only the `.pem` (public cert) into the repo. The `.p12` contains the CA **private
> key** — `scripts/certs/.gitignore` blocks `*.p12`/`*.key`/`*.pfx` from being committed.

---

## Step 3 — Launch the proxied debug Chrome

Three gotchas, all fixed below:
- **`open -na "Google Chrome"` will NOT start a 2nd instance on a `--user-data-dir`
  that's already running** — it silently reattaches to the existing process, so old
  flags persist. Kill any existing debug Chrome first.
- **Chrome 148+ rejects the CDP WebSocket** unless origins are allowed. The specific
  `--remote-allow-origins=http://127.0.0.1:9222` form gets compared against a *doubled*
  origin string and still fails — use `*`.
- **zsh globs the bare `*`** → "no matches found". Quote it: `"--remote-allow-origins=*"`.

```bash
# 1. kill any stale debug Chrome (throwaway profile, safe)
pkill -9 -f "user-data-dir=/tmp/chrome-recon"; sleep 3
lsof -nP -iTCP:9222 -sTCP:LISTEN || echo "9222 free"

# 2. launch the binary directly (avoids open -na reattach), proxied + wildcard origins
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --proxy-server=http://<KALI_TS_IP>:8090 \
  --remote-debugging-port=9222 \
  "--remote-allow-origins=*" \
  --user-data-dir=/tmp/chrome-recon \
  >/tmp/chrome-recon.log 2>&1 &
sleep 5
```
Verify the WS handshake works before logging in (this is the canary):
```bash
/tmp/capture-venv/bin/python -c "
import urllib.request,json,websocket
t=json.load(urllib.request.urlopen('http://127.0.0.1:9222/json',timeout=5))
ws=websocket.create_connection([x['webSocketDebuggerUrl'] for x in t if x.get('type')=='page'][0],timeout=8,header=['Origin: http://127.0.0.1:9222'])
print('WS OK'); ws.close()"
```

---

## Step 4 — Log in

In the proxied window, go to the target and log in normally (MFA/U2F all work — it's a
real browser). Every request is now recorded in Caido → review at `http://<KALI_TS_IP>:8090`.

---

## Step 5 — Capture the session into the credential store

```bash
/tmp/capture-venv/bin/python scripts/capture_session.py <handle> --origin https://app.<target>.com
```
This writes `<handle>.json` locally (Playwright storage_state, full cookie jar incl HttpOnly).
`--origin` matches the tab by URL **prefix** — point it at whatever host the logged-in tab
is actually on (e.g. `app.okx.com`, not `www.okx.com`); cookies for ALL origins are captured
regardless via `Network.getAllCookies`.

**The `--upload kali@...` flag is BROKEN two ways — do the upload manually instead:**
1. Plain `ssh` hits `Too many authentication failures` (SSH agent offers too many keys).
   Force password auth: `-o PreferredAuthentications=password -o PubkeyAuthentication=no`.
2. Host-side `credential_store.py` opens a **stale** `~/apps/hackerOne/bounties.db` that
   lacks the `program_credentials` table. The REAL table+DB is the **container's** volume:
   `/var/lib/docker/volumes/hackerone_bounty_data/_data/bounties.db` (owned by root).
3. The age key + `pyrage` live in the **kali** user env, but the DB write needs **root**.
   Bridge them with `sudo PYTHONPATH=<kali site-packages>`.

Working upload (run from the repo on the Mac after `capture_session.py` wrote `<handle>.json`):
```bash
HANDLE=okg
B64=$(python3 -c "import base64;print(base64.b64encode(open('$HANDLE.json','rb').read()).decode())")
REMOTE=$(cat <<PYWRAP
cd /home/kali/apps/hackerOne
sudo PYTHONPATH=/home/kali/.local/lib/python3.13/site-packages \
     DB_PATH=/var/lib/docker/volumes/hackerone_bounty_data/_data/bounties.db \
     python3 - <<'PYEOF'
import base64, json, sys; sys.path.insert(0,'.')
import credential_store
parsed = json.loads(base64.b64decode("$B64").decode())
rid = credential_store.store(
    program_handle="$HANDLE", auth_type="storage_state", value=parsed,
    notes="captured via proxied debug Chrome", account_email="you@email",
    probe_url="", expected_status=None)
print(f"STORED id={rid}")
PYEOF
PYWRAP
)
sshpass -p '<VM_PASSWORD>' ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  kali@<KALI_TS_IP> "$REMOTE"
```
Verify (note the function is `get`, not `get_for_program`):
```bash
sshpass -p '<VM_PASSWORD>' ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no kali@<KALI_TS_IP> \
  "cd /home/kali/apps/hackerOne && sudo PYTHONPATH=/home/kali/.local/lib/python3.13/site-packages \
   DB_PATH=/var/lib/docker/volumes/hackerone_bounty_data/_data/bounties.db python3 -c \
   'import sys;sys.path.insert(0,\".\");import credential_store as c;v=c.get(\"$HANDLE\");print(\"cookies\",len(v[\"value\"][\"cookies\"]),v[\"status\"])'"
```
Then it shows on the dashboard `/credentials` page and `xhr-capture` auto-attaches it.

**Set a `probe_url`** (an authed endpoint returning 200-live / 401-dead) so the pipeline
can revalidate liveness before each scan — pass `probe_url=` + `expected_status=` to `store()`.

---

## Kali VM down (if nothing on <KALI_TS_IP> responds)

VM 103 crashes occasionally (in-guest OOM; 93GB RAM, ballooning off). pve (`<PROXMOX_TS_IP>`)
stays up. See memory `[[project-kali-vm-crash-recovery]]`. Quick restart via Proxmox API
(creds in `proxmox/.secrets`, `root@pam` / VM password):
```bash
PVE=https://<PROXMOX_TS_IP>:8006/api2/json
T=$(curl -sk -d "username=root@pam&password=<PW>" $PVE/access/ticket)
TK=$(echo "$T"|python3 -c "import sys,json;print(json.load(sys.stdin)['data']['ticket'])")
CSRF=$(echo "$T"|python3 -c "import sys,json;print(json.load(sys.stdin)['data']['CSRFPreventionToken'])")
curl -sk -b "PVEAuthCookie=$TK" -H "CSRFPreventionToken: $CSRF" -X POST $PVE/nodes/pve/qemu/103/status/start
```
Wait ~60-90s for Tailscale + services. Then redo step 1 (Caido may need its project reselected).
```
```
