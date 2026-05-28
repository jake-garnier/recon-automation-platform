# Hetzner Exit Node — `recon-egress-ash`

The recon pipeline egresses through this Hetzner CPX21 VPS via a Tailscale
exit node. This eliminates home-modem NAT exhaustion from naabu/httpx fanout.

## Current deployment

- **Server**: Hetzner CPX21, Ashburn (`ash-dc1`), `recon-egress-ash`
- **Public IPv4**: `<EXIT_NODE_PUBLIC_IP>`
- **Tailscale IP**: `<EXIT_NODE_TS_IP>`
- **Cost**: ~$8.51/mo
- **OS**: Debian 12

## Files

| File | Purpose |
|---|---|
| `cloud-init.yaml` | One-shot provisioning user-data (Tailscale install, UFW, sysctl tuning, etc.). Used only at server creation. |
| `traffic-server.py` | Tiny stdlib HTTP server exposing `vnstat` JSON + conntrack stats on `<EXIT_NODE_TS_IP>:9090` (tailnet only). |
| `traffic-server.service` | Systemd unit for `traffic-server.py`. |

## Update flow (automatic)

Push changes to `hetzner-exit-node/**` → CI workflow `deploy-exit-node.yml`
rsyncs files to the VPS via Tailscale SSH and restarts `traffic-server` if
its files changed.

## Provisioning a fresh exit node (manual, one-time)

Not automated by CI — provisioning involves Hetzner account interaction,
billing, and Tailscale auth-key generation. Rough steps:

1. Hetzner account + API token (≥ Read & Write)
2. Tailscale tailnet ACL has `tagOwners: { "tag:exit": ["autogroup:admin"] }`
   and an SSH rule allowing root access from admin to `tag:exit`
3. Generate a Tailscale auth key with tag `tag:exit`, reusable, ephemeral=off
4. Build user-data from `cloud-init.yaml` with the auth key substituted in
   for `TAILSCALE_AUTH_KEY_PLACEHOLDER`
5. Create CPX21 via API: `POST /v1/servers` with image=`debian-12`,
   location=`ash`, attached SSH key, `user_data=<inline cloud-init>`
6. Wait ~60s for cloud-init. Verify in Tailscale admin that the new node
   appears with `tag:exit` and is advertising `0.0.0.0/0 + ::/0`
7. Enable the advertised routes via Tailscale API:
   `POST /v2/device/<id>/routes` with `{"routes": ["0.0.0.0/0", "::/0"]}`
8. On Kali: `sudo tailscale up --exit-node=<new-ts-ip> --exit-node-allow-lan-access=true`
9. Update `EXIT_NODE_REQUIRED_IP` + `EXIT_NODE_TS_IP` env vars in
   `../recon-agent.service` and redeploy

The repo's `proxmox/.secrets` file holds the Hetzner API token,
Tailscale auth/API keys, and current server IDs.

## Sanity checks

```bash
# From any machine on the tailnet:
curl http://<EXIT_NODE_TS_IP>:9090/traffic   # bytes + conntrack
curl http://<EXIT_NODE_TS_IP>:9090/health    # liveness

# From Kali — confirm egress IP:
curl https://api.ipify.org    # should print <EXIT_NODE_PUBLIC_IP>
```

If `api.ipify.org` returns your home IP, the exit node is not active; the
recon agent's exit-node monitor will SIGSTOP all scans within 3 minutes.
