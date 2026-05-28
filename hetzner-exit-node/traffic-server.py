#!/usr/bin/env python3
"""Tiny HTTP server serving vnstat JSON on the tailnet only.

Reachable from Kali via http://<EXIT_NODE_TS_IP>:9090/ — used by the
hackerOne dashboard to monitor egress bandwidth from the exit node side.
"""
import json
import os
import subprocess
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# Bind to the tailscale0 interface only — never the public IP.
# This is the Hetzner exit node's tailnet IP.
BIND_IP = os.environ.get("TRAFFIC_BIND_IP", "<EXIT_NODE_TS_IP>")
PORT = int(os.environ.get("TRAFFIC_PORT", "9090"))


def get_traffic():
    try:
        result = subprocess.run(
            ["/usr/local/bin/exit-traffic.sh"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return {"error": "exit-traffic.sh failed", "stderr": result.stderr}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "exit-traffic.sh timeout"}
    except Exception as e:
        return {"error": str(e)}


def get_uptime():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except Exception:
        return 0.0


def get_conntrack():
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            cur = int(f.read().strip())
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            mx = int(f.read().strip())
        return {"current": cur, "max": mx, "pct": round(100.0 * cur / mx, 1)}
    except Exception:
        return {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/traffic":
            traffic = get_traffic()
            self._send_json({
                "traffic": traffic,
                "conntrack": get_conntrack(),
                "uptime_s": get_uptime(),
                "server_time": time.time(),
            })
        elif self.path == "/health":
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "not found"}, 404)


if __name__ == "__main__":
    server = HTTPServer((BIND_IP, PORT), Handler)
    print("Traffic server listening on http://%s:%d" % (BIND_IP, PORT))
    server.serve_forever()
