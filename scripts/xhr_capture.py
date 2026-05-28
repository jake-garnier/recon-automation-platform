#!/usr/bin/env python3
"""
xhr_capture.py — load each live host in headless Chromium, capture XHR/fetch URLs.

Bug-bounty recon for SPA-heavy targets. Traditional crawlers (katana, gospider)
see only the static `<div id="root"></div>` shell because React Router's
catch-all returns 200 for every path. This tool runs the JS, waits for
hydration, and captures the actual API hosts/endpoints the SPA talks to.

Input: a text file of URLs (one per line, scheme + host, no path) — matches
       the output of `_extract_urls_from_httpx` in recon_agent.py.

Output: JSONL, one row per unique (method, url) tuple discovered. Fields:
        - source_host : the input URL we loaded (the SPA host)
        - method      : HTTP method
        - url         : full URL of the XHR/fetch
        - resource_type : xhr | fetch
        - status      : HTTP status (if response arrived in time)
        - is_graphql  : true if Content-Type is JSON and body contains "query":
        - is_cross_origin : true if the URL's host differs from source_host
        - post_data   : up to 4096 bytes of request body (helps GraphQL fuzzing)
        - operation_name : GraphQL operationName if discoverable

Usage:
  xhr_capture.py <input_urls.txt> <output.jsonl> <log_file> [--timeout 30]
                  [--concurrency 4] [--storage-state state.json]

Designed to be subprocess-spawned by recon_agent.py. Emits structured logs
to <log_file>. Per-host wall-clock cap is `--timeout` (default 30s).

DEPENDENCY: Playwright (`pip install playwright && playwright install chromium`).
On Kali the system Chromium can be reused by passing
`--executable-path /usr/bin/chromium` to avoid the per-install browser
download.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

# Playwright is an optional dep — fail loudly if missing
try:
    from playwright.async_api import async_playwright, Request, TimeoutError as PWTimeout
except ImportError:
    sys.stderr.write(
        "FATAL: playwright not installed. Run:\n"
        "  pip install playwright && playwright install --with-deps chromium\n"
    )
    sys.exit(2)


# Resource types worth capturing. We deliberately exclude image/font/stylesheet
# because they don't reveal API endpoints. "websocket" is captured separately
# via page.on('websocket') if we ever enable it.
CAPTURED_RESOURCE_TYPES = {"xhr", "fetch"}

# Reasonable navigation timeout. We don't want to hang on slow SPAs but we
# also need to wait long enough for hydration to fire its first XHRs.
NAV_TIMEOUT_MS = 15000
DEFAULT_HYDRATE_WAIT_MS = 25000  # of the 30s default per-host budget

# Hard cap on payload preview to bound JSONL size
POST_DATA_CAP = 4096

# Chrome flags required inside Linux network namespaces (no /dev/shm)
# and to silence automation-detection fingerprints.
CHROME_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-gpu",
    # Memory cap helps when we run 4 instances in parallel:
    "--memory-pressure-off",
]

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_file", help="Text file of URLs to load, one per line")
    p.add_argument("output_file", help="JSONL output path")
    p.add_argument("log_file", help="Log file path (progress + errors)")
    p.add_argument("--timeout", type=int, default=30,
                   help="Per-host wall-clock budget in seconds (default 30)")
    p.add_argument("--concurrency", type=int, default=4,
                   help="Parallel browsers (default 4; bounded by RAM)")
    p.add_argument("--executable-path", default=None,
                   help="Chromium binary path (e.g. /usr/bin/chromium on Kali)")
    p.add_argument("--storage-state", default=None,
                   help="Playwright storage_state.json for authenticated browsing")
    p.add_argument("--max-hosts", type=int, default=50,
                   help="Cap on number of hosts loaded (default 50). SPAs are "
                        "expensive — top live hosts give >80%% of the signal.")
    return p.parse_args()


def _load_inputs(input_path: Path, cap: int) -> list[str]:
    urls = []
    seen = set()
    for line in input_path.read_text().splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        # Normalize — accept bare host or full URL
        if "://" not in url:
            url = "https://" + url
        # Drop path/query — we want to load the *origin*
        try:
            parsed = urllib.parse.urlsplit(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        except ValueError:
            continue
        if origin in seen:
            continue
        seen.add(origin)
        urls.append(origin)
        if len(urls) >= cap:
            break
    return urls


def _is_graphql(post_data: str | None, content_type: str) -> tuple[bool, str | None]:
    """Detect GraphQL POSTs. Returns (is_graphql, operation_name_or_None)."""
    if not post_data:
        return (False, None)
    if "application/json" not in (content_type or "").lower():
        return (False, None)
    # Cheap substring check first
    if '"query"' not in post_data and '"mutation"' not in post_data:
        return (False, None)
    try:
        body = json.loads(post_data)
    except (json.JSONDecodeError, TypeError):
        return (False, None)
    if isinstance(body, dict) and "query" in body:
        return (True, body.get("operationName") or None)
    if isinstance(body, list) and body and isinstance(body[0], dict) and "query" in body[0]:
        # Batched GraphQL request
        return (True, body[0].get("operationName") or None)
    return (False, None)


async def _capture_one(
    browser, source_url: str, timeout_s: int,
    storage_state: dict | None, log_fh
) -> list[dict]:
    """Load one URL, capture XHR/fetch, return list of unique findings."""
    source_host = urllib.parse.urlsplit(source_url).hostname or ""
    seen: set[tuple[str, str]] = set()
    rows: list[dict] = []
    start = time.time()

    ctx_kwargs = dict(
        user_agent=USER_AGENT,
        ignore_https_errors=True,
        java_script_enabled=True,
        viewport={"width": 1366, "height": 768},
    )
    if storage_state:
        ctx_kwargs["storage_state"] = storage_state

    ctx = await browser.new_context(**ctx_kwargs)
    page = await ctx.new_page()

    def on_request(req: Request):
        if req.resource_type not in CAPTURED_RESOURCE_TYPES:
            return
        key = (req.method, req.url)
        if key in seen:
            return
        seen.add(key)
        post_data = None
        try:
            if req.post_data:
                post_data = req.post_data[:POST_DATA_CAP]
        except Exception:
            pass
        content_type = ""
        try:
            content_type = req.headers.get("content-type", "")
        except Exception:
            pass
        is_gql, op_name = _is_graphql(post_data, content_type)
        try:
            url_host = urllib.parse.urlsplit(req.url).hostname or ""
        except Exception:
            url_host = ""
        rows.append({
            "source_host": source_host,
            "method": req.method,
            "url": req.url,
            "resource_type": req.resource_type,
            "post_data": post_data,
            "content_type": content_type,
            "is_graphql": is_gql,
            "operation_name": op_name,
            "is_cross_origin": url_host != source_host,
        })

    page.on("request", on_request)

    # We'd like response status too. on_response fires for all responses so
    # we tag the matching row afterward by url+method.
    response_status: dict[tuple[str, str], int] = {}

    def on_response(resp):
        try:
            key = (resp.request.method, resp.url)
            response_status[key] = resp.status
        except Exception:
            pass

    page.on("response", on_response)

    try:
        await page.goto(source_url, wait_until="domcontentloaded",
                        timeout=NAV_TIMEOUT_MS)
        # Let SPA hydrate + fire its initial XHRs. Use the remaining budget
        # minus 2s safety margin for context.close().
        remaining_ms = max(2000, (timeout_s * 1000) - (int((time.time() - start) * 1000)) - 2000)
        wait_ms = min(remaining_ms, DEFAULT_HYDRATE_WAIT_MS)
        await page.wait_for_timeout(wait_ms)

        # Click up to 5 same-origin nav links to flush more XHR (gated by
        # remaining time budget).
        if time.time() - start < timeout_s - 4:
            try:
                links = await page.query_selector_all("a[href]")
                clicked = 0
                for link in links[:30]:
                    if time.time() - start > timeout_s - 3:
                        break
                    try:
                        href = await link.get_attribute("href")
                        if not href:
                            continue
                        abs_url = urllib.parse.urljoin(source_url, href)
                        # Same origin only — don't navigate away
                        if urllib.parse.urlsplit(abs_url).hostname != source_host:
                            continue
                        # Don't follow login/logout — they'd reset our session
                        if any(kw in href.lower() for kw in ("logout", "signout", "sign-out")):
                            continue
                        # Click + tiny wait, but DON'T navigate — capture XHRs
                        # triggered by the click handler. Use {trial: True} to
                        # avoid waiting for actionability.
                        await link.click(timeout=1500, no_wait_after=True)
                        await page.wait_for_timeout(800)
                        clicked += 1
                        if clicked >= 5:
                            break
                    except Exception:
                        continue
            except Exception:
                pass

    except PWTimeout:
        log_fh.write(f"[timeout] {source_url}\n")
    except Exception as e:
        log_fh.write(f"[error] {source_url}: {type(e).__name__}: {e}\n")
    finally:
        try:
            await ctx.close()
        except Exception:
            pass

    # Stitch status onto rows
    for r in rows:
        status = response_status.get((r["method"], r["url"]))
        if status is not None:
            r["status"] = status

    elapsed = time.time() - start
    log_fh.write(f"[done] {source_url}  rows={len(rows)}  elapsed={elapsed:.1f}s\n")
    log_fh.flush()
    return rows


async def _run(args: argparse.Namespace) -> int:
    input_path = Path(args.input_file)
    output_path = Path(args.output_file)
    log_path = Path(args.log_file)

    if not input_path.exists():
        sys.stderr.write(f"input file {input_path} not found\n")
        return 1

    urls = _load_inputs(input_path, args.max_hosts)
    if not urls:
        sys.stderr.write("no valid URLs in input\n")
        return 1

    storage_state = None
    if args.storage_state and Path(args.storage_state).exists():
        storage_state = args.storage_state  # Playwright accepts path or dict

    log_fh = open(log_path, "w", buffering=1)  # line-buffered
    out_fh = open(output_path, "w")
    log_fh.write(f"xhr_capture starting: {len(urls)} hosts, "
                 f"timeout={args.timeout}s, concurrency={args.concurrency}\n")

    async with async_playwright() as p:
        launch_kwargs = dict(
            headless=True,
            args=CHROME_LAUNCH_ARGS,
        )
        if args.executable_path:
            launch_kwargs["executable_path"] = args.executable_path
        try:
            browser = await p.chromium.launch(**launch_kwargs)
        except Exception as e:
            log_fh.write(f"[fatal] chromium launch failed: {e}\n")
            sys.stderr.write(f"chromium launch failed: {e}\n")
            return 2

        # Concurrency bound via Semaphore — each host gets its own context
        # (so cookies/storage don't leak between hosts). Default 4 parallel
        # contexts on Chromium uses ~1.5-2 GB RSS total.
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(url):
            async with sem:
                return await _capture_one(browser, url, args.timeout,
                                           storage_state, log_fh)

        tasks = [bounded(u) for u in urls]
        all_rows: list[dict] = []
        for coro in asyncio.as_completed(tasks):
            try:
                rows = await coro
                for r in rows:
                    out_fh.write(json.dumps(r) + "\n")
                all_rows.extend(rows)
            except Exception as e:
                log_fh.write(f"[task-error] {type(e).__name__}: {e}\n")

        try:
            await browser.close()
        except Exception:
            pass

    out_fh.close()
    # Summary
    unique_urls = {(r["method"], r["url"]) for r in all_rows}
    cross_origin = sum(1 for r in all_rows if r.get("is_cross_origin"))
    graphql = sum(1 for r in all_rows if r.get("is_graphql"))
    log_fh.write(
        f"xhr_capture done: {len(unique_urls)} unique requests, "
        f"{cross_origin} cross-origin, {graphql} GraphQL\n"
    )
    log_fh.close()
    return 0


def main():
    args = _parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
