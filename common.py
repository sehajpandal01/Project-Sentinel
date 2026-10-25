"""Shared helpers for the traffic simulators.

Simulated clients spoof distinct IPs via X-Forwarded-For, so the WAF under test must run
with SENTINEL_TRUST_FORWARDED_FOR=true (dev only!). When the WAF has SENTINEL_TRAINING_LOG_PATH
set, X-Sim-Label tells it the ground truth for building a training set.
"""
from __future__ import annotations

import argparse
import asyncio
import random
from collections import Counter
from collections.abc import Awaitable, Callable

import httpx

PAGES = ["/", "/products", "/about"]
ASSETS = ["/static/app.css", "/static/app.js", "/favicon.ico"]
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def fake_ip(prefix: int, i: int) -> str:
    return f"10.{prefix}.{i // 250}.{i % 250 + 1}"


def browser_headers(referer: str | None = None, doc: bool = True) -> list[tuple[str, str]]:
    """Chrome-like header set in Chrome-like order."""
    h = [("Connection", "keep-alive"), ("User-Agent", CHROME_UA),
         ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8" if doc else "*/*"),
         ("Sec-Fetch-Mode", "navigate" if doc else "no-cors")]
    if referer:
        h.append(("Referer", referer))
    return h + [("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "en-US,en;q=0.9")]


def extra(ip: str, label: str | None) -> list[tuple[str, str]]:
    return [("X-Forwarded-For", ip)] + ([("X-Sim-Label", label)] if label else [])


def human_delay(mean_s: float = 2.5, sigma: float = 0.8) -> float:
    """Log-normal 'reading time' with the requested mean."""
    import math
    mu = math.log(mean_s) - sigma**2 / 2
    return random.lognormvariate(mu, sigma)


def report(name: str, stats: Counter) -> None:
    total = sum(stats.values()) or 1
    print(f"\n[{name}] {total} requests")
    for code, n in sorted(stats.items(), key=lambda kv: str(kv[0])):
        print(f"  {code}: {n} ({100 * n / total:.1f}%)")


def cli(name: str, runner: Callable[..., Awaitable[Counter]], **defaults) -> None:
    ap = argparse.ArgumentParser(description=name)
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--clients", type=int, default=defaults.get("clients", 10))
    ap.add_argument("--duration", type=float, default=defaults.get("duration", 30.0))
    ap.add_argument("--label", default=None, help="ground-truth label for training logs")
    for k, v in defaults.items():
        if k not in ("clients", "duration"):
            ap.add_argument(f"--{k.replace('_', '-')}", default=v, type=type(v))
    args = vars(ap.parse_args())
    stats = asyncio.run(runner(**args))
    report(name, stats)


async def get(client: httpx.AsyncClient, path: str, headers, stats: Counter, **kw) -> int:
    try:
        r = await client.get(path, headers=headers, **kw)
        stats[r.status_code] += 1
        return r.status_code
    except httpx.HTTPError:
        stats["error"] += 1
        return 0
