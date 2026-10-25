"""Scenario B: naive HTTP flood (CC attack). Obvious by volume, and optionally by headers."""
from __future__ import annotations

import asyncio
import time
from collections import Counter

import httpx

from simulate.common import CHROME_UA, cli, extra, fake_ip, get


async def worker(base_url, ip, duration, label, spoof_ua, stats):
    end = time.monotonic() + duration
    headers = ([("User-Agent", CHROME_UA)] if spoof_ua else []) + extra(ip, label)
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as c:
        while time.monotonic() < end:
            await get(c, "/", headers, stats)


async def run(base_url, clients, duration, label, spoof_ua=0, **_):
    stats: Counter = Counter()
    await asyncio.gather(*(worker(base_url, fake_ip(2, i), duration, label, bool(spoof_ua), stats)
                           for i in range(clients)))
    return stats


if __name__ == "__main__":
    cli("flood", run, clients=5, duration=15.0, spoof_ua=0)
