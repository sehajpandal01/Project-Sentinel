"""Scenario C: 'gray market' slow-and-low bot. Human-like timing, full browser headers,
distinct IPs, stays under every rate threshold. This is the benchmark the heuristic
baseline is EXPECTED to fail; improving detection of it is the main research loop.

--evasion basic   : no subresource fetches (the tell the baseline can partly see)
--evasion assets  : also loads css/js like a browser (harder: needs timing/graph features)
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import Counter

import httpx

from simulate.common import (ASSETS, PAGES, browser_headers, cli, extra, fake_ip, get,
                             human_delay)


async def bot(base_url, ip, duration, label, evasion, stats):
    end, ref = time.monotonic() + duration, None
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as c:
        while time.monotonic() < end:
            page = random.choice(PAGES)
            await get(c, page, browser_headers(ref) + extra(ip, label), stats)
            ref = base_url + page
            if evasion == "assets":
                for asset in ASSETS:
                    await asyncio.sleep(random.uniform(0.03, 0.25))
                    await get(c, asset, browser_headers(ref, doc=False) + extra(ip, label), stats)
            await asyncio.sleep(human_delay(2.5))  # same distribution as the human sim


async def run(base_url, clients, duration, label, evasion="basic", **_):
    stats: Counter = Counter()
    await asyncio.gather(*(bot(base_url, fake_ip(3, i), duration, label, evasion, stats)
                           for i in range(clients)))
    return stats


if __name__ == "__main__":
    cli("graymarket", run, clients=20, duration=60.0, evasion="basic")
