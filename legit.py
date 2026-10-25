"""Scenario A: legitimate browsing. Any non-200 here is a FALSE POSITIVE."""
from __future__ import annotations

import asyncio
import random
import time
from collections import Counter

import httpx

from simulate.common import (ASSETS, PAGES, browser_headers, cli, extra, fake_ip, get,
                             human_delay)


async def one_user(base_url, ip, duration, label, stats):
    end, ref = time.monotonic() + duration, None
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as c:
        while time.monotonic() < end:
            page = random.choice(PAGES)
            await get(c, page, browser_headers(ref) + extra(ip, label), stats)
            ref = base_url + page
            for asset in ASSETS:  # browsers load subresources immediately after the document
                await asyncio.sleep(random.uniform(0.03, 0.25))
                await get(c, asset, browser_headers(ref, doc=False) + extra(ip, label), stats)
            if random.random() < 0.3:
                await asyncio.sleep(human_delay(2.0))
                await get(c, "/search", browser_headers(ref) + extra(ip, label), stats,
                          params={"q": random.choice(["shoes", "rock and roll", "union station"])})
            await asyncio.sleep(human_delay(3.0))


async def run(base_url, clients, duration, label, **_):
    stats: Counter = Counter()
    await asyncio.gather(*(one_user(base_url, fake_ip(1, i), duration, label, stats)
                           for i in range(clients)))
    return stats


if __name__ == "__main__":
    cli("legit", run, clients=20, duration=60.0)
