"""Scenario D: self-attack the rule layer. Prints what got through; add every bypass you
find to tests/test_rules.py::ATTACKS, patch detectors/rules.py, and document it in
docs/HANDOFF.md (the adversarial loop)."""
from __future__ import annotations

import asyncio
import sys

import httpx

from simulate.common import CHROME_UA

PAYLOADS = [
    ("sqli", "/search", {"q": "1' OR '1'='1"}),
    ("sqli", "/search", {"q": "1 UNION SELECT NULL,NULL--"}),
    ("sqli", "/search", {"q": "1' AND SLEEP(5)-- -"}),
    ("sqli-evasion", "/search", {"q": "1' UN/**/ION SEL/**/ECT 1--"}),       # comment splitting
    ("sqli-evasion", "/search", {"q": "1' oR 'a'='a"}),
    ("sqli-evasion", "/search", {"q": "1'||(SELECT pg_sleep(5))||'"}),
    ("xss", "/search", {"q": "<script>alert(1)</script>"}),
    ("xss", "/search", {"q": "\"><img src=x onerror=alert(1)>"}),
    ("xss-evasion", "/search", {"q": "<ScRiPt >alert(1)</sCrIpT>"}),
    ("xss-evasion", "/search", {"q": "<body onpageshow=alert(1)>"}),         # handler not in list
    ("xss-evasion", "/search", {"q": "<a href=\"&#106;avascript:alert(1)\">"}),  # entity encoding
    ("traversal", "/files/../../etc/passwd", {}),
    ("traversal-evasion", "/files/..%252f..%252fetc%252fpasswd", {}),
    ("traversal-evasion", "/files/....//....//etc/hosts", {}),               # nested ../ bypass
    ("cmdi", "/ping", {"host": "8.8.8.8; cat /etc/passwd"}),
    ("cmdi-evasion", "/ping", {"host": "8.8.8.8\nid"}),                       # newline separator
]


async def main(base_url: str) -> None:
    passed = []
    async with httpx.AsyncClient(base_url=base_url, timeout=10,
                                 headers={"User-Agent": CHROME_UA}) as c:
        for kind, path, params in PAYLOADS:
            r = await c.get(path, params=params)
            blocked = r.status_code == 403
            print(f"{'BLOCKED ' if blocked else 'PASSED  '} {kind:18} {path} {params}")
            if not blocked and r.status_code != 429:
                passed.append((kind, path, params))
    print(f"\n{len(passed)}/{len(PAYLOADS)} payloads reached the backend")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"))
