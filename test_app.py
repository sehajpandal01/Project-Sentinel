import httpx
import pytest

from backend.app import app as backend_app
from sentinel.challenge import solve
from sentinel.config import Settings
from sentinel.main import create_app

HDRS = {"user-agent": "Mozilla/5.0 Chrome/120", "accept": "text/html",
        "accept-language": "en-US", "sec-fetch-mode": "navigate"}


def make(settings: Settings):
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend_app),
                                 base_url="http://backend")
    app = create_app(settings, upstream_client=upstream)
    return app, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                  base_url="http://sentinel", headers=HDRS)


async def test_proxies_benign():
    _, c = make(Settings(secret="t"))
    r = await c.get("/search", params={"q": "shoes"})
    assert r.status_code == 200 and r.json()["query"] == "shoes"
    assert (await c.post("/login", content=b"{}")).status_code == 200


async def test_blocks_sqli_and_traversal():
    _, c = make(Settings(secret="t"))
    assert (await c.get("/search", params={"q": "1' OR '1'='1"})).status_code == 403
    assert (await c.get("/x/..%2f..%2fetc/passwd")).status_code == 403


async def test_monitor_mode_forwards_but_records():
    app, c = make(Settings(secret="t", mode="monitor"))
    r = await c.get("/search", params={"q": "<script>alert(1)</script>"})
    assert r.status_code == 200
    ev = app.state.metrics.recent_events()
    assert ev and ev[0]["detector"] == "rules" and ev[0]["enforced"] is False


async def test_flood_challenge_solve_then_pass():
    s = Settings(secret="t", rate_min_threshold=10, rate_hard_multiplier=100.0,
                 challenge_difficulty_bits=8, behavior_threshold=2.0)
    _, c = make(s)
    c.headers["accept"] = "application/json"  # API-style client gets a JSON challenge
    codes = [(await c.get("/search")).status_code for _ in range(15)]
    assert 429 in codes
    r = await c.get("/search")
    assert r.status_code == 429
    body = r.json()
    sol = solve(body["token"], body["difficulty_bits"])
    v = await c.post("/_sentinel/challenge/verify", json={"token": body["token"], "solution": str(sol)})
    assert v.status_code == 200 and "sentinel_pass" in v.headers["set-cookie"]
    assert (await c.get("/search")).status_code == 200  # cookie jar carries the pass
    bad = await c.post("/_sentinel/challenge/verify", json={"token": "x", "solution": "1"})
    assert bad.status_code == 403


async def test_html_clients_get_challenge_page():
    s = Settings(secret="t", rate_min_threshold=3, rate_hard_multiplier=100.0, behavior_threshold=2.0)
    _, c = make(s)
    for _ in range(5):
        r = await c.get("/")
    assert r.status_code == 429 and "crypto.subtle" in r.text


async def test_admin_endpoints_and_token():
    _, c = make(Settings(secret="t", admin_token="s3cret"))
    assert (await c.get("/_sentinel/health")).status_code == 200
    assert (await c.get("/_sentinel/api/metrics")).status_code == 401
    ok = await c.get("/_sentinel/api/metrics", headers={"x-admin-token": "s3cret"})
    assert ok.status_code == 200 and "totals" in ok.json()
    assert "Sentinel" in (await c.get("/_sentinel/dashboard")).text


async def test_oversize_body_rejected():
    _, c = make(Settings(secret="t", max_body_bytes=10))
    assert (await c.post("/login", content=b"x" * 100)).status_code == 413


async def test_xff_ignored_unless_trusted():
    s = Settings(secret="t", rate_min_threshold=5, rate_hard_multiplier=100.0, behavior_threshold=2.0)
    _, c = make(s)
    codes = [(await c.get("/search", headers={"x-forwarded-for": f"9.9.9.{i}"})).status_code
             for i in range(10)]
    assert 429 in codes  # spoofed XFF did not evade the limiter
