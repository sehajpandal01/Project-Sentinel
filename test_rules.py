import pytest

from sentinel.detectors.rules import RuleDetector
from sentinel.models import Action
from tests.helpers import make_ctx

ATTACKS = [
    ("/search", "q=1' OR '1'='1"),
    ("/search", "q=1 UNION SELECT username,password FROM users"),
    ("/search", "q=1%27%20or%201%3D1--"),
    ("/search", "q=%2527%2520OR%25201%253D1"),  # double-encoded
    ("/search", "q=1;DROP TABLE users"),
    ("/search", "q=1 AND SLEEP(5)"),
    ("/search", "q=<script>alert(1)</script>"),
    ("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("/search", "q=<img src=x onerror=alert(1)>"),
    ("/search", "q=javascript:alert(1)"),
    ("/files/..%2f..%2fetc/passwd", ""),
    ("/files", "name=../../etc/passwd"),
    ("/ping", "host=8.8.8.8;cat /etc/passwd"),
    ("/ping", "host=$(whoami)"),
]
BENIGN = [
    ("/", ""), ("/products", "page=2&sort=price"), ("/search", "q=rock and roll"),
    ("/search", "q=union station schedule"), ("/search", "q=it's a nice day"),
    ("/about", "ref=a&b=c"), ("/search", "q=select the best laptop"),
]


@pytest.mark.parametrize("path,query", ATTACKS)
async def test_attacks_blocked(path, query):
    v = await RuleDetector().inspect(make_ctx(path, query))
    assert v is not None and v.action is Action.BLOCK, (path, query)


@pytest.mark.parametrize("path,query", BENIGN)
async def test_benign_allowed(path, query):
    assert await RuleDetector().inspect(make_ctx(path, query)) is None, (path, query)


async def test_body_and_header_scanned():
    v = await RuleDetector().inspect(make_ctx("/login", body=b'{"u":"admin\' --"}', method="POST"))
    assert v and "body" in v.reason
    h = [("user-agent", "<script>alert(1)</script>")]
    v = await RuleDetector().inspect(make_ctx(headers=h))
    assert v and "header" in v.reason
