import json

import pytest

from sentinel.config import Settings
from sentinel.detectors.behavior import (FEATURE_NAMES, BehaviorDetector, HeuristicClassifier,
                                         LogisticClassifier, header_order_score)
from sentinel.models import Action
from tests.helpers import BROWSER, make_ctx

S = Settings(behavior_min_requests=6, behavior_threshold=0.9)
TOOL = [("host", "x"), ("user-agent", "python-httpx/0.27"), ("accept-encoding", "gzip"),
        ("accept", "*/*")]


async def test_fast_tool_bot_challenged():
    det, v = BehaviorDetector(S, HeuristicClassifier()), None
    for i in range(12):
        v = await det.inspect(make_ctx(f"/p{i}", ts=i * 0.01, headers=TOOL))
    assert v and v.action is Action.CHALLENGE and v.score >= 0.9


async def test_human_not_challenged():
    det = BehaviorDetector(S, HeuristicClassifier())
    t, gaps, verdicts = 0.0, [0.1, 0.2, 4.0, 0.15, 7.5, 0.1, 3.0, 11.0, 0.2, 5.0], []
    for i, g in enumerate(gaps):
        t += g
        path = ["/", "/static/app.css", "/products", "/static/app.js"][i % 4]
        verdicts.append(await det.inspect(make_ctx(path, ts=t)))
    assert all(v is None for v in verdicts)


async def test_pass_holder_exempt():
    det, v = BehaviorDetector(S, HeuristicClassifier()), None
    for i in range(12):
        v = await det.inspect(make_ctx(f"/p{i}", ts=i * 0.01, headers=TOOL, has_pass=True))
    assert v is None


def test_header_order_and_features():
    assert header_order_score(["user-agent", "accept", "accept-encoding"]) == 1.0
    assert header_order_score(["user-agent", "accept-encoding", "accept"]) < 1.0
    assert header_order_score(["host"]) == 1.0


def test_logistic_roundtrip_and_feature_guard(tmp_path):
    spec = {"features": list(FEATURE_NAMES), "mean": [0.0] * len(FEATURE_NAMES),
            "scale": [1.0] * len(FEATURE_NAMES), "coef": [0.0] * len(FEATURE_NAMES), "intercept": 0.0}
    clf = LogisticClassifier(spec)
    assert clf.predict_proba({n: 0.0 for n in FEATURE_NAMES}) == pytest.approx(0.5)
    spec["features"] = spec["features"][:-1]
    with pytest.raises(ValueError):
        LogisticClassifier(spec)


async def test_training_log_written(tmp_path):
    log = tmp_path / "t.jsonl"
    det = BehaviorDetector(Settings(behavior_min_requests=2, training_log_path=str(log)))
    for i in range(4):
        await det.inspect(make_ctx(f"/p{i}", ts=i, label="human"))
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert rows and rows[0]["label"] == "human" and set(rows[0]["features"]) == set(FEATURE_NAMES)
