"""Behavioral bot detection.

Pipeline: per-session history -> fixed feature vector (FEATURE_NAMES) -> Classifier
-> probability of "bot". A high-threshold hit yields CHALLENGE (never a hard block),
because false positives are the cost we most want to avoid.

The same `extract_features` runs at serve time and in ml/train.py, so training and
serving cannot drift apart. Add a feature = append to FEATURE_NAMES + compute it.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from statistics import fmean, pstdev
from typing import Protocol

from sentinel.config import Settings
from sentinel.models import Action, RequestContext, Verdict

STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".map", ".webp")
TOOL_UA = re.compile(r"python|curl|wget|httpx|requests|aiohttp|go-http|scrapy|java/|okhttp|libwww",
                     re.I)

FEATURE_NAMES: tuple[str, ...] = (
    "n_requests", "mean_gap", "min_gap", "gap_cv", "unique_path_ratio", "static_ratio",
    "referer_ratio", "missing_ua", "ua_is_tool", "missing_accept_lang", "missing_accept",
    "browser_ua_no_sec_fetch", "header_count", "header_order_score",
)

# (earlier, later) pairs that real browsers satisfy but many HTTP libraries do not.
_ORDER_PAIRS = (("user-agent", "accept"), ("accept", "accept-encoding"),
                ("accept", "accept-language"))


@dataclass(slots=True)
class _Hit:
    ts: float
    path: str
    is_static: bool
    has_referer: bool


@dataclass(slots=True)
class _Session:
    hits: deque = field(default_factory=lambda: deque(maxlen=64))
    last_seen: float = 0.0


def header_order_score(names: list[str]) -> float:
    pos = {n: i for i, n in reversed(list(enumerate(names)))}
    ok = total = 0
    for a, b in _ORDER_PAIRS:
        if a in pos and b in pos:
            total += 1
            ok += pos[a] < pos[b]
    return ok / total if total else 1.0


def extract_features(hits, ctx: RequestContext) -> dict[str, float]:
    hits = list(hits)
    n = len(hits)
    gaps = [b.ts - a.ts for a, b in zip(hits, hits[1:])] or [0.0]
    mean_gap = fmean(gaps)
    cv = pstdev(gaps) / mean_gap if mean_gap > 1e-9 and len(gaps) > 1 else 0.0
    ua = ctx.header("user-agent") or ""
    browser_ua = "mozilla" in ua.lower()
    names = ctx.header_names
    return {
        "n_requests": float(n),
        "mean_gap": min(mean_gap, 60.0),
        "min_gap": min(min(gaps), 60.0),
        "gap_cv": min(cv, 5.0),
        "unique_path_ratio": len({h.path for h in hits}) / n if n else 0.0,
        "static_ratio": sum(h.is_static for h in hits) / n if n else 0.0,
        "referer_ratio": sum(h.has_referer for h in hits) / n if n else 0.0,
        "missing_ua": float(not ua),
        "ua_is_tool": float(bool(TOOL_UA.search(ua))),
        "missing_accept_lang": float(browser_ua and "accept-language" not in names),
        "missing_accept": float("accept" not in names),
        "browser_ua_no_sec_fetch": float(browser_ua and "sec-fetch-mode" not in names),
        "header_count": float(len(names)),
        "header_order_score": header_order_score(names),
    }


class Classifier(Protocol):
    def predict_proba(self, features: dict[str, float]) -> float: ...
    def explain(self, features: dict[str, float]) -> str: ...


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))


class HeuristicClassifier:
    """Hand-weighted baseline so the system works before any model is trained.
    It intentionally struggles on slow, human-timed bots (the 'gray market' scenario):
    that gap is what the trained model in ml/ is meant to close."""

    def _contribs(self, f: dict[str, float]) -> dict[str, float]:
        c = {"bias": -3.0}
        c["missing_ua"] = 3.0 * f["missing_ua"]
        c["ua_is_tool"] = 3.5 * f["ua_is_tool"]
        c["missing_accept_lang"] = 1.5 * f["missing_accept_lang"]
        c["browser_ua_no_sec_fetch"] = 1.0 * f["browser_ua_no_sec_fetch"]
        c["header_order"] = 1.5 * (1.0 - f["header_order_score"])
        c["machine_regular_timing"] = 2.5 if f["gap_cv"] < 0.15 and f["n_requests"] >= 6 else 0.0
        c["very_fast"] = 2.0 if f["mean_gap"] < 0.3 else 0.0
        c["no_static_assets"] = 1.2 if f["static_ratio"] == 0 and f["n_requests"] >= 8 else 0.0
        return c

    def predict_proba(self, features: dict[str, float]) -> float:
        return _sigmoid(sum(self._contribs(features).values()))

    def explain(self, features: dict[str, float]) -> str:
        top = sorted(((k, v) for k, v in self._contribs(features).items()
                      if k != "bias" and v > 0), key=lambda kv: -kv[1])[:3]
        return ", ".join(k for k, _ in top) or "no strong signal"


class LogisticClassifier:
    """Pure-Python inference for a model exported by ml/train.py (no sklearn at runtime)."""

    def __init__(self, spec: dict):
        if tuple(spec["features"]) != FEATURE_NAMES:
            raise ValueError("model feature list does not match FEATURE_NAMES; retrain")
        self.mean, self.scale = spec["mean"], spec["scale"]
        self.coef, self.intercept = spec["coef"], spec["intercept"]

    @classmethod
    def load(cls, path: str) -> "LogisticClassifier":
        return cls(json.loads(Path(path).read_text()))

    def _terms(self, f):
        return [c * (f[n] - m) / (s or 1.0) for n, c, m, s
                in zip(FEATURE_NAMES, self.coef, self.mean, self.scale)]

    def predict_proba(self, features):
        return _sigmoid(self.intercept + sum(self._terms(features)))

    def explain(self, features):
        terms = sorted(zip(FEATURE_NAMES, self._terms(features)), key=lambda kv: -kv[1])[:3]
        return ", ".join(n for n, v in terms if v > 0) or "no strong signal"


def load_classifier(model_path: str | None) -> Classifier:
    return LogisticClassifier.load(model_path) if model_path else HeuristicClassifier()


class BehaviorDetector:
    name = "behavior"

    def __init__(self, settings: Settings, classifier: Classifier | None = None):
        self.s = settings
        self.classifier = classifier or HeuristicClassifier()
        self._sessions: dict[str, _Session] = {}

    @staticmethod
    def session_key(ctx: RequestContext) -> str:
        ua = hashlib.sha1((ctx.header("user-agent") or "").encode()).hexdigest()[:8]
        return f"{ctx.client_ip}|{ua}"

    def _evict(self, now: float) -> None:
        if len(self._sessions) < self.s.behavior_max_sessions:
            return
        cutoff = now - self.s.behavior_session_ttl_s
        for k in [k for k, v in self._sessions.items() if v.last_seen < cutoff]:
            del self._sessions[k]
        if len(self._sessions) >= self.s.behavior_max_sessions:  # still full: drop oldest
            for k in sorted(self._sessions, key=lambda k: self._sessions[k].last_seen)[:1000]:
                del self._sessions[k]

    def _record(self, ctx: RequestContext) -> _Session:
        self._evict(ctx.timestamp)
        sess = self._sessions.setdefault(self.session_key(ctx), _Session())
        if sess.hits and ctx.timestamp - sess.last_seen > self.s.behavior_session_ttl_s:
            sess.hits.clear()
        sess.last_seen = ctx.timestamp
        path = ctx.path.lower()
        sess.hits.append(_Hit(ctx.timestamp, path, path.endswith(STATIC_EXT),
                              ctx.header("referer") is not None))
        return sess

    def score(self, ctx: RequestContext) -> tuple[float, dict[str, float]] | None:
        sess = self._record(ctx)
        if len(sess.hits) < self.s.behavior_min_requests:
            return None
        feats = extract_features(sess.hits, ctx)
        return self.classifier.predict_proba(feats), feats

    async def inspect(self, ctx: RequestContext) -> Verdict | None:
        scored = self.score(ctx)
        if scored is None:
            return None
        p, feats = scored
        if self.s.training_log_path and ctx.label:
            with open(self.s.training_log_path, "a") as fh:
                fh.write(json.dumps({"label": ctx.label, "session": self.session_key(ctx),
                                     "features": feats}) + "\n")
        if p >= self.s.behavior_threshold and not ctx.has_pass:
            return Verdict(Action.CHALLENGE, self.name,
                           f"bot score {p:.2f}: {self.classifier.explain(feats)}", p)
        return None
