"""Adaptive CC/flood mitigation.

Per-IP sliding window. The threshold is NOT hardcoded: every `sample_interval` seconds
we sample per-IP request counts into a rolling baseline and set

    threshold = max(floor, mean + k * sigma)

IPs already over the threshold are excluded from the baseline so an attacker cannot
slowly "teach" the system that flooding is normal (baseline poisoning).
"""
from __future__ import annotations

import statistics
from collections import deque
from typing import Callable

from sentinel.config import Settings
from sentinel.models import Action, RequestContext, Verdict


class AdaptiveRateDetector:
    name = "rate"

    def __init__(self, settings: Settings,
                 on_threshold: Callable[[float, float, float], None] | None = None):
        self.s = settings
        self._hits: dict[str, deque[float]] = {}
        self._baseline: deque[int] = deque(maxlen=settings.rate_baseline_size)
        self._threshold: float = float(settings.rate_min_threshold)
        self._mean: float = 0.0
        self._last_sample: float | None = None
        self._on_threshold = on_threshold

    @property
    def threshold(self) -> float:
        return self._threshold

    def _prune(self, dq: deque[float], now: float) -> None:
        cutoff = now - self.s.rate_window_s
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def _maybe_sample(self, now: float) -> None:
        if self._last_sample is None:
            self._last_sample = now
            return
        if now - self._last_sample < self.s.rate_sample_interval_s:
            return
        self._last_sample = now
        for ip in list(self._hits):
            dq = self._hits[ip]
            self._prune(dq, now)
            if not dq:
                del self._hits[ip]  # bounds memory
            elif len(dq) <= self._threshold:  # exclude offenders from the baseline
                self._baseline.append(len(dq))
        floor = float(self.s.rate_min_threshold)
        if len(self._baseline) >= self.s.rate_min_samples:
            mean = statistics.fmean(self._baseline)
            sigma = statistics.pstdev(self._baseline)
            self._mean = mean
            self._threshold = max(floor, mean + self.s.rate_k_sigma * sigma)
        else:
            self._threshold = floor
        if self._on_threshold:
            self._on_threshold(now, self._threshold, self._mean)

    async def inspect(self, ctx: RequestContext) -> Verdict | None:
        now = ctx.timestamp
        dq = self._hits.setdefault(ctx.client_ip, deque())
        dq.append(now)
        self._prune(dq, now)
        count = len(dq)
        self._maybe_sample(now)
        thr = self._threshold
        if count > thr * self.s.rate_hard_multiplier:
            return Verdict(Action.BLOCK, self.name,
                           f"{count} req/{self.s.rate_window_s:g}s >> threshold {thr:.0f}",
                           min(1.0, count / (thr * self.s.rate_hard_multiplier)))
        if count > thr and not ctx.has_pass:
            return Verdict(Action.CHALLENGE, self.name,
                           f"{count} req/{self.s.rate_window_s:g}s > threshold {thr:.0f}",
                           min(1.0, count / (thr * self.s.rate_hard_multiplier)))
        return None
