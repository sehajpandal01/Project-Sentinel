"""In-memory metrics + recent-event ring buffer feeding the dashboard.
Swap for Prometheus/Redis later behind the same three methods."""
from __future__ import annotations

from collections import Counter, deque

from sentinel.models import RequestContext, Verdict


class MetricsStore:
    def __init__(self, max_events: int = 1000, max_points: int = 720):
        self.events: deque[dict] = deque(maxlen=max_events)
        self.threshold_series: deque[dict] = deque(maxlen=max_points)
        self.by_action: Counter = Counter()
        self.by_detector: Counter = Counter()
        self.rps: dict[int, int] = {}

    def record(self, ctx: RequestContext, verdict: Verdict, enforced: bool) -> None:
        self.by_action[verdict.action.value] += 1
        if verdict.action.value != "allow":
            self.by_detector[verdict.detector] += 1
            self.events.append({
                "ts": ctx.timestamp, "ip": ctx.client_ip, "method": ctx.method,
                "path": ctx.path[:200], "action": verdict.action.value,
                "detector": verdict.detector, "reason": verdict.reason,
                "score": round(verdict.score, 3), "enforced": enforced,
            })
        sec = int(ctx.timestamp)
        self.rps[sec] = self.rps.get(sec, 0) + 1
        for old in [s for s in self.rps if s < sec - 120]:
            del self.rps[old]

    def record_threshold(self, ts: float, threshold: float, mean: float) -> None:
        self.threshold_series.append({"ts": ts, "threshold": round(threshold, 2),
                                      "baseline_mean": round(mean, 2)})

    def snapshot(self) -> dict:
        return {
            "totals": dict(self.by_action),
            "by_detector": dict(self.by_detector),
            "rps": [{"ts": s, "n": n} for s, n in sorted(self.rps.items())],
            "threshold_series": list(self.threshold_series),
        }

    def recent_events(self, limit: int = 100) -> list[dict]:
        return list(self.events)[-limit:][::-1]
