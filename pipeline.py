"""Runs detectors in order. Enforce mode short-circuits on the first non-ALLOW
verdict; monitor mode runs everything (useful for shadow-testing and collecting
training data) and never acts."""
from __future__ import annotations

from sentinel.metrics import MetricsStore
from sentinel.models import Action, Detector, RequestContext, Verdict


class Pipeline:
    def __init__(self, detectors: list[Detector], mode: str, metrics: MetricsStore):
        self.detectors, self.mode, self.metrics = detectors, mode, metrics

    async def evaluate(self, ctx: RequestContext) -> Verdict:
        enforce = self.mode == "enforce"
        first: Verdict | None = None
        for det in self.detectors:
            v = await det.inspect(ctx)
            if v is None or v.action is Action.ALLOW:
                continue
            if first is None:
                first = v
            if enforce:
                break
        if first is None:
            self.metrics.record(ctx, Verdict.allow(), enforced=enforce)
            return Verdict.allow()
        self.metrics.record(ctx, first, enforced=enforce)
        return first if enforce else Verdict.allow()
