# Sentinel — Adaptive WAF with Behavioral Bot Detection

A reverse-proxy WAF that learns what normal traffic looks like, adapts its rate thresholds,
and separates bots from humans using behavioral signals — while deliberately favouring
**low false positives** (suspicious traffic gets a proof-of-work *challenge*, not a block).

**Stack:** Python 3.11+, FastAPI/Starlette (ASGI), httpx, scikit-learn (training only).
One language across proxy, detectors, ML, simulators and tests.
