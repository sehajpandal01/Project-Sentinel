Sentinel — Adaptive WAF with Behavioral Bot Detection

A reverse-proxy WAF that learns what normal traffic looks like, adapts its rate thresholds, and separates bots from humans using behavioral signals — while deliberately favouring low false positives (suspicious traffic gets a proof-of-work challenge, not a block).

Stack: Python 3.11+, FastAPI/Starlette (ASGI), httpx, scikit-learn (training only). One language across proxy, detectors, ML, simulators and tests.

Client -> [ Sentinel ] -> Backend
            1. RuleDetector      SQLi / XSS / traversal / cmdi signatures      -> BLOCK
            2. AdaptiveRate      per-IP window, threshold = mean + k*sigma     -> CHALLENGE / BLOCK
            3. BehaviorDetector  session features -> classifier -> bot score   -> CHALLENGE
            +  PoW challenge     HMAC-signed, IP-bound, replay-protected
            +  Metrics + /_sentinel/dashboard
Quickstart
bash
pip install -e ".[dev,ml]"
make test                      # 44 tests
make backend                   # terminal 1: toy backend on :9000
make waf                       # terminal 2: WAF on :8080
open http://localhost:8080/_sentinel/dashboard
python -m simulate.attacks     # self-attack the rule layer
make e2e                       # full scenario run (attacks, humans, gray-market bots, flood)

Everything is configured through SENTINEL_* env vars (see src/sentinel/config.py).

Layout
Path	Purpose
src/sentinel/main.py	app factory: wiring, proxy route, admin + challenge routes
src/sentinel/models.py	RequestContext, Verdict, Detector protocol (the extension point)
src/sentinel/pipeline.py	ordered detector execution, enforce vs monitor mode
src/sentinel/detectors/	rules.py, rate.py, behavior.py (features + classifiers)
src/sentinel/challenge.py	proof-of-work issue/verify + pass cookie
backend/	toy upstream app
simulate/	legit / flood / gray-market / rule-attack traffic generators
ml/train.py	session-split training, FP-targeted threshold tuning, JSON export
scripts/e2e.sh	one-command end-to-end run
docs/HANDOFF.md	start here for further development: status, gaps, roadmap

Containers: Dockerfile + docker-compose.yml (isolated internal network, non-root, read-only FS, dropped caps). Untested — written without Docker access.
