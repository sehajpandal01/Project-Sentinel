# HANDOFF — read this first

Everything below reflects the actual state of the code. 44 tests pass (`make test`).
  
## Mental model
Request -> `main.proxy` builds a `RequestContext` -> `Pipeline.evaluate` runs detectors in order
(`rules`, `rate`, `behavior`) -> first non-ALLOW verdict wins (enforce mode) -> BLOCK=403,
CHALLENGE=429 (HTML PoW page for browsers, JSON token for API clients), else forward upstream.
`monitor` mode runs *all* detectors, records, never acts (shadow testing + training-data collection).

## How to extend (all verified patterns)
- **New detector**: class with `name` and `async inspect(ctx) -> Verdict | None` (see `models.Detector`);
  add to the list in `main.create_app`. Order = cost/confidence, cheapest first.
- **New rule**: append a `Rule(id, category, regex)` in `detectors/rules.py`; add the payload to
  `tests/test_rules.py::ATTACKS` (and a lookalike to `BENIGN`).
- **New behavioral feature**: append to `FEATURE_NAMES`, compute in `extract_features`, then **retrain**
  (`LogisticClassifier` refuses a model whose feature list differs). Update `HeuristicClassifier` if useful.
- **New scenario**: add `simulate/<name>.py` using `simulate.common.cli`.
- **Detector time**: all detectors use `ctx.timestamp`, never the wall clock -> tests are deterministic.

## Measured results (simulator data only — read the caveat)
Live enforce-mode runs of `scripts/e2e.sh 40` (percent of *requests* challenged/blocked):

| Behavior classifier | Legit challenged | Gray-market (no assets) | Gray-market (loads assets) |
|---|---|---|---|
| Heuristic baseline @0.9 | 0.0% | 1.2% | 1.9% |
| Trained LR @0.403 (FPR-tuned offline) | **1.6%** | 85.7% | 89.8% |
| Trained LR @0.9 | 0.1% | 69.1% | 71.1% |

Flood: ~99% stopped (403 hard blocks + 429 challenges). Rule layer: 12/16 of `simulate.attacks` blocked.
Offline (`ml.train`): held-out FPR 0.00%, FNR 0.14%, vs heuristic FNR 13%. Raw: `models/report.json`.

**Caveat — do not quote these as real-world accuracy.** The simulated humans and gray bots differ in
artifacts of the simulator (e.g. humans also issue `/search`; reading-time means differ 3.0s vs 2.5s), so the
model learns simulator quirks. The 0% offline FPR vs 1.6% live FPR at the tuned threshold shows the gap.
`models/behavior.json` is a **demo artifact** of that data. Useful as pipeline proof, not as a production model.

## Known gaps (good next tasks, roughly by value)
1. **Realistic data**: make humans and gray bots statistically indistinguishable by construction (same
   timing distribution, same request mix), add noise/diversity, or train on public HTTP datasets.
   Then rerun `ml.train` and report honestly. Consider per-class FPR on *sessions*, not requests.
2. **Rule bypasses** (found by `simulate.attacks`, currently passing): comment-split SQLi `UN/**/ION SEL/**/ECT`;
   `onpageshow=` (handler allowlist too narrow -> switch to generic `on\w+=`); HTML-entity-encoded
   `&#106;avascript:`; newline command separator `\nid`. Fix, add to tests, re-run, document.
3. **Challenge limits**: PoW needs `crypto.subtle` (HTTPS or localhost only); a bot can solve PoW, which only
   raises its cost. Add escalating difficulty per IP; cookie is IP-bound (breaks behind CGNAT/mobile roaming).
4. **State is per-process memory** (rate counters, sessions, replay set, metrics). Multi-worker/multi-node needs
   Redis (or similar) behind the same detector interfaces; `SENTINEL_SECRET` must be shared across workers.
5. **Missing features**: TLS/JA3 fingerprint vs User-Agent mismatch (needs TLS termination you control),
   session navigation graph features, per-endpoint baselines, IPv6 /64 aggregation, WebSocket and streaming
   bodies (proxy buffers whole bodies, capped by `max_body_bytes`), rule-engine rate limits for login endpoints.
6. **Dashboard** is a single vanilla-JS page (`static/dashboard.html`) polling `/_sentinel/api/*`. A React/Next
   app can consume the same endpoints unchanged. Add CORS or serve it from the same origin.
7. **Containers untested**; add CI (pytest + ruff), a compose-based e2e job, and image scanning (trivy).
8. **Perf**: no benchmark yet. Detectors are O(1) per request except periodic baseline sampling (O(#IPs)).

## Gotchas learned while building
- `httpx.AsyncClient(headers=[...])` preserves header **order**; defaults otherwise put `accept` before
  `user-agent` (which the order feature treats as non-browser).
- Use `scope["raw_path"]` (still percent-encoded) for inspection/forwarding; `request.url.path` is decoded.
- `X-Forwarded-For` is only honoured with `SENTINEL_TRUST_FORWARDED_FOR=true` (tested that spoofing can't
  evade the limiter otherwise). Simulators need it on; production must not.
- `ASGITransport` doesn't run lifespan; `create_app(upstream_client=...)` exists so tests inject the backend ASGI app.
- Training: split by `session` (logged per row) — random row splits leak because rows within a session overlap.
- Background processes don't survive across tool calls in the authoring sandbox; `scripts/e2e.sh` is self-contained.

## Security notes
Admin API is open unless `SENTINEL_ADMIN_TOKEN` is set (the dashboard HTML itself is static; data needs the
token, pass `?token=`). Training mode (`SENTINEL_TRAINING_LOG_PATH`) trusts the `X-Sim-Label` header — never
enable it on a public listener. Secret defaults to a random per-process value.
