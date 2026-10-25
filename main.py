"""App factory. Wires settings -> detectors -> pipeline -> proxy + admin routes."""
from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from sentinel.challenge import PASS_COOKIE, ChallengeManager
from sentinel.config import Settings
from sentinel.detectors.behavior import BehaviorDetector, load_classifier
from sentinel.detectors.rate import AdaptiveRateDetector
from sentinel.detectors.rules import RuleDetector
from sentinel.metrics import MetricsStore
from sentinel.models import Action, Detector, RequestContext
from sentinel.pipeline import Pipeline
from sentinel.proxy import forward

STATIC = Path(__file__).parent / "static"
ADMIN_PREFIX = "/_sentinel"
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

CHALLENGE_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Checking your browser</title></head>
<body style="font:16px system-ui;text-align:center;margin-top:20vh"><p id="m">Checking your browser&hellip;</p>
<script>
const T=__TOKEN__,B=__BITS__;
function lz(b){let n=0;for(const x of b){if(x===0){n+=8;continue}n+=Math.clz32(x)-24;break}return n}
(async()=>{const e=new TextEncoder();let n=0;
 while(true){const d=new Uint8Array(await crypto.subtle.digest("SHA-256",e.encode(T+":"+n)));
  if(lz(d)>=B)break;n++}
 const r=await fetch("/_sentinel/challenge/verify",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({token:T,solution:String(n)})});
 if(r.ok)location.reload();else document.getElementById("m").textContent="Verification failed."})();
</script><noscript>JavaScript is required.</noscript></body></html>"""


def client_ip(request: Request, s: Settings) -> str:
    if s.trust_forwarded_for:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings | None = None,
               upstream_client: httpx.AsyncClient | None = None,
               detectors: list[Detector] | None = None) -> FastAPI:
    s = settings or Settings.from_env()
    metrics = MetricsStore()
    challenges = ChallengeManager(s)
    rate = AdaptiveRateDetector(s, on_threshold=metrics.record_threshold)
    behavior = BehaviorDetector(s, load_classifier(s.model_path))
    # ORDER MATTERS: cheap, high-confidence checks first.
    pipeline = Pipeline(detectors or [RuleDetector(), rate, behavior], s.mode, metrics)

    owns_client = upstream_client is None
    client = upstream_client or httpx.AsyncClient(base_url=s.upstream_url,
                                                  timeout=s.upstream_timeout_s)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if owns_client:
            await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings, app.state.metrics, app.state.pipeline = s, metrics, pipeline

    def require_admin(request: Request) -> None:
        if s.admin_token and request.headers.get("x-admin-token") != s.admin_token:
            raise HTTPException(401, "admin token required")

    @app.get(f"{ADMIN_PREFIX}/health")
    async def health():
        return {"status": "ok", "mode": s.mode}

    @app.get(f"{ADMIN_PREFIX}/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return (STATIC / "dashboard.html").read_text()

    @app.get(f"{ADMIN_PREFIX}/api/metrics")
    async def api_metrics(request: Request):
        require_admin(request)
        return {**metrics.snapshot(), "current_threshold": rate.threshold}

    @app.get(f"{ADMIN_PREFIX}/api/events")
    async def api_events(request: Request, limit: int = 100):
        require_admin(request)
        return metrics.recent_events(max(1, min(limit, 1000)))

    @app.post(f"{ADMIN_PREFIX}/challenge/verify")
    async def challenge_verify(request: Request):
        ip = client_ip(request, s)
        try:
            data = await request.json()
            ok = challenges.verify(ip, str(data["token"]), str(data["solution"]))
        except (ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            return JSONResponse({"ok": False}, status_code=403)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(PASS_COOKIE, challenges.issue_pass(ip), max_age=s.pass_ttl_s,
                        httponly=True, samesite="lax")
        return resp

    def challenge_response(request: Request, ip: str, reason: str) -> Response:
        ch = challenges.issue(ip)
        if "text/html" in request.headers.get("accept", ""):
            page = (CHALLENGE_PAGE.replace("__TOKEN__", json.dumps(ch.token).replace("<", "\\u003c"))
                    .replace("__BITS__", str(ch.difficulty_bits)))
            return HTMLResponse(page, status_code=429)
        return JSONResponse({"error": "challenge_required", "reason": reason, "token": ch.token,
                             "difficulty_bits": ch.difficulty_bits,
                             "verify": f"{ADMIN_PREFIX}/challenge/verify"}, status_code=429)

    @app.api_route("/{full_path:path}", methods=METHODS)
    async def proxy(request: Request, full_path: str):
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > s.max_body_bytes:
            return JSONResponse({"error": "payload_too_large"}, status_code=413)
        body = await request.body()
        if len(body) > s.max_body_bytes:
            return JSONResponse({"error": "payload_too_large"}, status_code=413)

        ip = client_ip(request, s)
        raw_path = (request.scope.get("raw_path") or request.url.path.encode()).decode("latin-1")
        raw_path = raw_path.split("?", 1)[0]
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
        ctx = RequestContext(
            client_ip=ip, method=request.method, path=raw_path, query=request.url.query,
            headers=headers, body=body,
            has_pass=challenges.check_pass(ip, request.cookies.get(PASS_COOKIE, "")),
            label=request.headers.get("x-sim-label") if s.training_log_path else None,
        )
        verdict = await pipeline.evaluate(ctx)
        rid = uuid.uuid4().hex[:8]
        if verdict.action is Action.BLOCK:
            return JSONResponse({"error": "blocked", "request_id": rid}, status_code=403,
                                headers={"x-request-id": rid})
        if verdict.action is Action.CHALLENGE:
            return challenge_response(request, ip, verdict.reason)
        target = raw_path + (f"?{ctx.query}" if ctx.query else "")
        resp = await forward(client, request.method, target, headers, body, ip)
        resp.headers["x-request-id"] = rid
        return resp

    return app


def app_factory() -> FastAPI:  # uvicorn --factory sentinel.main:app_factory
    return create_app()
