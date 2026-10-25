"""Thin reverse-proxy forwarding helper."""
from __future__ import annotations

import httpx
from starlette.responses import Response

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailers", "transfer-encoding", "upgrade"}
_DROP_REQ = HOP_BY_HOP | {"host", "content-length", "x-sim-label", "x-forwarded-for"}
_DROP_RESP = HOP_BY_HOP | {"content-length", "content-encoding"}  # httpx already decoded


async def forward(client: httpx.AsyncClient, method: str, target: str,
                  headers: list[tuple[str, str]], body: bytes, client_ip: str) -> Response:
    fwd = [(k, v) for k, v in headers if k.lower() not in _DROP_REQ]
    fwd.append(("x-forwarded-for", client_ip))
    try:
        r = await client.request(method, target, headers=fwd, content=body)
    except httpx.RequestError:
        return Response(b'{"error":"bad_gateway"}', 502, media_type="application/json")
    resp = Response(content=r.content, status_code=r.status_code)
    for k, v in r.headers.multi_items():
        if k.lower() not in _DROP_RESP:
            resp.headers.append(k, v)
    return resp
