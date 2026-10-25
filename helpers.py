from sentinel.models import RequestContext

BROWSER = [("host", "x"), ("user-agent", "Mozilla/5.0 Chrome/120"), ("accept", "text/html"),
           ("accept-language", "en-US"), ("accept-encoding", "gzip"), ("sec-fetch-mode", "navigate")]


def make_ctx(path="/", query="", ip="1.1.1.1", ts=0.0, headers=None, body=b"", method="GET", **kw):
    return RequestContext(client_ip=ip, method=method, path=path, query=query,
                          headers=list(headers if headers is not None else BROWSER),
                          body=body, timestamp=ts, **kw)
