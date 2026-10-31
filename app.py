"""Toy upstream app the WAF protects. Intentionally trivial.""" 
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
app = FastAPI()
PAGE = ('<html><head><link rel="stylesheet" href="/static/app.css"><script src="/static/app.js"></script>'
        '</head><body><h1>{title}</h1><a href="/products">products</a> <a href="/about">about</a>'
        '</body></html>')

@app.get("/", response_class=HTMLResponse)
async def index():
    return PAGE.format(title="Home")
@app.get("/products", response_class=HTMLResponse)
async def products():
    return PAGE.format(title="Products")
@app.get("/about", response_class=HTMLResponse)
async def about():
    return PAGE.format(title="About")
@app.get("/search")
async def search(q: str = ""):
    return {"query": q, "results": []}


@app.post("/login")
async def login(request: Request):
    return {"ok": True, "received_bytes": len(await request.body())}


@app.get("/static/app.css", response_class=PlainTextResponse)
async def css():
    return "body{font-family:sans-serif}"


@app.get("/static/app.js", response_class=PlainTextResponse)
async def js():
    return "console.log('hi')"


@app.get("/favicon.ico")
async def favicon():
    return PlainTextResponse("", status_code=204)
