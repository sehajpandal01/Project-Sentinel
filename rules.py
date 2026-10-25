"""Signature layer: SQLi, XSS, path traversal, command injection.

Deliberately simple and explainable. Each rule has a stable id so test attacks and
the dashboard can reference it. Known gaps are documented in docs/HANDOFF.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from sentinel.models import Action, RequestContext, Verdict

I = re.IGNORECASE


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern


RULES: tuple[Rule, ...] = (
    Rule("sqli-union", "sqli", re.compile(r"\bunion\b[\s/*()]+(all[\s/*()]+)?select\b", I)),
    Rule("sqli-tautology", "sqli",
         re.compile(r"""['"]?\s*\b(or|and)\b\s+['"]?(\w+)['"]?\s*=\s*['"]?\2""", I)),
    Rule("sqli-quote-comment", "sqli", re.compile(r"""['"]\s*(--|#|/\*)""")),
    Rule("sqli-stacked", "sqli",
         re.compile(r";\s*(drop|insert|update|delete|alter|create|exec|truncate)\b", I)),
    Rule("sqli-time-based", "sqli",
         re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", I)),
    Rule("sqli-info-schema", "sqli", re.compile(r"\binformation_schema\b", I)),
    Rule("xss-script-tag", "xss", re.compile(r"<\s*script\b", I)),
    Rule("xss-event-handler", "xss",
         re.compile(r"\bon(error|load|click|mouseover|focus|toggle|begin)\s*=", I)),
    Rule("xss-js-uri", "xss", re.compile(r"javascript\s*:", I)),
    Rule("xss-embed-tag", "xss", re.compile(r"<\s*(iframe|object|embed|svg|img)\b[^>]*", I)),
    Rule("traversal-dotdot", "traversal", re.compile(r"(\.\./|\.\.\\)")),
    Rule("traversal-sensitive-file", "traversal",
         re.compile(r"/etc/(passwd|shadow)|\bwin\.ini\b|boot\.ini", I)),
    Rule("cmdi-shell-chain", "cmdi",
         re.compile(r"[;&|`]\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b", I)),
    Rule("cmdi-subshell", "cmdi", re.compile(r"\$\([^)]*\)")),
)

_SCANNED_HEADERS = ("user-agent", "referer", "cookie", "x-forwarded-host")
_MAX_BODY_SCAN = 64 * 1024


def normalize(value: str, rounds: int = 3) -> str:
    """Percent-decode repeatedly to defeat double encoding; strip NULs."""
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value.replace("\x00", "")


def _targets(ctx: RequestContext):
    yield "path", ctx.path
    yield "query", ctx.query
    if ctx.body:
        yield "body", ctx.body[:_MAX_BODY_SCAN].decode("utf-8", errors="ignore")
    for name in _SCANNED_HEADERS:
        val = ctx.header(name)
        if val:
            yield f"header:{name}", val


class RuleDetector:
    name = "rules"

    def __init__(self, rules: tuple[Rule, ...] = RULES):
        self.rules = rules

    def scan(self, ctx: RequestContext) -> tuple[Rule, str] | None:
        for location, raw in _targets(ctx):
            text = normalize(raw)
            for rule in self.rules:
                if rule.pattern.search(text):
                    return rule, location
        return None

    async def inspect(self, ctx: RequestContext) -> Verdict | None:
        hit = self.scan(ctx)
        if not hit:
            return None
        rule, location = hit
        return Verdict(Action.BLOCK, self.name, f"{rule.id} in {location}", 1.0)
