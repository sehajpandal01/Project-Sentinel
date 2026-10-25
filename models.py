"""Core types shared by every detector. Keep this module dependency-free."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class Action(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"  # proof-of-work step; the soft, low-false-positive option
    BLOCK = "block"


@dataclass(slots=True)
class RequestContext:
    client_ip: str
    method: str
    path: str  # raw (still percent-encoded) path, no query string
    query: str
    headers: list[tuple[str, str]]  # original order preserved on purpose
    body: bytes = b""
    timestamp: float = field(default_factory=time.time)
    has_pass: bool = False  # client holds a valid solved-challenge cookie
    label: str | None = None  # ground-truth label, only set in training mode

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    @property
    def header_names(self) -> list[str]:
        return [k.lower() for k, _ in self.headers]


@dataclass(frozen=True, slots=True)
class Verdict:
    action: Action
    detector: str
    reason: str = ""
    score: float = 0.0

    @classmethod
    def allow(cls) -> "Verdict":
        return cls(Action.ALLOW, "none")


@runtime_checkable
class Detector(Protocol):
    """Extension point. Add a detector by implementing this and registering it
    in `sentinel.main.create_app`. Return None (or ALLOW) to abstain."""

    name: str

    async def inspect(self, ctx: RequestContext) -> Verdict | None: ...
