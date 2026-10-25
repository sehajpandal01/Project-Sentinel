"""Stateless proof-of-work challenge (the classic Challenge Collapsar countermeasure).

Flow: server issues an HMAC-signed token bound to the client IP -> client finds a
`solution` such that sha256(f"{token}:{solution}") has `bits` leading zero bits ->
POST to /_sentinel/challenge/verify -> server sets a signed pass cookie.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from sentinel.config import Settings

PASS_COOKIE = "sentinel_pass"


@dataclass(frozen=True)
class Challenge:
    token: str
    difficulty_bits: int
    expires: int


def leading_zero_bits(digest: bytes) -> int:
    return len(digest) * 8 - int.from_bytes(digest, "big").bit_length()


def solve(token: str, bits: int) -> int:
    """Reference solver (tests and Python simulators). Browsers use the page's JS."""
    n = 0
    while leading_zero_bits(hashlib.sha256(f"{token}:{n}".encode()).digest()) < bits:
        n += 1
    return n


class ChallengeManager:
    def __init__(self, settings: Settings):
        self.s = settings
        self._key = settings.secret.encode()
        self._used: dict[str, int] = {}  # token -> expiry, blocks solution replay

    def _sig(self, msg: str) -> str:
        return hmac.new(self._key, msg.encode(), hashlib.sha256).hexdigest()

    def issue(self, ip: str, now: float | None = None) -> Challenge:
        now = now if now is not None else time.time()
        exp = int(now) + self.s.challenge_ttl_s
        bits = self.s.challenge_difficulty_bits
        payload = f"{ip}|{exp}|{secrets.token_hex(8)}|{bits}"
        return Challenge(f"{payload}.{self._sig(payload)}", bits, exp)

    def verify(self, ip: str, token: str, solution: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        payload, _, sig = token.rpartition(".")
        if not payload or not hmac.compare_digest(sig, self._sig(payload)):
            return False
        try:
            t_ip, exp, _nonce, bits = payload.split("|")
            exp, bits = int(exp), int(bits)
        except ValueError:
            return False
        if t_ip != ip or exp < now or token in self._used:
            return False
        digest = hashlib.sha256(f"{token}:{solution}".encode()).digest()
        if leading_zero_bits(digest) < bits:
            return False
        self._used = {t: e for t, e in self._used.items() if e >= now}
        self._used[token] = exp
        return True

    def issue_pass(self, ip: str, now: float | None = None) -> str:
        now = now if now is not None else time.time()
        payload = f"{ip}|{int(now) + self.s.pass_ttl_s}"
        return f"{payload}.{self._sig(payload)}"

    def check_pass(self, ip: str, value: str, now: float | None = None) -> bool:
        if not value:
            return False
        now = now if now is not None else time.time()
        payload, _, sig = value.rpartition(".")
        if not payload or not hmac.compare_digest(sig, self._sig(payload)):
            return False
        try:
            p_ip, exp = payload.split("|")
            return p_ip == ip and int(exp) >= now
        except ValueError:
            return False
