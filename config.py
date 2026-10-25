"""All tunables live here. Every field can be overridden via SENTINEL_<FIELD> env vars."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, fields


def _coerce(raw: str, typ: str):
    t = typ.replace(" ", "")
    if t.startswith("bool"):
        return raw.lower() in ("1", "true", "yes", "on")
    if t.startswith("int"):
        return int(raw)
    if t.startswith("float"):
        return float(raw)
    return raw


@dataclass(frozen=True)
class Settings:
    upstream_url: str = "http://backend:9000"
    # "enforce": short-circuit and act. "monitor": run ALL detectors, log, never act.
    mode: str = "enforce"
    # Only enable behind a trusted load balancer; otherwise clients can spoof their IP.
    trust_forwarded_for: bool = False
    max_body_bytes: int = 1_000_000
    upstream_timeout_s: float = 15.0

    # Adaptive rate limiting: threshold = max(floor, mean + k * sigma) over a rolling baseline
    rate_window_s: float = 10.0
    rate_min_threshold: int = 30
    rate_k_sigma: float = 3.0
    rate_hard_multiplier: float = 3.0  # count > threshold * this  => BLOCK instead of CHALLENGE
    rate_sample_interval_s: float = 5.0
    rate_min_samples: int = 30  # use the static floor until the baseline has this many samples
    rate_baseline_size: int = 2000

    # Proof-of-work challenge (browser SubtleCrypto: 16 bits ~ 1-3 s)
    challenge_difficulty_bits: int = 16
    challenge_ttl_s: int = 120
    pass_ttl_s: int = 900
    secret: str = field(default_factory=lambda: secrets.token_hex(32))  # set explicitly in prod

    # Behavioral detector
    behavior_threshold: float = 0.90  # high on purpose: favour low false positives
    behavior_min_requests: int = 6
    behavior_session_ttl_s: float = 600.0
    behavior_max_sessions: int = 50_000
    model_path: str | None = None  # JSON exported by ml/train.py; heuristic baseline if unset
    training_log_path: str | None = None  # JSONL of {label, features}; enables X-Sim-Label

    admin_token: str | None = None  # if set, /_sentinel/api/* requires X-Admin-Token

    @classmethod
    def from_env(cls, prefix: str = "SENTINEL_") -> "Settings":
        kwargs = {}
        for f in fields(cls):
            raw = os.environ.get(prefix + f.name.upper())
            if raw not in (None, ""):
                kwargs[f.name] = _coerce(raw, str(f.type))
        return cls(**kwargs)
