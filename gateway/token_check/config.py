"""
gateway-auth settings. Environment only, all required, no defaults for the
three that decide what a valid token is — a checker that guessed its issuer or
audience would accept tokens the core refuses, or the reverse.

* ``CCURE_TOKEN_ISSUER``        — must equal the core's ``tokens.ISSUER``.
* ``CCURE_TOKEN_USER_AUDIENCE`` — must equal the core's ``tokens.USER_AUDIENCE``.
* ``CCURE_JWKS_URL``            — the core's published key set, e.g.
  ``http://api:8000/auth/jwks.json``. http or https only.
* ``CCURE_JWKS_MAX_AGE_SECONDS`` (300) — how long a fetched key set is trusted
  before it is refetched, so a key removed from the set stops verifying.
* ``CCURE_JWKS_MIN_REFETCH_SECONDS`` (30) — the floor between refetches an
  unknown ``kid`` may trigger, so a stream of forged kids cannot hammer the core.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


class ConfigError(RuntimeError):
    """gateway-auth cannot start as configured."""


@dataclass(frozen=True)
class Settings:
    issuer: str
    user_audience: str
    jwks_url: str
    jwks_max_age_seconds: float = 300.0
    jwks_min_refetch_seconds: float = 30.0


def _required(env, name: str) -> str:
    value = (env.get(name) or "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _seconds(env, name: str, default: float) -> float:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}={raw!r} is not a number") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def load(env=None) -> Settings:
    env = os.environ if env is None else env
    url = _required(env, "CCURE_JWKS_URL")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError(f"CCURE_JWKS_URL={url!r} is not an http(s) URL")
    return Settings(
        issuer=_required(env, "CCURE_TOKEN_ISSUER"),
        user_audience=_required(env, "CCURE_TOKEN_USER_AUDIENCE"),
        jwks_url=url,
        jwks_max_age_seconds=_seconds(env, "CCURE_JWKS_MAX_AGE_SECONDS", 300.0),
        jwks_min_refetch_seconds=_seconds(env, "CCURE_JWKS_MIN_REFETCH_SECONDS", 30.0),
    )
