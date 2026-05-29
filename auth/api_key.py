"""
Optional API-key authentication and rate limiting.

Both are **opt-in** and disabled by default so existing deployments and tests
are unaffected:

- Set ``REQUIRE_API_KEY=true`` and ``API_KEYS=key1,key2`` to require an
  ``X-API-Key`` (or ``Authorization: Bearer <key>``) header on protected routes.
- Set ``RATE_LIMIT_PER_MINUTE`` > 0 to enable a per-client token-bucket limiter.

Designed for FastAPI: use :func:`require_api_key` as a dependency and add
:class:`RateLimitMiddleware` to the app.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from starlette.requests import Request

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


def configured_api_keys() -> List[str]:
    """Parse the comma-separated API key allow-list from settings."""
    raw = getattr(get_settings(), "api_keys", "") or ""
    return [k.strip() for k in raw.split(",") if k.strip()]


def api_key_required() -> bool:
    return bool(getattr(get_settings(), "require_api_key", False))


def verify_api_key(provided: Optional[str]) -> bool:
    """Return True if auth is disabled or the provided key is allowed."""
    if not api_key_required():
        return True
    if not provided:
        return False
    allowed = configured_api_keys()
    return provided in allowed


def _extract_key(headers) -> Optional[str]:
    key = headers.get("x-api-key")
    if key:
        return key
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


async def require_api_key(request: "Request") -> Optional[str]:
    """
    FastAPI dependency enforcing the API key when enabled.

    Raises 401 if a key is required but missing/invalid; otherwise returns the
    key (or None when auth is disabled).
    """
    from fastapi import HTTPException

    if not api_key_required():
        return None
    key = _extract_key(request.headers)
    if not verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key


class RateLimiter:
    """A simple per-identity token-bucket rate limiter."""

    def __init__(self, per_minute: int) -> None:
        self.capacity = max(0, per_minute)
        self.refill_rate = self.capacity / 60.0  # tokens per second
        self._buckets: Dict[str, Tuple[float, float]] = {}  # id -> (tokens, last_ts)

    @property
    def enabled(self) -> bool:
        return self.capacity > 0

    def allow(self, identity: str) -> bool:
        if not self.enabled:
            return True
        now = time.time()
        tokens, last = self._buckets.get(identity, (float(self.capacity), now))
        # Refill based on elapsed time.
        tokens = min(self.capacity, tokens + (now - last) * self.refill_rate)
        if tokens >= 1.0:
            tokens -= 1.0
            self._buckets[identity] = (tokens, now)
            return True
        self._buckets[identity] = (tokens, now)
        return False


class RateLimitMiddleware:
    """ASGI middleware that applies :class:`RateLimiter` per client.

    No-ops unless ``RATE_LIMIT_PER_MINUTE`` > 0. Identity is the API key when
    present, otherwise the client IP.
    """

    def __init__(self, app, per_minute: Optional[int] = None) -> None:
        self.app = app
        if per_minute is None:
            per_minute = int(getattr(get_settings(), "rate_limit_per_minute", 0) or 0)
        self.limiter = RateLimiter(per_minute)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not self.limiter.enabled:
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        identity = _extract_key(headers)
        if not identity:
            client = scope.get("client")
            identity = client[0] if client else "anonymous"

        if not self.limiter.allow(identity):
            from starlette.responses import JSONResponse

            response = JSONResponse(
                {"detail": "Rate limit exceeded. Try again shortly."},
                status_code=429,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
