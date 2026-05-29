"""Tests for optional API-key auth and rate limiting."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from auth.api_key import (
    RateLimiter,
    RateLimitMiddleware,
    configured_api_keys,
    require_api_key,
    verify_api_key,
)
from utils.config import get_settings


@pytest.fixture(autouse=True)
def clear_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _app():
    app = FastAPI()

    @app.get("/protected")
    async def protected(_=Depends(require_api_key)):
        return {"ok": True}

    return app


def test_auth_disabled_allows(monkeypatch):
    monkeypatch.delenv("REQUIRE_API_KEY", raising=False)
    get_settings.cache_clear()
    client = TestClient(_app())
    assert client.get("/protected").status_code == 200


def test_auth_enabled_rejects_missing(monkeypatch):
    monkeypatch.setenv("REQUIRE_API_KEY", "true")
    monkeypatch.setenv("API_KEYS", "secret1,secret2")
    get_settings.cache_clear()
    client = TestClient(_app())
    assert client.get("/protected").status_code == 401


def test_auth_enabled_accepts_valid_x_api_key(monkeypatch):
    monkeypatch.setenv("REQUIRE_API_KEY", "true")
    monkeypatch.setenv("API_KEYS", "secret1,secret2")
    get_settings.cache_clear()
    client = TestClient(_app())
    r = client.get("/protected", headers={"X-API-Key": "secret1"})
    assert r.status_code == 200


def test_auth_enabled_accepts_bearer(monkeypatch):
    monkeypatch.setenv("REQUIRE_API_KEY", "true")
    monkeypatch.setenv("API_KEYS", "secret1")
    get_settings.cache_clear()
    client = TestClient(_app())
    r = client.get("/protected", headers={"Authorization": "Bearer secret1"})
    assert r.status_code == 200


def test_auth_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("REQUIRE_API_KEY", "true")
    monkeypatch.setenv("API_KEYS", "secret1")
    get_settings.cache_clear()
    client = TestClient(_app())
    assert client.get("/protected", headers={"X-API-Key": "nope"}).status_code == 401


def test_verify_api_key_disabled(monkeypatch):
    monkeypatch.delenv("REQUIRE_API_KEY", raising=False)
    get_settings.cache_clear()
    assert verify_api_key(None) is True


def test_configured_api_keys_parsing(monkeypatch):
    monkeypatch.setenv("API_KEYS", " a , b ,, c ")
    get_settings.cache_clear()
    assert configured_api_keys() == ["a", "b", "c"]


def test_rate_limiter_allows_within_capacity():
    rl = RateLimiter(per_minute=60)
    assert all(rl.allow("ip") for _ in range(10))


def test_rate_limiter_blocks_over_capacity():
    rl = RateLimiter(per_minute=3)
    results = [rl.allow("ip") for _ in range(6)]
    assert results[:3] == [True, True, True]
    assert results[3] is False


def test_rate_limiter_disabled_when_zero():
    rl = RateLimiter(per_minute=0)
    assert rl.enabled is False
    assert all(rl.allow("x") for _ in range(100))


def test_rate_limit_middleware_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()
    app = FastAPI()

    @app.get("/ping")
    async def ping():
        return {"pong": True}

    app.add_middleware(RateLimitMiddleware)
    client = TestClient(app)
    codes = [client.get("/ping").status_code for _ in range(4)]
    assert 429 in codes
    assert codes[0] == 200
