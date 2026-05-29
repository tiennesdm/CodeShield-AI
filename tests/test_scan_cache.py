"""Tests for the content-addressed scan result cache."""

import time

import pytest

from scanner.cache import ScanCache


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


@pytest.fixture
def cache(tmp_path):
    return ScanCache(cache_dir=str(tmp_path / "cache"), ttl_seconds=3600)


def test_key_stable_for_same_content(tmp_path):
    src = tmp_path / "src"
    _write(src, "a.py", "print('hello')\n")
    _write(src, "pkg/b.py", "x = 1\n")
    k1 = ScanCache.compute_key(str(src), "cfg")
    k2 = ScanCache.compute_key(str(src), "cfg")
    assert k1 == k2
    assert len(k1) == 64


def test_key_changes_with_content(tmp_path):
    src = tmp_path / "src"
    f = _write(src, "a.py", "print('hello')\n")
    k1 = ScanCache.compute_key(str(src))
    f.write_text("print('changed')\n")
    k2 = ScanCache.compute_key(str(src))
    assert k1 != k2


def test_key_changes_with_config(tmp_path):
    src = tmp_path / "src"
    _write(src, "a.py", "x=1\n")
    assert ScanCache.compute_key(str(src), "cfgA") != ScanCache.compute_key(str(src), "cfgB")


def test_skips_ignored_dirs(tmp_path):
    src = tmp_path / "src"
    _write(src, "a.py", "x=1\n")
    k1 = ScanCache.compute_key(str(src))
    _write(src, "node_modules/lib.js", "junk\n")
    _write(src, ".git/config", "junk\n")
    k2 = ScanCache.compute_key(str(src))
    assert k1 == k2  # ignored dirs don't change the key


def test_set_get_roundtrip(cache):
    cache.set("k1", {"scan_id": "s1", "risk_score": 42})
    assert cache.has("k1")
    assert cache.get("k1")["risk_score"] == 42


def test_miss_returns_none(cache):
    assert cache.get("nope") is None


def test_ttl_expiry(tmp_path):
    c = ScanCache(cache_dir=str(tmp_path / "c"), ttl_seconds=1)
    c.set("k", {"v": 1})
    assert c.get("k") is not None
    # Simulate expiry by rewriting cached_at in the past.
    import json
    p = c._path_for("k")
    entry = json.loads(p.read_text())
    entry["cached_at"] = time.time() - 10
    p.write_text(json.dumps(entry))
    assert c.get("k") is None  # expired -> miss


def test_config_signature_deterministic():
    a = ScanCache.config_signature({"tools": ["bandit", "semgrep"], "x": 1})
    b = ScanCache.config_signature({"x": 1, "tools": ["bandit", "semgrep"]})
    assert a == b


def test_clear_and_stats(cache):
    cache.set("a", {"v": 1})
    cache.set("b", {"v": 2})
    assert cache.stats()["entries"] == 2
    removed = cache.clear()
    assert removed == 2
    assert cache.stats()["entries"] == 0


def test_model_dump_object(cache):
    class Fake:
        def model_dump(self):
            return {"scan_id": "x", "n": 5}
    cache.set("m", Fake())
    assert cache.get("m")["n"] == 5
