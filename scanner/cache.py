"""
Content-addressed scan result cache.

Avoids re-scanning identical inputs: the cache key is a SHA-256 over the source
file contents (path + bytes) combined with a configuration signature (selected
tools/options). If the same code is scanned again with the same config, the
previous result can be returned instantly.

Backed by plain JSON files under ``<data_dir>/cache`` (no external service),
with a TTL. Use :meth:`ScanCache.compute_key` to derive a key and
``get``/``set`` to read/write cached results.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)

# Files/dirs that never affect scan results — skip when hashing.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox", ".cache"}
_MAX_FILE_BYTES = 5 * 1024 * 1024  # don't hash huge blobs


class ScanCache:
    """A simple, TTL'd, content-addressed cache for scan results."""

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        ttl_seconds: int = 24 * 3600,
    ) -> None:
        if cache_dir is None:
            cache_dir = str(get_settings().data_dir / "cache")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

    # ------------------------------------------------------------------
    # Key computation
    # ------------------------------------------------------------------
    @staticmethod
    def _iter_files(root: Path) -> Iterable[Path]:
        for p in sorted(root.rglob("*")):
            if p.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            yield p

    @classmethod
    def compute_key(cls, source_path: str, config_signature: str = "") -> str:
        """
        Compute a stable content hash for a file or directory + config.

        The hash covers each file's relative path and bytes, so any change to
        the code (or the config signature) yields a new key.
        """
        root = Path(source_path)
        h = hashlib.sha256()
        h.update(b"cfg:")
        h.update(config_signature.encode("utf-8"))
        h.update(b"\n")

        if root.is_file():
            files = [root]
            base = root.parent
        else:
            files = list(cls._iter_files(root))
            base = root

        for f in files:
            try:
                rel = f.relative_to(base).as_posix()
            except ValueError:
                rel = f.name
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            try:
                size = f.stat().st_size
                if size > _MAX_FILE_BYTES:
                    # Hash size + mtime instead of full content for big files.
                    h.update(f"big:{size}:{int(f.stat().st_mtime)}".encode("utf-8"))
                else:
                    with open(f, "rb") as fh:
                        h.update(fh.read())
            except OSError:
                h.update(b"unreadable")
            h.update(b"\n")

        return h.hexdigest()

    @staticmethod
    def config_signature(config: Any) -> str:
        """Build a deterministic signature string from a scan config."""
        if config is None:
            return "default"
        if hasattr(config, "model_dump"):
            data = config.model_dump()
        elif isinstance(config, dict):
            data = config
        else:
            data = getattr(config, "__dict__", {})
        return json.dumps(data, sort_keys=True, default=str)

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------
    def _path_for(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Return the cached result payload, or None on miss/expiry."""
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if self.ttl_seconds > 0 and (time.time() - entry.get("cached_at", 0)) > self.ttl_seconds:
            logger.debug("Cache entry %s expired", key)
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return entry.get("result")

    def set(self, key: str, result: Any) -> None:
        """Store a result payload (dict or any model with model_dump)."""
        if hasattr(result, "model_dump"):
            payload = result.model_dump()
        else:
            payload = result
        entry = {"cached_at": time.time(), "key": key, "result": payload}
        try:
            self._path_for(key).write_text(
                json.dumps(entry, default=str), encoding="utf-8"
            )
        except OSError as e:  # pragma: no cover
            logger.warning("Failed to write cache entry %s: %s", key, e)

    def has(self, key: str) -> bool:
        return self.get(key) is not None

    def clear(self) -> int:
        """Delete all cache entries. Returns the number removed."""
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
        return count

    def stats(self) -> Dict[str, Any]:
        files = list(self.cache_dir.glob("*.json"))
        return {
            "entries": len(files),
            "cache_dir": str(self.cache_dir),
            "ttl_seconds": self.ttl_seconds,
            "size_bytes": sum(f.stat().st_size for f in files if f.exists()),
        }
