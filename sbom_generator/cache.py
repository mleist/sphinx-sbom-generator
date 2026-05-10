"""Simple JSON file cache for registry and OSV API responses.

The cache is intentionally minimal: one JSON file per cache instance,
keyed by structured strings like ``pypi:requests`` or ``osv-vuln:GHSA-…``.
Entries carry a timestamp so expired data can be filtered on read.

We avoid more sophisticated stores (SQLite, diskcache, …) because the
cache typically lives next to the generated SBOM in CI artifacts; a
single human-readable JSON file makes debugging trivial — you can just
``cat .sbom-cache/cache.json`` to see what was hit and what wasn't.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class JsonFileCache:
    """File-backed key/value cache with TTL.

    Reads happen against an in-memory copy; writes only hit the disk on
    :meth:`flush`, which performs an atomic rename. That means partial
    runs (Ctrl+C, exception) never corrupt the cache file.
    """

    DEFAULT_TTL_SECONDS = 24 * 60 * 60

    def __init__(
        self,
        path: Path,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        self._data: dict[str, dict[str, Any]] = {}
        if self.enabled:
            self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                self._data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Cache file %s unreadable, starting fresh: %s", self.path, exc)
            self._data = {}

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        entry = self._data.get(key)
        if entry is None:
            return None
        if time.time() - entry.get("ts", 0) >= self.ttl_seconds:
            return None
        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        self._data[key] = {"ts": time.time(), "value": value}

    def flush(self) -> None:
        """Write the in-memory cache to disk atomically."""
        if not self.enabled:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".cache.", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
