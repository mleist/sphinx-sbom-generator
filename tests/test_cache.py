"""Tests for the JSON file cache."""

from __future__ import annotations

import json
from pathlib import Path

from sbom_generator.cache import JsonFileCache


def test_set_and_get_roundtrip(tmp_path: Path) -> None:
    cache = JsonFileCache(path=tmp_path / "c.json")
    cache.set("k", {"v": 1})
    assert cache.get("k") == {"v": 1}


def test_disabled_cache_is_a_noop(tmp_path: Path) -> None:
    cache = JsonFileCache(path=tmp_path / "c.json", enabled=False)
    cache.set("k", "v")
    assert cache.get("k") is None
    cache.flush()
    assert not (tmp_path / "c.json").exists()


def test_expired_entries_are_treated_as_missing(tmp_path: Path) -> None:
    cache = JsonFileCache(path=tmp_path / "c.json", ttl_seconds=0)
    cache.set("k", "v")
    # ttl=0 means anything older than "now" is stale, so reads should
    # return None.
    assert cache.get("k") is None


def test_flush_writes_atomically(tmp_path: Path) -> None:
    cache = JsonFileCache(path=tmp_path / "c.json")
    cache.set("foo", 42)
    cache.flush()

    written = json.loads((tmp_path / "c.json").read_text())
    assert written["foo"]["value"] == 42
    assert "ts" in written["foo"]


def test_corrupt_cache_file_recovers(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    path.write_text("not valid json")

    # Should not raise; should start with empty cache.
    cache = JsonFileCache(path=path)
    assert cache.get("anything") is None
    cache.set("k", "v")
    cache.flush()
    assert cache.get("k") == "v"


def test_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    cache1 = JsonFileCache(path=path)
    cache1.set("k", "v")
    cache1.flush()

    cache2 = JsonFileCache(path=path)
    assert cache2.get("k") == "v"
