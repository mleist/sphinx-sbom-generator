"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from sbom_generator.cache import JsonFileCache


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def disabled_cache(tmp_path: Path) -> JsonFileCache:
    """A cache that never persists. Tests should mock the network instead."""
    return JsonFileCache(path=tmp_path / "cache.json", enabled=False)


@pytest.fixture
def file_cache(tmp_path: Path) -> Iterator[JsonFileCache]:
    """A real on-disk cache scoped to the test's tmp_path."""
    cache = JsonFileCache(path=tmp_path / "cache.json", ttl_seconds=60)
    yield cache
    cache.flush()
