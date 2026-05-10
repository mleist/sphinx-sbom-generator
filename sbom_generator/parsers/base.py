"""Abstract base for manifest parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import Package


class ManifestParser(ABC):
    """Parses a dependency manifest into a list of ``Package`` objects.

    Implementations should be tolerant: parse what they can and skip
    lines they don't understand (with a logged warning) rather than
    failing the whole build for one malformed entry.
    """

    @abstractmethod
    def parse(self, path: Path) -> list[Package]: ...
