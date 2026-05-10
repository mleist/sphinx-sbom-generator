"""Abstract base for enrichers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import EnrichedPackage


class Enricher(ABC):
    """Adds metadata or vulnerability info to an ``EnrichedPackage`` in place.

    Enrichers must be tolerant of failures: errors are appended to
    ``EnrichedPackage.enrichment_errors`` rather than raised, so a
    transient outage of one source never blocks the rest of the report.
    """

    @abstractmethod
    def enrich(self, ep: EnrichedPackage) -> None: ...
