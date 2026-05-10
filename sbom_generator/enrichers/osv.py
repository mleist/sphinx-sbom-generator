"""OSV.dev vulnerability enricher.

OSV.dev exposes a batch query endpoint that takes up to 1000 queries
in a single request, which is dramatically more efficient than per-package
GETs. Each query returns a list of vulnerability IDs; we then fetch full
details for each unique ID (cached aggressively, since they don't change).

We query by ``(ecosystem, name, version)``. For unpinned specs we use the
package's resolved/latest version — see ``EnrichedPackage.resolved_version``.
That means findings represent "what would you ship today if you installed
right now", not "what could possibly be installed under your spec range".
The latter would require a full resolver and is out of scope.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from ..cache import JsonFileCache
from ..models import EnrichedPackage, Vulnerability
from .base import Enricher

log = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
TIMEOUT = 15
BATCH_SIZE = 100  # well under the 1000 limit; smaller = faster recovery on errors


class OsvEnricher(Enricher):
    """Vulnerability lookup against OSV.dev.

    Use :meth:`enrich_all` for batch processing — that's the preferred
    path. The single-package :meth:`enrich` method exists only to satisfy
    the ``Enricher`` interface and does one round-trip per package.
    """

    def __init__(
        self,
        cache: JsonFileCache,
        session: requests.Session | None = None,
    ) -> None:
        self.cache = cache
        self.session = session or requests.Session()

    # --- single-package path (interface compatibility) ---

    def enrich(self, ep: EnrichedPackage) -> None:
        version = ep.resolved_version
        if not version:
            ep.enrichment_errors.append("OSV: no resolvable version to query")
            return
        ids = self._query_versions([(ep.package.ecosystem.value, ep.package.name, version)])
        if ids is None:
            ep.enrichment_errors.append("OSV: query failed")
            return
        ep.vulnerabilities = [v for v in (self._fetch_vuln(i) for i in ids[0]) if v is not None]

    # --- preferred batch path ---

    def enrich_all(self, eps: list[EnrichedPackage]) -> None:
        targets = [ep for ep in eps if ep.resolved_version]
        for ep in eps:
            if not ep.resolved_version:
                ep.enrichment_errors.append("OSV: no resolvable version to query")

        for chunk_start in range(0, len(targets), BATCH_SIZE):
            chunk = targets[chunk_start : chunk_start + BATCH_SIZE]
            # `targets` was filtered for truthy `resolved_version`, but mypy
            # can't follow that across two list comprehensions — re-narrow
            # inline so the tuple type is concretely (str, str, str).
            queries: list[tuple[str, str, str]] = [
                (ep.package.ecosystem.value, ep.package.name, ep.resolved_version)
                for ep in chunk
                if ep.resolved_version is not None
            ]
            results = self._query_versions(queries)
            if results is None:
                for ep in chunk:
                    ep.enrichment_errors.append("OSV: batch query failed")
                continue
            for ep, ids in zip(chunk, results):
                ep.vulnerabilities = [
                    v for v in (self._fetch_vuln(i) for i in ids) if v is not None
                ]

    # --- internals ---

    def _query_versions(self, items: list[tuple[str, str, str]]) -> list[list[str]] | None:
        """Return one list of vulnerability IDs per input tuple, or None on failure."""
        payload = {
            "queries": [
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
                for ecosystem, name, version in items
            ]
        }
        try:
            resp = self.session.post(OSV_BATCH_URL, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            log.warning("OSV batch query failed: %s", exc)
            return None

        out: list[list[str]] = []
        for entry in data.get("results", []):
            vulns = entry.get("vulns") or []
            out.append([v.get("id") for v in vulns if v.get("id")])
        # results length should match queries length; pad defensively
        while len(out) < len(items):
            out.append([])
        return out

    def _fetch_vuln(self, vuln_id: str) -> Vulnerability | None:
        cache_key = f"osv-vuln:{vuln_id}"
        data = self.cache.get(cache_key)
        if data is None:
            try:
                resp = self.session.get(OSV_VULN_URL.format(id=vuln_id), timeout=TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                self.cache.set(cache_key, data)
            except (requests.RequestException, ValueError) as exc:
                log.warning("OSV vuln fetch %s failed: %s", vuln_id, exc)
                return None
        return _parse_vuln(data)


def _parse_vuln(data: dict[str, Any]) -> Vulnerability:
    severity = None
    sev_list = data.get("severity") or []
    if sev_list:
        first = sev_list[0]
        severity = f"{first.get('type', '')}: {first.get('score', '')}".strip(": ")
    if not severity:
        # GHSA-style severity (LOW/MEDIUM/HIGH/CRITICAL) lives here
        ds = data.get("database_specific") or {}
        severity = ds.get("severity")

    fixed: list[str] = []
    for affected in data.get("affected") or []:
        for r in affected.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])

    refs = [r.get("url") for r in (data.get("references") or []) if r.get("url")]

    summary = (data.get("summary") or data.get("details") or "").strip()
    summary = summary.split("\n")[0]
    if len(summary) > 300:
        summary = summary[:300] + "…"

    return Vulnerability(
        id=data.get("id", "unknown"),
        summary=summary,
        severity=severity,
        fixed_versions=tuple(dict.fromkeys(fixed)),  # dedupe, preserve order
        references=tuple(refs),
    )
