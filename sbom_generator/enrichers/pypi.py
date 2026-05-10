"""PyPI metadata enricher.

Fetches description, latest version, homepage, and license from the
PyPI JSON API at ``https://pypi.org/pypi/{name}/json``.

Failures (404, network, malformed JSON) are recorded on the package
rather than raised; the SBOM should still build with whatever data
we managed to collect.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from ..cache import JsonFileCache
from ..models import Ecosystem, EnrichedPackage
from .base import Enricher

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/{name}/json"
TIMEOUT = 10


class PyPIEnricher(Enricher):
    def __init__(
        self,
        cache: JsonFileCache,
        session: requests.Session | None = None,
    ) -> None:
        self.cache = cache
        self.session = session or requests.Session()

    def enrich(self, ep: EnrichedPackage) -> None:
        if ep.package.ecosystem != Ecosystem.PYPI:
            return

        name = ep.package.name
        cache_key = f"pypi:{name.lower()}"
        data = self.cache.get(cache_key)

        if data is None:
            try:
                resp = self.session.get(PYPI_URL.format(name=name), timeout=TIMEOUT)
                if resp.status_code == 404:
                    ep.enrichment_errors.append(f"PyPI: package '{name}' not found")
                    return
                resp.raise_for_status()
                data = self._compact(resp.json())
                self.cache.set(cache_key, data)
            except requests.RequestException as exc:
                ep.enrichment_errors.append(f"PyPI: {exc}")
                return
            except ValueError as exc:
                ep.enrichment_errors.append(f"PyPI: invalid JSON ({exc})")
                return

        ep.description = data.get("summary")
        ep.latest_version = data.get("version")
        ep.homepage = data.get("homepage")
        ep.license = data.get("license") or None

    @staticmethod
    def _compact(payload: dict[str, Any]) -> dict[str, Any]:
        """Trim PyPI's response to just the fields we care about.

        Cached PyPI documents balloon to many MB across a project; keeping
        only the summary fields shrinks the cache file dramatically.
        """
        info = payload.get("info") or {}
        return {
            "summary": _short(info.get("summary")),
            "version": info.get("version"),
            "homepage": (info.get("home_page") or info.get("project_url") or _project_url(info)),
            "license": info.get("license"),
        }


def _short(s: str | None, limit: int = 200) -> str | None:
    if not s:
        return None
    s = s.strip().split("\n")[0]
    return s if len(s) <= limit else s[:limit] + "…"


def _project_url(info: dict[str, Any]) -> str | None:
    urls = info.get("project_urls") or {}
    for key in ("Homepage", "Source", "Repository"):
        if key in urls:
            url = urls[key]
            return url if isinstance(url, str) else None
    return None
