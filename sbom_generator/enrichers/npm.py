"""npm registry metadata enricher.

Uses ``https://registry.npmjs.org/{name}``. The full document includes
every historical version and can be hundreds of KB; we only need the
``dist-tags.latest`` entry plus its description, so we trim before
caching.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import requests

from ..cache import JsonFileCache
from ..models import Ecosystem, EnrichedPackage
from .base import Enricher

log = logging.getLogger(__name__)

NPM_URL = "https://registry.npmjs.org/{name}"
TIMEOUT = 10


class NpmEnricher(Enricher):
    def __init__(
        self,
        cache: JsonFileCache,
        session: requests.Session | None = None,
    ) -> None:
        self.cache = cache
        self.session = session or requests.Session()

    def enrich(self, ep: EnrichedPackage) -> None:
        if ep.package.ecosystem != Ecosystem.NPM:
            return

        name = ep.package.name
        cache_key = f"npm:{name}"
        data = self.cache.get(cache_key)

        if data is None:
            # scoped packages: @scope/name -> @scope%2Fname
            url_name = quote(name, safe="@")
            try:
                resp = self.session.get(NPM_URL.format(name=url_name), timeout=TIMEOUT)
                if resp.status_code == 404:
                    ep.enrichment_errors.append(f"npm: package '{name}' not found")
                    return
                resp.raise_for_status()
                data = self._compact(resp.json())
                self.cache.set(cache_key, data)
            except requests.RequestException as exc:
                ep.enrichment_errors.append(f"npm: {exc}")
                return
            except ValueError as exc:
                ep.enrichment_errors.append(f"npm: invalid JSON ({exc})")
                return

        ep.description = data.get("description")
        ep.latest_version = data.get("latest")
        ep.homepage = data.get("homepage") or data.get("repository")
        ep.license = data.get("license")

    @staticmethod
    def _compact(full: dict[str, Any]) -> dict[str, Any]:
        latest = (full.get("dist-tags") or {}).get("latest")
        version_info = (full.get("versions") or {}).get(latest, {}) if latest else {}
        return {
            "description": full.get("description") or version_info.get("description"),
            "latest": latest,
            "homepage": version_info.get("homepage") or full.get("homepage"),
            "license": _normalize_license(version_info.get("license") or full.get("license")),
            "repository": _normalize_repo(version_info.get("repository") or full.get("repository")),
        }


def _normalize_license(value: Any) -> str | None:
    """npm's ``license`` field has had three different shapes over the years."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        t = value.get("type")
        return t if isinstance(t, str) else None
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict):
            t = first.get("type")
            return t if isinstance(t, str) else None
    return None


def _normalize_repo(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        url = value.get("url")
        if not isinstance(url, str):
            return None
        if url.startswith("git+"):
            url = url[4:]
        if url.endswith(".git"):
            url = url[:-4]
        return url
    return None
