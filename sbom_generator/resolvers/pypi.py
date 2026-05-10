"""Transitive dependency resolver for PyPI.

Strategy: fetch ``https://pypi.org/pypi/{name}/{version}/json`` (falling
back to ``/pypi/{name}/json`` for the latest release) and parse the
``info.requires_dist`` list. Each entry is a PEP 508 requirement string,
which we hand to ``packaging.requirements.Requirement``.

We deliberately filter out:

* Requirements gated by ``extra == '<group>'`` markers — those are
  optional extras (``pip install pkg[group]``), not runtime needs.
* Requirements whose other markers (``python_version``,
  ``sys_platform``, ...) evaluate to false in the *current* environment.
  This is a pragmatic choice: the SBOM reflects what would be installed
  here, today.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

import requests
from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from ..cache import JsonFileCache
from ..models import Ecosystem, Package
from .base import DependencyResolver

log = logging.getLogger(__name__)

PYPI_VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"
PYPI_LATEST_URL = "https://pypi.org/pypi/{name}/json"
TIMEOUT = 10


class PyPIDependencyResolver(DependencyResolver):
    def __init__(
        self,
        cache: JsonFileCache,
        session: requests.Session | None = None,
    ) -> None:
        self.cache = cache
        self.session = session or requests.Session()

    def find_dependencies(self, package: Package) -> list[Package]:
        if package.ecosystem != Ecosystem.PYPI:
            return []

        version = self._best_version(package)
        if version is None:
            return []

        info = self._fetch_info(package.name, version)
        if info is None:
            return []

        requires = info.get("requires_dist") or []
        if not isinstance(requires, list):
            return []

        out: list[Package] = []
        seen_names: set[str] = set()
        for raw in requires:
            if not isinstance(raw, str):
                continue
            try:
                req = Requirement(raw)
            except InvalidRequirement:
                log.debug("Skipping unparseable requires_dist entry: %s", raw)
                continue

            if req.url:
                # PEP 508 URL deps — nothing to enrich.
                continue

            if req.marker is not None and not _marker_applies(req.marker):
                continue

            normalized = req.name.lower()
            if normalized in seen_names:
                # The same name can appear multiple times in
                # ``requires_dist`` with different markers; one entry
                # is enough.
                continue
            seen_names.add(normalized)

            out.append(
                Package(
                    name=req.name,
                    requested_spec=str(req.specifier) or "(any)",
                    ecosystem=Ecosystem.PYPI,
                    source=f"transitive (via {package.name})",
                    is_transitive=True,
                    parent=package.name,
                )
            )
        return out

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _best_version(package: Package) -> str | None:
        """Return the version we should query PyPI for.

        Pinned specs (``==X.Y.Z``) are honoured; otherwise we let PyPI
        fall back to its latest release in ``_fetch_info``.
        """
        spec = package.requested_spec.strip()
        if spec.startswith("==") and len(spec) > 2:
            return spec[2:].split(",", 1)[0].strip() or None
        # Validate well-formed specifier strings; if invalid, treat as
        # "no constraint" and use latest.
        with contextlib.suppress(InvalidSpecifier):
            SpecifierSet(spec)
        return "latest"

    def _fetch_info(self, name: str, version: str) -> dict[str, Any] | None:
        cache_key = f"pypi-deps:{name.lower()}@{version}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached if isinstance(cached, dict) else None

        if version == "latest":
            url = PYPI_LATEST_URL.format(name=name)
        else:
            url = PYPI_VERSION_URL.format(name=name, version=version)

        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            if resp.status_code == 404:
                # Specific version may not exist; fall back to latest.
                if version != "latest":
                    return self._fetch_info(name, "latest")
                log.info("PyPI: %s not found while resolving deps", name)
                return None
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as exc:
            log.warning("PyPI deps fetch %s@%s failed: %s", name, version, exc)
            return None

        info = payload.get("info") or {}
        compact = {"requires_dist": info.get("requires_dist") or []}
        self.cache.set(cache_key, compact)
        return compact


def _marker_applies(marker: Marker) -> bool:
    """Return True if the marker holds in the *current* environment.

    Markers gated by ``extra == ...`` always evaluate False without an
    extras context — which is exactly what we want, since extras are
    not part of the runtime closure.
    """
    try:
        return bool(marker.evaluate())
    except Exception:
        return False
