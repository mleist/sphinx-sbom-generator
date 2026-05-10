"""Transitive dependency resolver for npm.

The npm registry document for a package contains every published
version under ``versions``, each with its own ``dependencies`` map:

::

    {
      "dist-tags": {"latest": "4.18.2"},
      "versions": {
        "4.18.2": {"dependencies": {"accepts": "~1.3.8", ...}}
      }
    }

We pick the version corresponding to the package's pinned spec
(when it exactly matches a published version) or fall back to
``dist-tags.latest`` otherwise. Resolving non-trivial semver ranges
(``^4.0``, ``~1.2``) properly would require a semver library and a
real version selection algorithm; for documentation purposes "latest
matching dist-tag" is good enough and the behaviour is documented.

We do not follow ``peerDependencies`` or ``optionalDependencies`` —
neither is part of npm's default install closure.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import requests

from ..cache import JsonFileCache
from ..models import Ecosystem, Package
from .base import DependencyResolver

log = logging.getLogger(__name__)

NPM_URL = "https://registry.npmjs.org/{name}"
TIMEOUT = 10


class NpmDependencyResolver(DependencyResolver):
    def __init__(
        self,
        cache: JsonFileCache,
        session: requests.Session | None = None,
    ) -> None:
        self.cache = cache
        self.session = session or requests.Session()

    def find_dependencies(self, package: Package) -> list[Package]:
        if package.ecosystem != Ecosystem.NPM:
            return []

        doc = self._fetch(package.name)
        if doc is None:
            return []

        versions = doc.get("versions") or {}
        if not isinstance(versions, dict):
            return []

        version = self._pick_version(package.requested_spec, doc)
        if version is None or version not in versions:
            return []

        deps = versions[version].get("dependencies") or {}
        if not isinstance(deps, dict):
            return []

        out: list[Package] = []
        for name, spec in deps.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            out.append(
                Package(
                    name=name,
                    requested_spec=spec,
                    ecosystem=Ecosystem.NPM,
                    source=f"transitive (via {package.name})",
                    is_transitive=True,
                    parent=package.name,
                )
            )
        return out

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _fetch(self, name: str) -> dict[str, Any] | None:
        cache_key = f"npm-deps:{name}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached if isinstance(cached, dict) else None

        url_name = quote(name, safe="@")
        try:
            resp = self.session.get(NPM_URL.format(name=url_name), timeout=TIMEOUT)
            if resp.status_code == 404:
                log.info("npm: %s not found while resolving deps", name)
                return None
            resp.raise_for_status()
            full = resp.json()
        except (requests.RequestException, ValueError) as exc:
            log.warning("npm deps fetch %s failed: %s", name, exc)
            return None

        # Trim aggressively: keep only what the resolver needs.
        compact = {
            "dist-tags": full.get("dist-tags") or {},
            "versions": {
                v: {"dependencies": meta.get("dependencies") or {}}
                for v, meta in (full.get("versions") or {}).items()
                if isinstance(meta, dict)
            },
        }
        self.cache.set(cache_key, compact)
        return compact

    @staticmethod
    def _pick_version(spec: str, doc: dict[str, Any]) -> str | None:
        """Pick a published version of ``doc`` that matches ``spec``.

        Strategy: if ``spec`` is bare digits (e.g. ``"4.17.21"``) and
        that version is published, use it; otherwise return the
        ``dist-tags.latest``. This intentionally side-steps full semver
        range resolution — see the module docstring.
        """
        versions = doc.get("versions") or {}
        if isinstance(versions, dict) and spec in versions:
            return spec
        latest = (doc.get("dist-tags") or {}).get("latest")
        return latest if isinstance(latest, str) else None
