"""Parser for npm ``package.json`` files.

We read ``dependencies``, ``devDependencies``, and ``optionalDependencies``,
recording which section each entry came from in ``Package.source`` so the
renderer can group them.

Deliberate non-features:

- ``workspaces`` aren't followed — multi-package monorepos should be
  scanned by passing each workspace's ``package.json`` individually.
- ``peerDependencies`` are skipped — they're not installed by default.
- Non-registry specs (``git+``, ``file:``, ``link:``, ``workspace:``,
  raw URLs) are skipped — there's no public registry to enrich from.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Ecosystem, Package
from .base import ManifestParser

log = logging.getLogger(__name__)

_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_NON_REGISTRY_PREFIXES = (
    "git+",
    "git:",
    "file:",
    "link:",
    "http:",
    "https:",
    "workspace:",
)


class PackageJsonParser(ManifestParser):
    def parse(self, path: Path) -> list[Package]:
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            log.error("Cannot parse %s: %s", path, exc)
            return []

        packages: list[Package] = []
        for section in _SECTIONS:
            entries = data.get(section) or {}
            if not isinstance(entries, dict):
                log.warning("%s in %s is not an object, skipping", section, path)
                continue
            for name, spec in entries.items():
                if not isinstance(spec, str):
                    log.warning("Spec for %s in %s is not a string, skipping", name, path)
                    continue
                if any(spec.startswith(p) for p in _NON_REGISTRY_PREFIXES):
                    log.info("Skipping non-registry dependency %s (%s)", name, spec)
                    continue
                packages.append(
                    Package(
                        name=name,
                        requested_spec=spec,
                        ecosystem=Ecosystem.NPM,
                        source=section,
                    )
                )
        return packages
