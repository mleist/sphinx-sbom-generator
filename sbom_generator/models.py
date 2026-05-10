"""Core data structures shared across parsers, enrichers, and renderers.

Keeping these in a single small module makes the data flow obvious:
parsers produce `Package`, enrichers wrap it in `EnrichedPackage` and fill
in fields, the renderer consumes `EnrichedPackage` only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    """Package ecosystems supported by the SBOM generator.

    The string values match OSV.dev's ecosystem identifiers, so they
    can be used directly when querying the vulnerability database.
    """

    PYPI = "PyPI"
    NPM = "npm"


@dataclass(frozen=True)
class Package:
    """A package as declared in a manifest file, or pulled in transitively.

    `requested_spec` preserves the original constraint (e.g. ">=2.0,<3.0"),
    not a resolved version. Resolution happens later in the enrichment step.

    `is_transitive` distinguishes packages that came directly from a manifest
    (False) from those discovered by walking another package's dependencies
    (True). `parent` records the *immediate* package that pulled a transitive
    dependency in — only the first such parent is kept when the same package
    is reachable through several paths.
    """

    name: str
    requested_spec: str
    ecosystem: Ecosystem
    source: str  # e.g. "dependencies", "devDependencies", "requirements.txt"
    is_transitive: bool = False
    parent: str | None = None


@dataclass(frozen=True)
class Vulnerability:
    """A known vulnerability affecting a specific package version."""

    id: str
    summary: str
    severity: str | None
    fixed_versions: tuple[str, ...]
    references: tuple[str, ...]


@dataclass
class EnrichedPackage:
    """A package augmented with registry metadata and vulnerability info.

    Fields can be `None` when enrichment fails (network error, package
    not found, …). The renderer is responsible for handling these
    gracefully so a partial outage never breaks the whole document.
    """

    package: Package
    description: str | None = None
    latest_version: str | None = None
    homepage: str | None = None
    license: str | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    enrichment_errors: list[str] = field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        return bool(self.vulnerabilities)

    @property
    def resolved_version(self) -> str | None:
        """Best guess at the version that would actually be installed.

        For pinned specs (``==X.Y.Z``) we trust the pin; otherwise we fall
        back to the latest version from the registry. This matches what
        gets sent to OSV when querying for vulnerabilities.

        Note: without a real lockfile this is an approximation. If you
        need lockfile-precise results, parse `poetry.lock` /
        `package-lock.json` and feed those versions through instead.
        """
        spec = self.package.requested_spec.strip()
        if spec.startswith("==") and len(spec) > 2:
            return spec[2:].split(",", 1)[0].strip()
        return self.latest_version
