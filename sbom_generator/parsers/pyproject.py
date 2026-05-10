"""Parser for ``pyproject.toml`` files.

Supported dependency declarations (most projects use exactly one of these):

* PEP 621 — ``[project] dependencies`` and
  ``[project.optional-dependencies]``. The standard since 2021.
* PEP 735 — ``[dependency-groups]``. Newer (2024) standard for grouping
  dev/test/lint-only dependencies separately from runtime extras.
* Poetry — ``[tool.poetry.dependencies]``,
  ``[tool.poetry.dev-dependencies]`` (legacy), and
  ``[tool.poetry.group.<name>.dependencies]`` (current).

Deliberately not supported (logged and skipped):

* Direct, git, URL, or path requirements — no public registry to enrich
  from. Examples: Poetry's ``{git = "..."}``, ``{path = "..."}``, ``{url
  = "..."}``; PEP 508's ``pkg @ https://…``.
* Setuptools' legacy ``setup.py``/``setup.cfg`` — a project on either of
  those should pin its runtime deps in a generated ``requirements.txt``
  instead.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from ..models import Ecosystem, Package
from .base import ManifestParser

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - import selection by interpreter version
    import tomli as tomllib  # type: ignore[import-not-found]

log = logging.getLogger(__name__)


class PyProjectTomlParser(ManifestParser):
    def parse(self, path: Path) -> list[Package]:
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            log.error("Cannot parse %s: %s", path, exc)
            return []

        source = path.name
        packages: list[Package] = []
        packages.extend(self._parse_pep621(data, source))
        packages.extend(self._parse_pep735_groups(data, source))
        packages.extend(self._parse_poetry(data, source))
        return packages

    # ------------------------------------------------------------------
    # PEP 621
    # ------------------------------------------------------------------

    def _parse_pep621(self, data: dict[str, Any], source: str) -> list[Package]:
        project = data.get("project")
        if not isinstance(project, dict):
            return []

        out: list[Package] = []

        for spec in project.get("dependencies") or []:
            pkg = self._from_pep508(spec, f"{source} [project]")
            if pkg is not None:
                out.append(pkg)

        optionals = project.get("optional-dependencies") or {}
        if isinstance(optionals, dict):
            for group, specs in optionals.items():
                if not isinstance(specs, list):
                    continue
                for spec in specs:
                    pkg = self._from_pep508(
                        spec, f"{source} [project.optional-dependencies.{group}]"
                    )
                    if pkg is not None:
                        out.append(pkg)

        return out

    # ------------------------------------------------------------------
    # PEP 735
    # ------------------------------------------------------------------

    def _parse_pep735_groups(self, data: dict[str, Any], source: str) -> list[Package]:
        groups = data.get("dependency-groups")
        if not isinstance(groups, dict):
            return []

        out: list[Package] = []
        for group, specs in groups.items():
            if not isinstance(specs, list):
                continue
            for spec in specs:
                # PEP 735 also allows ``{include-group = "other"}`` table
                # entries; we follow only the literal string requirements
                # here. Resolving cross-group includes properly is a future
                # nicety, not a v0.3 requirement.
                if not isinstance(spec, str):
                    continue
                pkg = self._from_pep508(spec, f"{source} [dependency-groups.{group}]")
                if pkg is not None:
                    out.append(pkg)
        return out

    # ------------------------------------------------------------------
    # Poetry
    # ------------------------------------------------------------------

    def _parse_poetry(self, data: dict[str, Any], source: str) -> list[Package]:
        poetry = (data.get("tool") or {}).get("poetry")
        if not isinstance(poetry, dict):
            return []

        out: list[Package] = []

        out.extend(
            self._from_poetry_table(poetry.get("dependencies") or {}, f"{source} [tool.poetry]")
        )
        out.extend(
            self._from_poetry_table(
                poetry.get("dev-dependencies") or {},
                f"{source} [tool.poetry.dev-dependencies]",
            )
        )

        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for name, group_data in groups.items():
                if not isinstance(group_data, dict):
                    continue
                out.extend(
                    self._from_poetry_table(
                        group_data.get("dependencies") or {},
                        f"{source} [tool.poetry.group.{name}]",
                    )
                )

        return out

    def _from_poetry_table(self, table: dict[str, Any], source: str) -> list[Package]:
        out: list[Package] = []
        for name, raw_spec in table.items():
            if name.lower() == "python":
                # Poetry conventionally lists the Python version constraint
                # under [tool.poetry.dependencies]; it isn't a package.
                continue
            spec = self._normalize_poetry_spec(raw_spec)
            if spec is None:
                log.info("Skipping non-registry dependency %s in %s", name, source)
                continue
            out.append(
                Package(
                    name=name,
                    requested_spec=spec,
                    ecosystem=Ecosystem.PYPI,
                    source=source,
                )
            )
        return out

    @staticmethod
    def _normalize_poetry_spec(value: Any) -> str | None:
        """Convert a Poetry dependency value to a printable spec string.

        Returns ``None`` if the dependency points at a git/url/path source
        with no registry counterpart we could enrich from.
        """
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("git", "url", "path"):
                if key in value:
                    return None
            version = value.get("version")
            if isinstance(version, str):
                return version
        if isinstance(value, list):
            # Poetry allows a list of constraint tables (multiple
            # constraints, e.g. per-Python-version). We pick the first
            # one that resolves to a printable spec.
            for entry in value:
                spec = PyProjectTomlParser._normalize_poetry_spec(entry)
                if spec is not None:
                    return spec
        return None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _from_pep508(spec: Any, source: str) -> Package | None:
        if not isinstance(spec, str):
            return None
        try:
            req = Requirement(spec)
        except InvalidRequirement as exc:
            log.warning("Cannot parse PEP 508 requirement %r in %s: %s", spec, source, exc)
            return None
        if req.url:
            # `pkg @ https://example.com/whl` style — no registry to query.
            log.info("Skipping URL dependency %s in %s", req.name, source)
            return None
        return Package(
            name=req.name,
            requested_spec=str(req.specifier) or "(any)",
            ecosystem=Ecosystem.PYPI,
            source=source,
        )
