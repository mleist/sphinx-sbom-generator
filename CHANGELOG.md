# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-10

### Added
- Initial public release as `sphinx-sbom-generator`.
- Parsers for:
  - `requirements.txt` (pip).
  - `package.json` (npm) — `dependencies`, `devDependencies`, and
    `optionalDependencies`. Non-registry entries (git, file, link, http,
    workspace) are skipped.
  - `pyproject.toml`, supporting **PEP 621** `[project]` dependencies and
    `[project.optional-dependencies]`, **PEP 735** `[dependency-groups]`,
    and **Poetry** `[tool.poetry.dependencies]`,
    `[tool.poetry.dev-dependencies]`, and
    `[tool.poetry.group.<name>.dependencies]`.
- Metadata enrichment from PyPI and the npm registry.
- Vulnerability lookup via the OSV.dev batch API.
- **Optional transitive dependency resolution** (`--transitive` flag) for
  both PyPI and npm. Walks `requires_dist` (filtering extras and markers
  for the current environment) and `versions[v].dependencies`. BFS-based
  with cycle detection, configurable `--max-depth` (default 5) and
  `--max-packages` ceiling (default 2000).
- JSON file cache with TTL and atomic writes.
- Sphinx-ready Markdown renderer with an overview, per-ecosystem tables
  separating direct from transitive dependencies, a "Via" column for
  transitive provenance, and a per-package vulnerability detail section.
- Command-line interface (`sphinx-sbom-generator`) and module entry point
  (`python -m sbom_generator`), including `--version` / `-V`.

[Unreleased]: https://github.com/mleist/sphinx-sbom-generator/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mleist/sphinx-sbom-generator/releases/tag/v0.3.0
