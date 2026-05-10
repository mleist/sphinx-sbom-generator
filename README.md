# sphinx-sbom-generator

[![CI](https://github.com/mleist/sphinx-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/mleist/sphinx-sbom-generator/actions/workflows/ci.yml)
[![Python versions](https://img.shields.io/pypi/pyversions/sphinx-sbom-generator.svg)](https://pypi.org/project/sphinx-sbom-generator/)
[![PyPI version](https://img.shields.io/pypi/v/sphinx-sbom-generator.svg)](https://pypi.org/project/sphinx-sbom-generator/)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-green.svg)](LICENSE)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/mleist/sphinx-sbom-generator/total)

Generate a Software Bill of Materials (SBOM) as a Sphinx-ready Markdown
document from `requirements.txt`, `pyproject.toml`, and/or `package.json`
manifests. For each package the report includes a short description,
requested and latest versions, license, and known security vulnerabilities
(source: [OSV.dev](https://osv.dev)). With `--transitive`, the tool also
recursively resolves indirect dependencies via the PyPI and npm registries
and surfaces them in a separate section.

## Installation

From source:

```bash
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Usage

```bash
# requirements.txt
sphinx-sbom-generator -r requirements.txt -o docs/sbom.md

# pyproject.toml (PEP 621 / PEP 735 / Poetry)
sphinx-sbom-generator --pyproject pyproject.toml -o docs/sbom.md

# package.json
sphinx-sbom-generator -p package.json -o docs/sbom.md

# Mix any combination in a single report
sphinx-sbom-generator \
    -r requirements.txt -r requirements-dev.txt \
    --pyproject pyproject.toml \
    -p frontend/package.json -p admin/package.json \
    -o docs/sbom.md

# Recursively walk transitive dependencies (slower, much larger report)
sphinx-sbom-generator --pyproject pyproject.toml --transitive -o docs/sbom.md

# Tame a deep graph
sphinx-sbom-generator --pyproject pyproject.toml --transitive \
    --max-depth 3 --max-packages 500 -o docs/sbom.md
```

The same is available as a module:

```bash
python -m sbom_generator --pyproject pyproject.toml -o docs/sbom.md
```

Full help:

```bash
sphinx-sbom-generator --help
```

### What gets read from `pyproject.toml`

* **PEP 621** (`[project] dependencies` and
  `[project.optional-dependencies]`) — the modern standard.
* **PEP 735** (`[dependency-groups]`) — newer dev/lint/test groups.
* **Poetry** (`[tool.poetry.dependencies]`,
  `[tool.poetry.dev-dependencies]`, and
  `[tool.poetry.group.<name>.dependencies]`).

Direct, git, URL, and path dependencies are skipped — there is no public
registry to enrich them from. Poetry's special `python` constraint is
also ignored (it isn't a package).

## Sphinx integration

With `myst-parser`, Sphinx renders the generated Markdown directly:

```python
# conf.py
extensions = ["myst_parser"]
source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
```

In `index.rst`:

```rst
.. toctree::
   :maxdepth: 2

   sbom
```

Recommended pattern: invoke the generator in CI immediately before
`sphinx-build` so the SBOM stays in sync with the manifests:

```yaml
- run: sphinx-sbom-generator -r requirements.txt -p package.json -o docs/sbom.md
- run: sphinx-build docs docs/_build
```

## Architecture

```
sbom_generator/
├── models.py              Data classes (Package, Vulnerability, ...)
├── cache.py               JSON file cache with TTL
├── cli.py                 Argument parsing + orchestration
├── parsers/
│   ├── base.py            ManifestParser base class
│   ├── requirements.py    requirements.txt
│   ├── pyproject.py       pyproject.toml (PEP 621 + PEP 735 + Poetry)
│   └── package_json.py    package.json
├── enrichers/
│   ├── base.py            Enricher base class
│   ├── pypi.py            PyPI metadata
│   ├── npm.py             npm metadata
│   └── osv.py             OSV.dev vulnerabilities (batch API)
├── resolvers/
│   ├── base.py            DependencyResolver base class
│   ├── pypi.py            PyPI requires_dist walker
│   ├── npm.py             npm versions[v].dependencies walker
│   └── expander.py        BFS expander (cycle-safe, depth-bounded)
└── renderers/
    └── markdown.py        Markdown for Sphinx
```

The four layers — **parsers → resolvers → enrichers → renderers** —
communicate only through the data classes in `models.py`. Adding a new
ecosystem (Cargo, Maven, ...) means writing one parser, one metadata
enricher, and (if transitive resolution is wanted) one resolver. OSV
covers most ecosystems and can be reused as-is.

## Caching

Default location: `.sbom-cache/cache.json`, TTL 24 hours. Writes are
atomic (temp file + `os.replace`), so an interrupted run never leaves
the cache in an inconsistent state.

- `--cache-dir PATH` — change the directory
- `--cache-ttl SECONDS` — change the TTL
- `--no-cache` — disable caching entirely

In CI, caching the cache directory between builds noticeably speeds
things up and reduces API load.

## What this tool does *not* do

- **Transitive resolution is approximate.** With `--transitive`, the
  tool walks `requires_dist` (PyPI) and `versions[v].dependencies`
  (npm). For PyPI it filters out extras and platform-mismatched markers
  for the *current* environment. For npm it picks the version matching
  a literal pin or otherwise falls back to `dist-tags.latest` —
  semver ranges (`^4.0`, `~1.2`) are not range-resolved. If you need
  lockfile-precise results, parse `poetry.lock` / `package-lock.json`
  and feed those versions through instead (a lockfile parser fits
  naturally as another module under `parsers/`).
- **No exact version resolution for unpinned specs.** When a spec is
  a range, the report shows the *currently latest* version. That
  reflects "what would I deploy today", not "what could ever be
  installed under this range".
- **No license-compliance evaluation.** Licenses are surfaced but not
  checked against an allow-list.
- **No setuptools `setup.py`/`setup.cfg` support.** Project still on
  those should pin its runtime deps in a generated `requirements.txt`.

## Fault tolerance

Per-package failures (package not in registry, network timeout, malformed
manifest line) are recorded on the affected package without aborting the
run or the report. The SBOM remains useful even when an upstream service
is flaky.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[BSD-3-Clause](LICENSE)
