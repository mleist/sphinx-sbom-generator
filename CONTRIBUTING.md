# Contributing

Thanks for your interest in improving sphinx-sbom-generator! This document covers
the workflow for code contributions.

## Development setup

```bash
git clone https://github.com/mleist/sphinx-sbom-generator.git
cd sphinx-sbom-generator
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Running checks locally

```bash
ruff check .              # lint
ruff format --check .     # formatting
mypy sbom_generator       # type check
pytest                    # tests
pytest --cov              # tests with coverage
```

`pre-commit run --all-files` runs the same lint/format checks the CI does.

## Project layout

The codebase is split into three layers that communicate only through
the data classes in `sbom_generator/models.py`:

| Layer | Location | Responsibility |
|---|---|---|
| Parsers | `sbom_generator/parsers/` | Read a manifest, produce `Package` objects. |
| Enrichers | `sbom_generator/enrichers/` | Add metadata or vulnerability info. |
| Renderers | `sbom_generator/renderers/` | Format `EnrichedPackage` into output. |

When adding support for a new ecosystem (Cargo, Maven, ...):

1. Add a parser under `parsers/` subclassing `ManifestParser`.
2. Add a metadata enricher under `enrichers/` subclassing `Enricher`. OSV
   itself usually needs no changes — its `ecosystem` field accepts most
   common identifiers.
3. Wire the new components in `cli.py` and add a flag to the argument
   parser.
4. Add tests for the new parser and enricher.

## Code style

- `ruff` handles linting and formatting; settings live in `pyproject.toml`.
- `mypy --strict` is the type-check baseline. New code should be fully
  annotated.
- Public functions and classes get docstrings explaining intent, not
  mechanics. Comments inside functions explain *why*, not *what*.

## Tests

Run the suite with `pytest`. Network-touching code is mocked via
`responses`; tests must not make real HTTP calls.

When adding a feature, add at least:

- One unit test for the happy path.
- One unit test for the most likely failure mode (malformed input,
  network error, missing field, ...).

## Commit messages

We loosely follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parsers): support Pipfile
fix(osv): handle empty severity arrays
docs: clarify cache TTL semantics
```

This isn't enforced by tooling but makes the changelog and history
easier to scan.

## Pull requests

- Keep PRs focused — one logical change per PR.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Make sure CI passes before requesting review.
- New public APIs need docstrings and tests.

## Reporting bugs

Use the issue templates. A minimal reproduction (manifest snippet + the
exact CLI invocation) is the most helpful thing you can include.
