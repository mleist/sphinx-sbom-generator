"""Command-line entry point.

Examples::

    python -m sbom_generator -r requirements.txt -o docs/sbom.md
    python -m sbom_generator -p package.json -o docs/sbom.md
    python -m sbom_generator --pyproject pyproject.toml -o docs/sbom.md
    python -m sbom_generator -r requirements.txt -p package.json \\
        --pyproject pyproject.toml --transitive -o docs/sbom.md

All manifest options accept multiple values.

The CLI module itself is deliberately thin: it parses arguments, wires
the components together in the right order, and prints a summary. All
real logic lives in ``parsers``, ``enrichers``, ``resolvers``, and
``renderers`` and can be reused programmatically without going through
argparse.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import requests

from . import __version__
from .cache import JsonFileCache
from .enrichers.npm import NpmEnricher
from .enrichers.osv import OsvEnricher
from .enrichers.pypi import PyPIEnricher
from .models import Ecosystem, EnrichedPackage, Package
from .parsers.package_json import PackageJsonParser
from .parsers.pyproject import PyProjectTomlParser
from .parsers.requirements import RequirementsTxtParser
from .renderers.markdown import MarkdownRenderer
from .resolvers.expander import TransitiveExpander
from .resolvers.npm import NpmDependencyResolver
from .resolvers.pypi import PyPIDependencyResolver

log = logging.getLogger("sbom_generator")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom_generator",
        description=(
            "Generate a Markdown SBOM (Sphinx-ready) from requirements.txt, "
            "pyproject.toml, and/or package.json files. Optionally walks "
            "transitive dependencies."
        ),
    )
    p.add_argument(
        "-r",
        "--requirements",
        action="append",
        default=[],
        type=Path,
        help="Path to a requirements.txt file. May be passed multiple times.",
    )
    p.add_argument(
        "-p",
        "--package-json",
        action="append",
        default=[],
        type=Path,
        help="Path to a package.json file. May be passed multiple times.",
    )
    p.add_argument(
        "--pyproject",
        action="append",
        default=[],
        type=Path,
        help=(
            "Path to a pyproject.toml file. Reads PEP 621 dependencies, "
            "PEP 735 dependency-groups, and Poetry sections. May be passed "
            "multiple times."
        ),
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Path for the generated Markdown file (e.g. docs/sbom.md).",
    )
    p.add_argument(
        "--title",
        default="Software Bill of Materials",
        help="Top-level heading for the generated document.",
    )
    p.add_argument(
        "--transitive",
        action="store_true",
        help=(
            "Recursively resolve transitive dependencies via the PyPI and "
            "npm registries. Slower and produces a much larger report; "
            "ideal for full SBOMs, overkill for a quick overview."
        ),
    )
    p.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum depth for transitive resolution (default: 5).",
    )
    p.add_argument(
        "--max-packages",
        type=int,
        default=2000,
        help=(
            "Hard ceiling on total packages (direct + transitive). "
            "Resolution stops when this is reached. Default: 2000."
        ),
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".sbom-cache"),
        help="Directory for the API response cache (default: .sbom-cache).",
    )
    p.add_argument(
        "--cache-ttl",
        type=int,
        default=86400,
        help="Cache TTL in seconds (default: 86400 = 24h).",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable the cache (always hit the network).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )
    p.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _parse_manifests(
    req_paths: list[Path],
    pkg_paths: list[Path],
    pyproject_paths: list[Path],
) -> list[Package] | None:
    packages: list[Package] = []

    req_parser = RequirementsTxtParser()
    for path in req_paths:
        if not path.exists():
            log.error("Manifest not found: %s", path)
            return None
        log.info("Parsing %s", path)
        packages.extend(req_parser.parse(path))

    pkg_parser = PackageJsonParser()
    for path in pkg_paths:
        if not path.exists():
            log.error("Manifest not found: %s", path)
            return None
        log.info("Parsing %s", path)
        packages.extend(pkg_parser.parse(path))

    pyproject_parser = PyProjectTomlParser()
    for path in pyproject_paths:
        if not path.exists():
            log.error("Manifest not found: %s", path)
            return None
        log.info("Parsing %s", path)
        packages.extend(pyproject_parser.parse(path))

    return packages


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)
    _setup_logging(args.verbose)

    if not args.requirements and not args.package_json and not args.pyproject:
        log.error("At least one of --requirements, --package-json, or --pyproject is required.")
        return 2

    # 1. parse manifests
    direct = _parse_manifests(args.requirements, args.package_json, args.pyproject)
    if direct is None:
        return 1
    if not direct:
        log.error("No packages found in any manifest. Nothing to do.")
        return 1
    log.info("Parsed %d direct package entries", len(direct))

    # 2. (optional) walk transitive dependencies
    cache = JsonFileCache(
        path=args.cache_dir / "cache.json",
        ttl_seconds=args.cache_ttl,
        enabled=not args.no_cache,
    )
    session = requests.Session()
    session.headers.update(
        {"User-Agent": f"sphinx-sbom-generator/{__version__} (+https://example.invalid)"}
    )

    if args.transitive:
        log.info(
            "Resolving transitive dependencies (max_depth=%d, max_packages=%d)…",
            args.max_depth,
            args.max_packages,
        )
        expander = TransitiveExpander(
            resolvers={
                Ecosystem.PYPI: PyPIDependencyResolver(cache=cache, session=session),
                Ecosystem.NPM: NpmDependencyResolver(cache=cache, session=session),
            },
            max_depth=args.max_depth,
            max_packages=args.max_packages,
        )
        all_packages = expander.expand(direct)
        log.info("Discovered %d transitive package(s)", len(all_packages) - len(direct))
    else:
        all_packages = direct

    # 3. enrich
    enriched = [EnrichedPackage(package=p) for p in all_packages]

    pypi = PyPIEnricher(cache=cache, session=session)
    npm = NpmEnricher(cache=cache, session=session)
    osv = OsvEnricher(cache=cache, session=session)

    log.info("Fetching registry metadata for %d package(s)…", len(enriched))
    for ep in enriched:
        pypi.enrich(ep)
        npm.enrich(ep)

    log.info("Querying OSV.dev for vulnerabilities…")
    osv.enrich_all(enriched)

    cache.flush()

    # 4. render
    log.info("Rendering Markdown to %s", args.output)
    md = MarkdownRenderer().render(enriched, title=args.title)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md, encoding="utf-8")

    direct_count = sum(1 for ep in enriched if not ep.package.is_transitive)
    transitive_count = len(enriched) - direct_count
    vuln_count = sum(len(ep.vulnerabilities) for ep in enriched)
    print(
        f"Wrote {args.output} "
        f"({direct_count} direct + {transitive_count} transitive = "
        f"{len(enriched)} packages, {vuln_count} vulnerabilities)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
