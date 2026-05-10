"""End-to-end CLI smoke test.

Exercises the full pipeline (parse -> enrich -> render) with all
network calls mocked.
"""

from __future__ import annotations

import re
from pathlib import Path

import responses

from sbom_generator.cli import main


@responses.activate
def test_cli_writes_markdown_file(tmp_path: Path, fixtures_dir: Path) -> None:
    # Stub all external endpoints the run will touch.
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/requests/json",
        json={"info": {"summary": "HTTP for humans", "version": "2.31.0"}},
    )
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/flask/json",
        json={"info": {"summary": "Web framework", "version": "3.0.0"}},
    )
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/django/json",
        json={"info": {"summary": "Web framework", "version": "5.0.0"}},
    )
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/pyyaml/json",
        json={"info": {"summary": "YAML parser", "version": "6.0.1"}},
    )
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/black/json",
        json={"info": {"summary": "Formatter", "version": "24.0.0"}},
    )
    # OSV: no vulns for any package in this run.
    responses.add(
        responses.POST,
        "https://api.osv.dev/v1/querybatch",
        json={"results": [{} for _ in range(5)]},
    )

    output = tmp_path / "sbom.md"
    exit_code = main(
        [
            "-r",
            str(fixtures_dir / "requirements_sample.txt"),
            "-o",
            str(output),
            "--cache-dir",
            str(tmp_path / ".cache"),
        ]
    )

    assert exit_code == 0
    assert output.exists()
    content = output.read_text()
    assert "# Software Bill of Materials" in content
    assert "requests" in content


def test_cli_requires_at_least_one_manifest(tmp_path: Path) -> None:
    exit_code = main(["-o", str(tmp_path / "sbom.md")])
    assert exit_code == 2


def test_cli_reports_missing_manifest_path(tmp_path: Path) -> None:
    exit_code = main(["-r", str(tmp_path / "does-not-exist.txt"), "-o", str(tmp_path / "sbom.md")])
    assert exit_code == 1


@responses.activate
def test_cli_accepts_pyproject_manifest(tmp_path: Path, fixtures_dir: Path) -> None:
    # Stub PyPI for every package the fixture might reach. Use a regex
    # callback so we don't have to enumerate them up front.
    responses.add_callback(
        responses.GET,
        re.compile(r"https://pypi\.org/pypi/[^/]+/json"),
        callback=lambda req: (200, {}, '{"info": {"summary": "x", "version": "1"}}'),
    )
    responses.add(
        responses.POST,
        "https://api.osv.dev/v1/querybatch",
        json={"results": [{} for _ in range(50)]},
    )

    output = tmp_path / "sbom.md"
    exit_code = main(
        [
            "--pyproject",
            str(fixtures_dir / "pyproject_sample.toml"),
            "-o",
            str(output),
            "--cache-dir",
            str(tmp_path / ".cache"),
        ]
    )
    assert exit_code == 0
    content = output.read_text()
    assert "requests" in content  # PEP 621
    assert "ruff" in content  # PEP 735
    assert "flask" in content  # Poetry


@responses.activate
def test_cli_transitive_flag_pulls_in_indirect_deps(tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("parentpkg==1.0.0\n")

    responses.add(
        responses.GET,
        "https://pypi.org/pypi/parentpkg/json",
        json={"info": {"summary": "p", "version": "1.0.0"}},
    )
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/childpkg/json",
        json={"info": {"summary": "c", "version": "2.0.0"}},
    )
    # Resolver fetches the version-specific endpoint to read requires_dist.
    responses.add(
        responses.GET,
        "https://pypi.org/pypi/parentpkg/1.0.0/json",
        json={"info": {"requires_dist": ["childpkg>=2"]}},
    )
    responses.add(
        responses.POST,
        "https://api.osv.dev/v1/querybatch",
        json={"results": [{}, {}]},
    )

    output = tmp_path / "sbom.md"
    exit_code = main(
        [
            "-r",
            str(req),
            "--transitive",
            "-o",
            str(output),
            "--cache-dir",
            str(tmp_path / ".cache"),
        ]
    )
    assert exit_code == 0
    content = output.read_text()
    assert "parentpkg" in content
    assert "childpkg" in content
    assert "### Transitive dependencies" in content
