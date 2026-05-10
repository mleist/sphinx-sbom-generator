"""Tests for manifest parsers."""

from __future__ import annotations

from pathlib import Path

from sbom_generator.models import Ecosystem
from sbom_generator.parsers.package_json import PackageJsonParser
from sbom_generator.parsers.requirements import RequirementsTxtParser


class TestRequirementsTxtParser:
    def test_parses_pinned_and_ranged_specs(self, fixtures_dir: Path) -> None:
        parser = RequirementsTxtParser()
        packages = parser.parse(fixtures_dir / "requirements_sample.txt")

        names = {p.name for p in packages}
        assert {"requests", "flask", "django", "pyyaml", "black"} <= names

        # All should be PyPI-tagged with the source filename preserved.
        assert all(p.ecosystem == Ecosystem.PYPI for p in packages)
        assert all(p.source == "requirements_sample.txt" for p in packages)

    def test_skips_includes_editables_and_flags(self, fixtures_dir: Path) -> None:
        parser = RequirementsTxtParser()
        packages = parser.parse(fixtures_dir / "requirements_sample.txt")
        names = {p.name for p in packages}

        # editable install (-e ./local-pkg) and -r include must not appear
        assert "local-pkg" not in names
        assert "other-requirements.txt" not in names

    def test_handles_line_continuation(self, fixtures_dir: Path) -> None:
        parser = RequirementsTxtParser()
        packages = parser.parse(fixtures_dir / "requirements_sample.txt")
        black = next(p for p in packages if p.name == "black")
        assert black.requested_spec == "==23.12.0"

    def test_ignores_invalid_specs(self, fixtures_dir: Path) -> None:
        # Should not raise; parser logs and continues.
        parser = RequirementsTxtParser()
        packages = parser.parse(fixtures_dir / "requirements_sample.txt")
        assert all("@@@" not in p.name for p in packages)

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.txt"
        path.write_text("")
        assert RequirementsTxtParser().parse(path) == []


class TestPackageJsonParser:
    def test_parses_dependencies_and_devDependencies(self, fixtures_dir: Path) -> None:
        parser = PackageJsonParser()
        packages = parser.parse(fixtures_dir / "package_sample.json")
        by_name = {p.name: p for p in packages}

        assert "lodash" in by_name
        assert by_name["lodash"].source == "dependencies"
        assert by_name["jest"].source == "devDependencies"

    def test_supports_scoped_packages(self, fixtures_dir: Path) -> None:
        packages = PackageJsonParser().parse(fixtures_dir / "package_sample.json")
        names = {p.name for p in packages}
        assert "@scoped/pkg" in names

    def test_skips_non_registry_specs(self, fixtures_dir: Path) -> None:
        packages = PackageJsonParser().parse(fixtures_dir / "package_sample.json")
        # file:../local should be filtered
        assert "local-thing" not in {p.name for p in packages}

    def test_ignores_peer_dependencies(self, fixtures_dir: Path) -> None:
        packages = PackageJsonParser().parse(fixtures_dir / "package_sample.json")
        assert "react" not in {p.name for p in packages}

    def test_invalid_json_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{ not valid json")
        assert PackageJsonParser().parse(path) == []
