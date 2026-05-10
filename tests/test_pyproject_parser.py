"""Tests for the pyproject.toml parser."""

from __future__ import annotations

from pathlib import Path

from sbom_generator.models import Ecosystem
from sbom_generator.parsers.pyproject import PyProjectTomlParser


class TestPyProjectTomlParser:
    def test_parses_pep621_dependencies(self, fixtures_dir: Path) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        names = {p.name for p in packages}
        assert {"requests", "click"} <= names
        assert all(p.ecosystem == Ecosystem.PYPI for p in packages)

    def test_parses_pep621_optional_dependencies_with_group_in_source(
        self, fixtures_dir: Path
    ) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        sphinx = next(p for p in packages if p.name == "sphinx")
        assert "optional-dependencies.docs" in sphinx.source

    def test_skips_pep508_url_dependencies(self, fixtures_dir: Path) -> None:
        # `pkg @ https://...` has no registry counterpart.
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        assert "remote-wheel" not in {p.name for p in packages}

    def test_parses_pep735_dependency_groups(self, fixtures_dir: Path) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        names = {p.name for p in packages}
        assert "ruff" in names
        assert "mypy" in names
        # types-requests is in the typing group; include-group entries
        # are skipped, but plain string entries in typing should appear.
        assert "types-requests" in names

    def test_parses_poetry_dependencies(self, fixtures_dir: Path) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        names = {p.name for p in packages}
        assert "flask" in names
        assert "gunicorn" in names

    def test_skips_poetry_python_pseudo_dependency(self, fixtures_dir: Path) -> None:
        # Poetry lists the Python version constraint here; it isn't a
        # package and must not appear in the SBOM.
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        assert "python" not in {p.name.lower() for p in packages}

    def test_skips_poetry_path_and_git_dependencies(self, fixtures_dir: Path) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        names = {p.name for p in packages}
        assert "local-thing" not in names
        assert "git-thing" not in names

    def test_parses_poetry_groups(self, fixtures_dir: Path) -> None:
        packages = PyProjectTomlParser().parse(fixtures_dir / "pyproject_sample.toml")
        black = next((p for p in packages if p.name == "black"), None)
        assert black is not None
        assert "tool.poetry.group.dev" in black.source

    def test_invalid_toml_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.toml"
        path.write_text("this is = not valid = toml")
        assert PyProjectTomlParser().parse(path) == []
