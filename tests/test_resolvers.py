"""Tests for transitive dependency resolvers and the BFS expander."""

from __future__ import annotations

import responses

from sbom_generator.cache import JsonFileCache
from sbom_generator.models import Ecosystem, Package
from sbom_generator.resolvers.base import DependencyResolver
from sbom_generator.resolvers.expander import TransitiveExpander
from sbom_generator.resolvers.npm import NpmDependencyResolver
from sbom_generator.resolvers.pypi import PyPIDependencyResolver


def _direct(name: str, ecosystem: Ecosystem, spec: str = "==1.0.0") -> Package:
    return Package(name=name, requested_spec=spec, ecosystem=ecosystem, source="test")


# ---------------------------------------------------------------------------
# PyPI resolver
# ---------------------------------------------------------------------------


class TestPyPIDependencyResolver:
    @responses.activate
    def test_returns_runtime_deps(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/flask/3.0.0/json",
            json={"info": {"requires_dist": ["click>=8", "jinja2>=3"]}},
        )
        deps = PyPIDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("flask", Ecosystem.PYPI, spec="==3.0.0")
        )
        names = {d.name for d in deps}
        assert names == {"click", "jinja2"}
        assert all(d.is_transitive for d in deps)
        assert all(d.parent == "flask" for d in deps)

    @responses.activate
    def test_filters_extras_via_marker(self, disabled_cache: JsonFileCache) -> None:
        # Markers gated on `extra == "..."` are not part of the runtime
        # closure and must be excluded.
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/example/1.0.0/json",
            json={
                "info": {
                    "requires_dist": [
                        "core-dep>=1",
                        "docs-dep>=1; extra == 'docs'",
                    ]
                }
            },
        )
        deps = PyPIDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("example", Ecosystem.PYPI, spec="==1.0.0")
        )
        names = {d.name for d in deps}
        assert "core-dep" in names
        assert "docs-dep" not in names

    @responses.activate
    def test_falls_back_to_latest_when_pinned_version_missing(
        self, disabled_cache: JsonFileCache
    ) -> None:
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/foo/9.9.9/json",
            status=404,
        )
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/foo/json",
            json={"info": {"requires_dist": ["bar"]}},
        )
        deps = PyPIDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("foo", Ecosystem.PYPI, spec="==9.9.9")
        )
        assert {d.name for d in deps} == {"bar"}

    def test_skips_non_pypi_packages(self, disabled_cache: JsonFileCache) -> None:
        deps = PyPIDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("lodash", Ecosystem.NPM)
        )
        assert deps == []


# ---------------------------------------------------------------------------
# npm resolver
# ---------------------------------------------------------------------------


class TestNpmDependencyResolver:
    @responses.activate
    def test_returns_runtime_deps_for_pinned_version(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://registry.npmjs.org/express",
            json={
                "dist-tags": {"latest": "4.18.2"},
                "versions": {"4.18.2": {"dependencies": {"accepts": "~1.3.8"}}},
            },
        )
        deps = NpmDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("express", Ecosystem.NPM, spec="4.18.2")
        )
        names = {d.name for d in deps}
        assert names == {"accepts"}
        assert all(d.is_transitive for d in deps)
        assert all(d.parent == "express" for d in deps)

    @responses.activate
    def test_falls_back_to_dist_tag_latest_for_ranges(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://registry.npmjs.org/foo",
            json={
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "1.0.0": {"dependencies": {"old-dep": "1"}},
                    "2.0.0": {"dependencies": {"new-dep": "2"}},
                },
            },
        )
        # `^1.0.0` doesn't match exactly; resolver picks dist-tags.latest.
        deps = NpmDependencyResolver(cache=disabled_cache).find_dependencies(
            _direct("foo", Ecosystem.NPM, spec="^1.0.0")
        )
        assert {d.name for d in deps} == {"new-dep"}


# ---------------------------------------------------------------------------
# Expander
# ---------------------------------------------------------------------------


class _FakeResolver(DependencyResolver):
    """A static graph, indexed by package name, for expander tests."""

    def __init__(self, graph: dict[str, list[str]]) -> None:
        self.graph = graph
        self.calls: list[str] = []

    def find_dependencies(self, package: Package) -> list[Package]:
        self.calls.append(package.name)
        return [
            Package(
                name=child,
                requested_spec="(any)",
                ecosystem=package.ecosystem,
                source=f"transitive (via {package.name})",
                is_transitive=True,
                parent=package.name,
            )
            for child in self.graph.get(package.name, [])
        ]


class TestTransitiveExpander:
    def test_expands_breadth_first_and_dedupes(self) -> None:
        # a -> b, c ; b -> d ; c -> d (shared); d -> nothing.
        resolver = _FakeResolver({"a": ["b", "c"], "b": ["d"], "c": ["d"]})
        expander = TransitiveExpander(resolvers={Ecosystem.PYPI: resolver}, max_depth=5)
        result = expander.expand([_direct("a", Ecosystem.PYPI)])

        names = [p.name for p in result]
        # a (direct) first; then b, c at depth 1; then d once at depth 2.
        assert names == ["a", "b", "c", "d"]
        # d resolved through whichever parent reached it first (b in BFS).
        d = next(p for p in result if p.name == "d")
        assert d.parent == "b"

    def test_handles_cycles(self) -> None:
        # a -> b -> a -> ...
        resolver = _FakeResolver({"a": ["b"], "b": ["a"]})
        expander = TransitiveExpander(resolvers={Ecosystem.PYPI: resolver}, max_depth=10)
        result = expander.expand([_direct("a", Ecosystem.PYPI)])
        assert [p.name for p in result] == ["a", "b"]

    def test_respects_max_depth(self) -> None:
        # depth 0: a (direct); depth 1: b; depth 2 not reached.
        resolver = _FakeResolver({"a": ["b"], "b": ["c"], "c": ["d"]})
        expander = TransitiveExpander(resolvers={Ecosystem.PYPI: resolver}, max_depth=1)
        result = expander.expand([_direct("a", Ecosystem.PYPI)])
        assert [p.name for p in result] == ["a", "b"]

    def test_respects_max_packages(self) -> None:
        resolver = _FakeResolver({"a": ["b", "c", "d", "e"]})
        expander = TransitiveExpander(
            resolvers={Ecosystem.PYPI: resolver},
            max_depth=5,
            max_packages=3,
        )
        result = expander.expand([_direct("a", Ecosystem.PYPI)])
        # a (direct) + 2 transitives = 3, then stop.
        assert len(result) == 3

    def test_resolver_exception_does_not_break_run(self) -> None:
        class _Boom(DependencyResolver):
            def find_dependencies(self, package: Package) -> list[Package]:
                raise RuntimeError("boom")

        expander = TransitiveExpander(resolvers={Ecosystem.PYPI: _Boom()}, max_depth=5)
        result = expander.expand([_direct("a", Ecosystem.PYPI)])
        assert [p.name for p in result] == ["a"]

    def test_rejects_invalid_limits(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            TransitiveExpander(resolvers={}, max_depth=0)
        with pytest.raises(ValueError):
            TransitiveExpander(resolvers={}, max_packages=0)
