"""Tests for the Markdown renderer and EnrichedPackage logic."""

from __future__ import annotations

from sbom_generator.models import (
    Ecosystem,
    EnrichedPackage,
    Package,
    Vulnerability,
)
from sbom_generator.renderers.markdown import MarkdownRenderer


def _make_ep(
    name: str = "foo",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    spec: str = "==1.0.0",
    latest: str | None = "1.0.0",
    vulns: list[Vulnerability] | None = None,
) -> EnrichedPackage:
    ep = EnrichedPackage(
        package=Package(name=name, requested_spec=spec, ecosystem=ecosystem, source="test"),
        description=f"{name} description",
        latest_version=latest,
        license="MIT",
    )
    if vulns:
        ep.vulnerabilities = vulns
    return ep


class TestEnrichedPackage:
    def test_resolved_version_uses_pin_when_available(self) -> None:
        ep = _make_ep(spec="==2.5.1", latest="3.0.0")
        assert ep.resolved_version == "2.5.1"

    def test_resolved_version_falls_back_to_latest(self) -> None:
        ep = _make_ep(spec=">=1.0", latest="1.4.0")
        assert ep.resolved_version == "1.4.0"

    def test_resolved_version_is_none_without_either(self) -> None:
        ep = _make_ep(spec=">=1.0", latest=None)
        assert ep.resolved_version is None


class TestMarkdownRenderer:
    def test_includes_overview_with_counts(self) -> None:
        eps = [_make_ep("a"), _make_ep("b", Ecosystem.NPM)]
        md = MarkdownRenderer().render(eps)

        assert "# Software Bill of Materials" in md
        assert "Total packages:** 2" in md
        assert "PyPI:** 1" in md
        assert "npm:** 1" in md

    def test_groups_packages_by_ecosystem_and_source(self) -> None:
        eps = [
            _make_ep("a"),
            _make_ep("b", Ecosystem.NPM),
        ]
        md = MarkdownRenderer().render(eps)

        # Order: ecosystems alphabetical -> PyPI first, then npm.
        pypi_idx = md.index("## PyPI")
        npm_idx = md.index("## npm")
        assert pypi_idx < npm_idx

    def test_table_escapes_pipe_characters(self) -> None:
        ep = _make_ep("weird")
        ep.description = "summary with | pipe"
        md = MarkdownRenderer().render([ep])
        # The literal pipe must be escaped so the markdown table doesn't break.
        assert "summary with \\| pipe" in md

    def test_renders_vulnerability_details_section(self) -> None:
        v = Vulnerability(
            id="GHSA-1",
            summary="Bad bug",
            severity="HIGH",
            fixed_versions=("1.0.1",),
            references=("https://example.com/a",),
        )
        ep = _make_ep("vuln", vulns=[v])
        md = MarkdownRenderer().render([ep])

        assert "## Vulnerability Details" in md
        assert "GHSA-1" in md
        assert "Bad bug" in md
        assert "1.0.1" in md

    def test_no_vulnerability_section_when_none_found(self) -> None:
        md = MarkdownRenderer().render([_make_ep()])
        assert "Vulnerability Details" not in md

    def test_handles_missing_metadata_gracefully(self) -> None:
        # All optional fields stripped — renderer should still work.
        ep = EnrichedPackage(
            package=Package(
                name="bare",
                requested_spec="==1.0.0",
                ecosystem=Ecosystem.PYPI,
                source="test",
            )
        )
        md = MarkdownRenderer().render([ep])
        assert "bare" in md

    def test_overview_counts_direct_and_transitive(self) -> None:
        direct = _make_ep("a")
        trans = EnrichedPackage(
            package=Package(
                name="b",
                requested_spec="(any)",
                ecosystem=Ecosystem.PYPI,
                source="transitive (via a)",
                is_transitive=True,
                parent="a",
            )
        )
        md = MarkdownRenderer().render([direct, trans])
        assert "Direct:** 1" in md
        assert "Transitive:** 1" in md

    def test_transitive_section_includes_via_column(self) -> None:
        direct = _make_ep("a")
        trans = EnrichedPackage(
            package=Package(
                name="b",
                requested_spec="(any)",
                ecosystem=Ecosystem.PYPI,
                source="transitive (via a)",
                is_transitive=True,
                parent="a",
            )
        )
        md = MarkdownRenderer().render([direct, trans])
        assert "### Transitive dependencies" in md
        # Transitive table has the extra "Via" column.
        assert "| Package | Via | Spec |" in md
        # The parent name appears in the `Via` cell.
        assert "`a`" in md.split("### Transitive dependencies", 1)[1]

    def test_no_transitive_section_when_only_directs(self) -> None:
        md = MarkdownRenderer().render([_make_ep("a"), _make_ep("b")])
        assert "Transitive dependencies" not in md
