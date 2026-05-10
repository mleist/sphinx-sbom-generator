"""Tests for metadata and vulnerability enrichers.

All HTTP calls are mocked via the ``responses`` library so the suite
runs offline and deterministically.
"""

from __future__ import annotations

import responses

from sbom_generator.cache import JsonFileCache
from sbom_generator.enrichers.npm import NpmEnricher
from sbom_generator.enrichers.osv import OsvEnricher
from sbom_generator.enrichers.pypi import PyPIEnricher
from sbom_generator.models import Ecosystem, EnrichedPackage, Package


def _ep(name: str, ecosystem: Ecosystem, spec: str = "==1.0.0") -> EnrichedPackage:
    return EnrichedPackage(
        package=Package(name=name, requested_spec=spec, ecosystem=ecosystem, source="test")
    )


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


class TestPyPIEnricher:
    @responses.activate
    def test_populates_metadata(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/requests/json",
            json={
                "info": {
                    "summary": "Python HTTP for Humans.",
                    "version": "2.31.0",
                    "home_page": "https://requests.readthedocs.io",
                    "license": "Apache-2.0",
                }
            },
        )

        ep = _ep("requests", Ecosystem.PYPI)
        PyPIEnricher(cache=disabled_cache).enrich(ep)

        assert ep.description == "Python HTTP for Humans."
        assert ep.latest_version == "2.31.0"
        assert ep.homepage == "https://requests.readthedocs.io"
        assert ep.license == "Apache-2.0"
        assert ep.enrichment_errors == []

    @responses.activate
    def test_404_records_error_without_raising(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/missing/json",
            status=404,
        )
        ep = _ep("missing", Ecosystem.PYPI)
        PyPIEnricher(cache=disabled_cache).enrich(ep)
        assert ep.description is None
        assert any("not found" in err for err in ep.enrichment_errors)

    def test_skips_non_pypi_ecosystems(self, disabled_cache: JsonFileCache) -> None:
        ep = _ep("lodash", Ecosystem.NPM)
        PyPIEnricher(cache=disabled_cache).enrich(ep)
        # No HTTP call expected; nothing populated, no errors.
        assert ep.description is None
        assert ep.enrichment_errors == []

    @responses.activate
    def test_uses_cache_on_second_call(self, file_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/requests/json",
            json={"info": {"summary": "x", "version": "1"}},
        )

        enricher = PyPIEnricher(cache=file_cache)
        enricher.enrich(_ep("requests", Ecosystem.PYPI))
        enricher.enrich(_ep("requests", Ecosystem.PYPI))

        # Only one HTTP call despite two enrichments.
        assert len(responses.calls) == 1


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


class TestNpmEnricher:
    @responses.activate
    def test_populates_metadata(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.GET,
            "https://registry.npmjs.org/lodash",
            json={
                "dist-tags": {"latest": "4.17.21"},
                "versions": {
                    "4.17.21": {
                        "description": "Lodash modular utilities.",
                        "homepage": "https://lodash.com/",
                        "license": "MIT",
                    }
                },
            },
        )
        ep = _ep("lodash", Ecosystem.NPM)
        NpmEnricher(cache=disabled_cache).enrich(ep)
        assert ep.latest_version == "4.17.21"
        assert ep.license == "MIT"
        assert ep.homepage == "https://lodash.com/"

    @responses.activate
    def test_normalizes_legacy_license_object(self, disabled_cache: JsonFileCache) -> None:
        # Some old packages still ship `license: {type: "MIT", url: "..."}`.
        responses.add(
            responses.GET,
            "https://registry.npmjs.org/legacy-pkg",
            json={
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"license": {"type": "BSD-3-Clause", "url": "x"}}},
            },
        )
        ep = _ep("legacy-pkg", Ecosystem.NPM)
        NpmEnricher(cache=disabled_cache).enrich(ep)
        assert ep.license == "BSD-3-Clause"

    @responses.activate
    def test_handles_scoped_package_name(self, disabled_cache: JsonFileCache) -> None:
        # Scoped names contain `/` and need URL escaping.
        responses.add(
            responses.GET,
            "https://registry.npmjs.org/@scope%2Fpkg",
            json={
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"license": "MIT"}},
            },
        )
        ep = _ep("@scope/pkg", Ecosystem.NPM)
        NpmEnricher(cache=disabled_cache).enrich(ep)
        assert ep.latest_version == "1.0.0"


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------


class TestOsvEnricher:
    @responses.activate
    def test_batch_query_returns_vulnerabilities(self, disabled_cache: JsonFileCache) -> None:
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/querybatch",
            json={"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}]},
        )
        responses.add(
            responses.GET,
            "https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz",
            json={
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Critical RCE",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
                "references": [{"url": "https://example.com/advisory"}],
            },
        )
        ep = _ep("vuln-pkg", Ecosystem.PYPI, spec="==1.0.0")
        OsvEnricher(cache=disabled_cache).enrich_all([ep])

        assert len(ep.vulnerabilities) == 1
        v = ep.vulnerabilities[0]
        assert v.id == "GHSA-xxxx-yyyy-zzzz"
        assert v.summary == "Critical RCE"
        assert "1.0.1" in v.fixed_versions

    @responses.activate
    def test_records_error_when_no_resolvable_version(self, disabled_cache: JsonFileCache) -> None:
        # No latest version, no pin -> nothing to query.
        ep = _ep("ranged", Ecosystem.PYPI, spec=">=1.0")
        # latest_version stays None, so resolved_version is None.
        OsvEnricher(cache=disabled_cache).enrich_all([ep])
        assert ep.vulnerabilities == []
        assert any("no resolvable version" in e for e in ep.enrichment_errors)

    @responses.activate
    def test_batch_failure_marks_packages_but_does_not_raise(
        self, disabled_cache: JsonFileCache
    ) -> None:
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/querybatch",
            status=500,
        )
        ep = _ep("pkg", Ecosystem.PYPI, spec="==1.0.0")
        OsvEnricher(cache=disabled_cache).enrich_all([ep])
        assert any("batch query failed" in e for e in ep.enrichment_errors)
