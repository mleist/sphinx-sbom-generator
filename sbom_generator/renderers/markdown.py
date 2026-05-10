"""Markdown renderer producing Sphinx-compatible output.

Output layout:

- H1 title with generation timestamp
- Overview block with totals and counts
- One H2 section per ecosystem (PyPI, npm), each containing:

  - One H3 subsection per source (``dependencies`` vs ``devDependencies``)
  - A table of packages: name, requested spec, resolved version, latest,
    license, vulnerabilities, description.

- A trailing H2 ``Vulnerability Details`` section with one H3 per
  affected package, listing every CVE/GHSA found with summary, severity,
  fixed versions, and reference links.

Sphinx (with ``myst-parser``) renders this directly. We deliberately avoid
Sphinx-specific directives so the same file is also readable on GitHub
or any plain Markdown viewer.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from ..models import Ecosystem, EnrichedPackage, Vulnerability


class MarkdownRenderer:
    def render(
        self,
        packages: list[EnrichedPackage],
        title: str = "Software Bill of Materials",
    ) -> str:
        lines: list[str] = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"_Generated on {ts}._")
        lines.append("")
        lines.extend(self._overview(packages))
        lines.append("")

        by_eco: dict[Ecosystem, list[EnrichedPackage]] = defaultdict(list)
        for ep in packages:
            by_eco[ep.package.ecosystem].append(ep)

        for eco in sorted(by_eco.keys(), key=lambda e: e.value):
            lines.extend(self._render_ecosystem(eco, by_eco[eco]))

        vuln_section = self._render_vulnerability_details(packages)
        if vuln_section:
            lines.extend(vuln_section)

        return "\n".join(lines).rstrip() + "\n"

    # --- sections ---

    def _overview(self, packages: list[EnrichedPackage]) -> list[str]:
        total = len(packages)
        direct = sum(1 for p in packages if not p.package.is_transitive)
        transitive = total - direct
        vulnerable = sum(1 for p in packages if p.has_vulnerabilities)
        vuln_count = sum(len(p.vulnerabilities) for p in packages)
        by_eco: dict[Ecosystem, int] = defaultdict(int)
        for p in packages:
            by_eco[p.package.ecosystem] += 1

        rows = ["## Overview", "", f"- **Total packages:** {total}"]
        rows.append(f"- **Direct:** {direct}")
        rows.append(f"- **Transitive:** {transitive}")
        for eco, count in sorted(by_eco.items(), key=lambda x: x[0].value):
            rows.append(f"- **{eco.value}:** {count}")
        rows.append(f"- **Packages with known vulnerabilities:** {vulnerable}")
        rows.append(f"- **Total vulnerabilities:** {vuln_count}")
        return rows

    def _render_ecosystem(self, eco: Ecosystem, eps: list[EnrichedPackage]) -> list[str]:
        lines = [f"## {eco.value}", ""]
        directs = [ep for ep in eps if not ep.package.is_transitive]
        transitives = [ep for ep in eps if ep.package.is_transitive]

        by_source: dict[str, list[EnrichedPackage]] = defaultdict(list)
        for ep in directs:
            by_source[ep.package.source].append(ep)

        for source in sorted(by_source.keys()):
            lines.append(f"### {source}")
            lines.append("")
            sorted_eps = sorted(by_source[source], key=lambda p: p.package.name.lower())
            lines.append(self._render_table(sorted_eps, include_via=False))
            lines.append("")

        if transitives:
            lines.append("### Transitive dependencies")
            lines.append("")
            lines.append(
                f"_{len(transitives)} package(s) pulled in indirectly. "
                "The 'Via' column shows the immediate parent that introduced "
                "each dependency._"
            )
            lines.append("")
            sorted_trans = sorted(transitives, key=lambda p: p.package.name.lower())
            lines.append(self._render_table(sorted_trans, include_via=True))
            lines.append("")

        return lines

    def _render_table(self, eps: list[EnrichedPackage], include_via: bool) -> str:
        if include_via:
            header = "| Package | Via | Spec | Resolved | Latest | License | Vulns | Description |"
            sep = "|---|---|---|---|---|---|---|---|"
        else:
            header = "| Package | Spec | Resolved | Latest | License | Vulns | Description |"
            sep = "|---|---|---|---|---|---|---|"
        rows = [header, sep]
        for ep in eps:
            name = (
                self._link(ep.package.name, ep.homepage) if ep.homepage else f"`{ep.package.name}`"
            )
            spec = self._md_escape(ep.package.requested_spec)
            resolved = ep.resolved_version or "—"
            latest = ep.latest_version or "—"
            license_ = self._md_escape(ep.license) if ep.license else "—"
            vulns = self._vuln_cell(ep.vulnerabilities)
            desc = self._md_escape(ep.description) if ep.description else "—"
            if include_via:
                via = f"`{ep.package.parent}`" if ep.package.parent else "—"
                rows.append(
                    f"| {name} | {via} | `{spec}` | `{resolved}` | `{latest}` | "
                    f"{license_} | {vulns} | {desc} |"
                )
            else:
                rows.append(
                    f"| {name} | `{spec}` | `{resolved}` | `{latest}` | "
                    f"{license_} | {vulns} | {desc} |"
                )
        return "\n".join(rows)

    def _render_vulnerability_details(self, packages: list[EnrichedPackage]) -> list[str]:
        affected = [p for p in packages if p.has_vulnerabilities]
        if not affected:
            return []
        lines = ["## Vulnerability Details", ""]
        for ep in sorted(affected, key=lambda p: p.package.name.lower()):
            header = (
                f"### {ep.package.name} ({ep.package.ecosystem.value} {ep.resolved_version or '?'})"
            )
            lines.append(header)
            lines.append("")
            for v in ep.vulnerabilities:
                lines.extend(self._render_vuln(v))
                lines.append("")
        return lines

    @staticmethod
    def _render_vuln(v: Vulnerability) -> list[str]:
        head = f"**{v.id}**" + (f" — _{v.severity}_" if v.severity else "")
        out = [head]
        if v.summary:
            out.append("")
            out.append(v.summary)
        if v.fixed_versions:
            out.append("")
            out.append("Fixed in: " + ", ".join(f"`{fv}`" for fv in v.fixed_versions))
        if v.references:
            out.append("")
            out.append("References:")
            for ref in v.references[:5]:  # cap to keep list scannable
                out.append(f"- <{ref}>")
        return out

    # --- helpers ---

    @staticmethod
    def _vuln_cell(vulns: list[Vulnerability]) -> str:
        if not vulns:
            return "—"
        # Warning emoji so a quick visual scan of the table catches issues
        ids = ", ".join(v.id for v in vulns[:3])
        if len(vulns) > 3:
            ids += f", +{len(vulns) - 3}"
        return f"⚠️ {ids}"

    @staticmethod
    def _link(text: str, url: str) -> str:
        return f"[{text}]({url})"

    @staticmethod
    def _md_escape(s: str | None) -> str:
        if s is None:
            return ""
        # minimal: escape pipe (table breaker) and collapse newlines
        return s.replace("|", "\\|").replace("\n", " ").strip()
