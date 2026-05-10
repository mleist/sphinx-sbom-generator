"""Parser for pip's ``requirements.txt`` format.

We delegate spec syntax to ``packaging.requirements``, but the file-level
constructs (comments, includes, editable installs, URL installs, line
continuations) need to be handled here.

Skipped with a logged note rather than supported, by design:

- ``-r other.txt`` includes — avoids surprising recursive scans; pass
  each file explicitly on the CLI instead.
- ``-e ./local-pkg`` editable installs — no registry to enrich from.
- Direct URL or path installs (``pkg @ https://…``) — same reason.
- ``--hash=`` — accepted on the line, but the hash itself is ignored.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from ..models import Ecosystem, Package
from .base import ManifestParser

log = logging.getLogger(__name__)


class RequirementsTxtParser(ManifestParser):
    def parse(self, path: Path) -> list[Package]:
        packages: list[Package] = []
        source = path.name

        for raw_line, lineno in self._iter_logical_lines(path):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement")):
                log.info("Skipping include directive at %s:%d", path, lineno)
                continue
            if line.startswith(("-e", "--editable")):
                log.info("Skipping editable install at %s:%d", path, lineno)
                continue
            if line.startswith("-"):
                # other pip flags (--index-url, --find-links, …)
                continue

            # strip trailing pip options that may follow on the same line
            spec_part = line.split(" --hash=")[0].split(" #")[0].strip()

            try:
                req = Requirement(spec_part)
            except InvalidRequirement as exc:
                log.warning(
                    "Cannot parse requirement at %s:%d (%s): %s",
                    path,
                    lineno,
                    exc,
                    line,
                )
                continue

            packages.append(
                Package(
                    name=req.name,
                    requested_spec=str(req.specifier) or "(any)",
                    ecosystem=Ecosystem.PYPI,
                    source=source,
                )
            )

        return packages

    @staticmethod
    def _iter_logical_lines(path: Path) -> Iterator[tuple[str, int]]:
        """Yield ``(line, lineno)`` tuples, joining backslash continuations.

        pip joins continuation lines without a separator (it strips the
        ``\\\\\\n`` pair); we mirror that so ``black==23.\\\\\\n12.0``
        parses as ``black==23.12.0``.
        """
        with path.open("r", encoding="utf-8") as fh:
            buffer: list[str] = []
            start_lineno = 0
            for lineno, line in enumerate(fh, start=1):
                line = line.rstrip("\n")
                if line.endswith("\\"):
                    if not buffer:
                        start_lineno = lineno
                    buffer.append(line[:-1])
                    continue
                if buffer:
                    buffer.append(line)
                    yield "".join(buffer), start_lineno
                    buffer = []
                else:
                    yield line, lineno
            if buffer:
                yield "".join(buffer), start_lineno
