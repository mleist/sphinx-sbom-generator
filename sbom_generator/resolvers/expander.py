"""Breadth-first expander that turns a list of direct packages into the
full (or depth-bounded) transitive closure.

Why BFS rather than DFS: the report is most useful when transitive
packages are listed by their *shortest* distance from a direct
dependency. BFS naturally yields that, and it also makes the depth
cap behave intuitively — "depth 1" means "direct deps only", "depth
2" means "direct deps plus their direct deps", and so on.

Cycle handling: a package's identity for de-duplication is its
``(ecosystem, lowercased name)`` tuple. The first time we see a name
we record it; later occurrences (different parents, different
specs, etc.) are ignored. This is correct for our purposes because
the *enrichment* layer queries each package once anyway, and the
*renderer* surfaces the first-discovered parent as the path of
record. If you need full multi-path provenance, that's a future
extension and would belong here.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Mapping

from ..models import Ecosystem, Package
from .base import DependencyResolver

log = logging.getLogger(__name__)


class TransitiveExpander:
    """Walks the dependency graph using one resolver per ecosystem.

    The expander itself is ecosystem-agnostic; it dispatches each
    package to the resolver registered for its ecosystem and handles
    visit-tracking, depth limits, and a hard ceiling on total packages
    so a pathological graph cannot run forever.
    """

    def __init__(
        self,
        resolvers: Mapping[Ecosystem, DependencyResolver],
        max_depth: int = 5,
        max_packages: int = 2000,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if max_packages < 1:
            raise ValueError("max_packages must be at least 1")
        self.resolvers = dict(resolvers)
        self.max_depth = max_depth
        self.max_packages = max_packages

    def expand(self, direct: list[Package]) -> list[Package]:
        """Return ``direct`` followed by every transitive dependency.

        Direct packages are kept in the order given; transitive packages
        follow in BFS order. Each ``(ecosystem, name)`` appears exactly
        once in the result.
        """
        seen: set[tuple[Ecosystem, str]] = set()
        result: list[Package] = []
        queue: deque[tuple[Package, int]] = deque()

        # Seed with directs. Directs at depth 0 — their *own*
        # dependencies are at depth 1, which is what max_depth controls.
        for pkg in direct:
            key = (pkg.ecosystem, pkg.name.lower())
            if key in seen:
                continue
            seen.add(key)
            result.append(pkg)
            queue.append((pkg, 0))

        truncated = False
        while queue:
            current, depth = queue.popleft()
            if depth >= self.max_depth:
                continue

            resolver = self.resolvers.get(current.ecosystem)
            if resolver is None:
                continue

            try:
                children = resolver.find_dependencies(current)
            except Exception as exc:
                log.warning(
                    "Resolver for %s raised on %s: %s",
                    current.ecosystem.value,
                    current.name,
                    exc,
                )
                continue

            for child in children:
                key = (child.ecosystem, child.name.lower())
                if key in seen:
                    continue
                if len(result) >= self.max_packages:
                    truncated = True
                    break
                seen.add(key)
                result.append(child)
                queue.append((child, depth + 1))

            if truncated:
                break

        if truncated:
            log.warning(
                "Stopped expansion at %d packages (max_packages limit). "
                "Some transitive dependencies are not represented.",
                self.max_packages,
            )
        return result
