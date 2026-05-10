"""Abstract base for transitive dependency resolvers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Package


class DependencyResolver(ABC):
    """Returns the *direct* runtime dependencies of a package.

    Implementations look up registry metadata for a given package and
    extract its runtime dependency list. They are intentionally one
    hop deep — the BFS expander in ``resolvers.expander`` is responsible
    for walking the graph, deduplicating, and capping depth.
    """

    @abstractmethod
    def find_dependencies(self, package: Package) -> list[Package]:
        """Return the runtime dependencies of ``package``.

        The returned packages have ``is_transitive=True`` and ``parent``
        set to ``package.name``. They are *candidates* — the expander
        decides which ones are actually new and need to be visited.

        Failures (network, package not found, version unknown) should be
        logged and produce an empty list; the expander should never have
        to handle exceptions from this method.
        """
