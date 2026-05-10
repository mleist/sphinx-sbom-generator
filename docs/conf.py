"""Sphinx configuration for the sbom-generator documentation."""

from __future__ import annotations

import importlib.metadata

# -- Project information -----------------------------------------------------

project = "sbom-generator"
author = "Markus Leist"
copyright = "2026, Markus Leist"

try:
    release = importlib.metadata.version("sbom-generator")
except importlib.metadata.PackageNotFoundError:
    # Building docs without installing the package.
    release = "0.0.0+unknown"

version = ".".join(release.split(".")[:2])

# -- General configuration ---------------------------------------------------

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
]

# Treat both .rst and .md as source.
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- HTML output -------------------------------------------------------------

html_theme = "alabaster"
html_static_path = ["_static"]

# -- Intersphinx -------------------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- MyST --------------------------------------------------------------------

myst_enable_extensions = [
    "deflist",
    "fieldlist",
    "tasklist",
]
