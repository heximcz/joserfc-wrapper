"""Sphinx configuration of the documentation (Read the Docs)"""

# pylint: disable=invalid-name,redefined-builtin

from importlib.metadata import version as package_version

project = "joserfc-wrapper"
author = "Lubomir Spacek"
copyright = "2024, Lubomir Spacek"
release = package_version("joserfc-wrapper")
version = release

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
]

# navigation (toctree) is in _toc.md, index.md is plain markdown readable
# on GitHub and it is also the home page (index.html)
root_doc = "_toc"
source_suffix = {".md": "markdown"}
exclude_patterns = ["_build"]

# GitHub style anchors of headings (#upgrading-from-03x)
myst_heading_anchors = 3

# types are taken from the type hints of the code
autodoc_typehints = "description"
autodoc_member_order = "bysource"
autodoc_default_options = {"members": True, "show-inheritance": True}

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
html_title = f"joserfc-wrapper {release}"
