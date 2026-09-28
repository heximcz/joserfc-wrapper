"""Documentation must be readable on GitHub and on Read the Docs"""

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).parent.parent / "docs"


def toc_pages() -> list[str]:
    """Pages in the order of the Sphinx navigation (docs/_toc.md)"""
    toc = (DOCS / "_toc.md").read_text()
    block = re.search(r"```\{toctree\}\n(.*?)```", toc, re.S)
    assert block, "toctree in docs/_toc.md"
    return [
        line.strip()
        for line in block.group(1).splitlines()
        if line.strip() and not line.startswith(":")
    ]


def title(page: str) -> str:
    match = re.search(r"^# (.+)$", (DOCS / f"{page}.md").read_text(), re.M)
    assert match, f"{page}.md has a title"
    return match.group(1)


def expected_navigation(pages: list[str], i: int) -> str:
    items = []
    if i > 1:
        items.append(
            f"[< Previous: {title(pages[i - 1])}](./{pages[i - 1]}.md)"
        )
    items.append("[Contents](./index.md)")
    if i + 1 < len(pages):
        items.append(f"[Next: {title(pages[i + 1])} >](./{pages[i + 1]}.md)")
    return " |\n".join(items)


def test_all_pages_are_in_navigation():
    pages = set(toc_pages())
    files = {p.stem for p in DOCS.glob("*.md")} - {"_toc"}

    assert pages == files


def test_index_links_all_pages():
    """GitHub has no Sphinx navigation, index.md lists all pages"""
    index = (DOCS / "index.md").read_text()
    links = set(re.findall(r"\]\(\./([a-z-]+)\.md\)", index))

    assert links == set(toc_pages()) - {"index"}


@pytest.mark.parametrize("page", toc_pages()[1:])
def test_page_navigation(page):
    """Each page ends with links to the previous, contents and next page"""
    pages = toc_pages()
    text = (DOCS / f"{page}.md").read_text().rstrip()

    assert text.endswith(expected_navigation(pages, pages.index(page)))


def test_sphinx_directives_only_in_toc_and_api():
    """Sphinx directives are not rendered on GitHub"""
    for path in DOCS.glob("*.md"):
        if path.stem in ("_toc", "api"):
            continue
        assert "```{" not in path.read_text(), path.name
