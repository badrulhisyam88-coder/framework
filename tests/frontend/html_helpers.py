"""Category 1 — Rendered HTML structural assertions.

Helpers for rendering Jinja2 templates with mock state and returning parsed
HTML (BeautifulSoup) for structural assertion.

No FastAPI dependency. Works in the bare test environment.

Typical use:
    from tests.frontend.html_helpers import render_template_file, select, text_of

    soup = render_template_file(
        "apps/admin_ui/templates",
        "admin/_conductor_table.html",
        context={"investigations": [], "target_auth": {}, "now_iso": "2026-01-01T00:00:00"},
    )
    assert "No active investigations." in soup.get_text()

    rows = select(soup, "tr.state-EXPLOIT_RUNNING")
    assert len(rows) == 1
    assert text_of(rows[0]) == "Mark Done"
"""
from __future__ import annotations

import pathlib
from typing import Any

import jinja2
from bs4 import BeautifulSoup, Tag

_PROJECT_ROOT = pathlib.Path(__file__).parents[2]


def render_template_string(
    source: str,
    context: dict[str, Any] | None = None,
) -> BeautifulSoup:
    """Render a Jinja2 template string with context, return parsed HTML.

    Use for quick inline assertions on template snippets.
    """
    env = jinja2.Environment(autoescape=jinja2.select_autoescape(["html"]))
    tmpl = env.from_string(source)
    html = tmpl.render(**(context or {}))
    return BeautifulSoup(html, "html.parser")


def render_template_file(
    loader_dir: str | pathlib.Path,
    template_name: str,
    context: dict[str, Any] | None = None,
) -> BeautifulSoup:
    """Render a Jinja2 template file with context, return parsed HTML.

    loader_dir: root directory for the FileSystemLoader. Can be absolute
        or relative to the project root.
        Example: "apps/admin_ui/templates"
    template_name: path relative to loader_dir.
        Example: "admin/_conductor_table.html"
    context: variables passed to the template.

    Supports {% extends %} and {% include %} — both resolve relative to
    loader_dir. Autoescape is enabled for HTML files.
    """
    loader_path = pathlib.Path(loader_dir)
    if not loader_path.is_absolute():
        loader_path = _PROJECT_ROOT / loader_path

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(loader_path)),
        autoescape=jinja2.select_autoescape(["html"]),
    )
    tmpl = env.get_template(template_name)
    html = tmpl.render(**(context or {}))
    return BeautifulSoup(html, "html.parser")


def select(soup: BeautifulSoup | Tag, css_selector: str) -> list[Tag]:
    """Return all elements matching css_selector."""
    return soup.select(css_selector)


def text_of(tag: BeautifulSoup | Tag) -> str:
    """Return stripped text content of a tag."""
    return tag.get_text(strip=True)


def attr(tag: Tag, attr_name: str) -> str | None:
    """Return the value of an attribute, or None if absent."""
    return tag.get(attr_name)
