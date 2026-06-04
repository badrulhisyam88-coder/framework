"""Frontend smoke test infrastructure sanity tests.

One test per helper category — proves the substrate works before coverage
tests for V2.1 surfaces are written (next PR).

Category 1 (html_helpers): Render a real admin partial template with mock
  state and assert on structural properties.
Category 2 (api_helpers): Hit a real admin endpoint against a test app and
  assert on response shape. Skipped if fastapi is absent (bare test env).
Category 3 (asset_helpers): Grep a JS static asset for known-present and
  known-absent strings.
"""
from __future__ import annotations

import pytest

# ── Category 1 — HTML structural assertions ───────────────────────────────────


def test_html_helper_renders_empty_conductor_table():
    """render_template_file() renders _conductor_table.html with mock empty state.

    Verifies the helper can load a real admin partial (with {% if %} logic)
    and that BeautifulSoup correctly finds the 'No active investigations.' row.
    """
    from tests.frontend.html_helpers import render_template_file, select, text_of

    soup = render_template_file(
        "apps/admin_ui/templates",
        "admin/_conductor_table.html",
        context={
            "investigations": [],
            "target_auth": {},
            "now_iso": "2026-01-01T00:00:00",
        },
    )
    cells = select(soup, "td")
    cell_texts = [text_of(c) for c in cells]
    assert "No active investigations." in cell_texts, (
        "render_template_file() did not produce expected 'No active investigations.' cell. "
        f"Got cells: {cell_texts}"
    )


def test_html_helper_renders_investigation_row_with_state_class():
    """render_template_file() renders state CSS class correctly on investigation rows."""
    from tests.frontend.html_helpers import render_template_file, select, attr

    soup = render_template_file(
        "apps/admin_ui/templates",
        "admin/_conductor_table.html",
        context={
            "investigations": [
                {
                    "id": "inv_test_001",
                    "target": "http://example.local",
                    "state": "RUNNING",
                    "current_phase": "enumeration",
                    "findings_count": 3,
                    "age_seconds": 42,
                },
            ],
            "target_auth": {},
            "now_iso": "2026-01-01T00:00:00",
        },
    )
    state_cells = select(soup, "td.state-RUNNING")
    assert len(state_cells) == 1, (
        f"Expected exactly 1 td.state-RUNNING, got {len(state_cells)}"
    )
    assert "state-RUNNING" in (attr(state_cells[0], "class") or [])


def test_html_helper_template_string():
    """render_template_string() renders an inline template."""
    from tests.frontend.html_helpers import render_template_string, select

    soup = render_template_string(
        "<ul>{% for item in items %}<li class='entry'>{{ item }}</li>{% endfor %}</ul>",
        context={"items": ["alpha", "beta"]},
    )
    entries = select(soup, "li.entry")
    assert len(entries) == 2
    assert entries[0].get_text(strip=True) == "alpha"
    assert entries[1].get_text(strip=True) == "beta"


# ── Category 2 — JSON/HTML endpoint shape assertions ─────────────────────────
# Requires FastAPI. Skipped in the bare test environment (no fastapi installed).


@pytest.mark.asyncio
async def test_api_helper_admin_conductor_refresh_returns_200(tmp_path):
    """async_client(build_admin_app()) hits /admin/conductor/refresh and gets 200.

    Verifies the Category 2 helper builds a working ASGI test client and
    that the admin refresh endpoint returns the expected no-investigations HTML.
    """
    pytest.importorskip("fastapi")

    from tests.frontend.api_helpers import assert_html_200, async_client, build_admin_app

    app_bundle = build_admin_app(tmp_path)
    async with async_client(app_bundle) as (client, _):
        resp = await client.get("/admin/conductor/refresh")
        assert_html_200(resp, contains="No active investigations.")


@pytest.mark.asyncio
async def test_api_helper_assert_html_200_fails_on_bad_status(tmp_path):
    """assert_html_200() raises AssertionError when status != 200."""
    pytest.importorskip("fastapi")

    from tests.frontend.api_helpers import assert_html_200, async_client, build_admin_app

    app_bundle = build_admin_app(tmp_path)
    async with async_client(app_bundle) as (client, _):
        resp = await client.get("/admin/nonexistent_route_xyz")
        with pytest.raises(AssertionError, match="404"):
            assert_html_200(resp)


# ── Category 3 — Static asset reference checks ────────────────────────────────


def test_asset_helper_assert_present_finds_known_symbol():
    """assert_present() finds CRITICAL_KINDS in exploit-tree.js."""
    from tests.frontend.asset_helpers import assert_present

    lines = assert_present("frontend/static/js/exploit-tree.js", "CRITICAL_KINDS")
    assert lines, "assert_present() returned empty list for a present string"
    assert all(isinstance(n, int) and n > 0 for n in lines)


def test_asset_helper_assert_absent_passes_for_retired_symbol():
    """assert_absent() passes for csp_xss_reflected (removed in V2.2 Step 1)."""
    from tests.frontend.asset_helpers import assert_absent

    assert_absent("frontend/static/js/exploit-tree.js", "csp_xss_reflected")


def test_asset_helper_assert_absent_fails_for_present_symbol():
    """assert_absent() raises AssertionError when the string IS present."""
    from tests.frontend.asset_helpers import assert_absent

    with pytest.raises(AssertionError, match="CRITICAL_KINDS"):
        assert_absent("frontend/static/js/exploit-tree.js", "CRITICAL_KINDS")


def test_asset_helper_grep_returns_line_numbers():
    """grep_source() returns correct 1-based line numbers."""
    from tests.frontend.asset_helpers import grep_source

    lines = grep_source("frontend/static/js/exploit-tree.js", "CRITICAL_KINDS")
    assert isinstance(lines, list)
    assert len(lines) >= 1
    assert all(isinstance(n, int) and n > 0 for n in lines)


def test_asset_helper_grep_returns_empty_for_absent():
    """grep_source() returns [] for a string not present in the file."""
    from tests.frontend.asset_helpers import grep_source

    lines = grep_source("frontend/static/js/exploit-tree.js", "csp_xss_reflected")
    assert lines == []
