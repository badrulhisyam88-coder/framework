"""Page object: investigation workspace.

Wraps the /api/v1/validation/workspace/investigations/{id} surface.
Exposes the assertable properties the exploitation phase UI presents:
current phase badge, category filter chips, exploitation tab visibility.

Used by V2.2 closeout scenarios — not the sanity test.
"""
from __future__ import annotations


class WorkspacePage:
    """Page object for the investigation workspace (/workspace/investigations/{id})."""

    _WORKSPACE_PATH = "/api/v1/validation/workspace/investigations/{investigation_id}"

    def __init__(self, page):
        self._page = page

    @classmethod
    async def open(cls, context, base_url: str, investigation_id: str) -> "WorkspacePage":
        path = cls._WORKSPACE_PATH.format(investigation_id=investigation_id)
        page = await context.new_page()
        await page.goto(f"{base_url}{path}")
        return cls(page)

    async def phase_badge_text(self) -> str:
        """Return the text of the current phase badge element.

        The badge element carries data-phase attribute and visible text.
        Catches Pattern 13 failure mode at the JS rendering layer.
        """
        badge = await self._page.query_selector("[data-phase]")
        if badge is None:
            return ""
        return (await badge.text_content() or "").strip()

    async def category_filter_chips(self) -> list[str]:
        """Return the text of all visible category filter chips.

        Used to verify that the exploitation category tab renders chips
        for the active categories after an engine lift.
        """
        chips = await self._page.query_selector_all(".category-chip, .cat-chip, [data-slug]")
        return [(await c.text_content() or "").strip() for c in chips if (await c.text_content())]

    async def active_category_slug(self) -> str:
        """Return the slug of the currently active category chip."""
        active = await self._page.query_selector(".cat-chip.active, .category-chip.active")
        if active is None:
            return ""
        return (await active.get_attribute("data-slug") or "")

    async def exploitation_tab_visible(self) -> bool:
        """Return True if the Exploitation tab is visible in the workspace nav."""
        tab = await self._page.query_selector("[data-tab='exploitation'], #exploitation-tab")
        return tab is not None

    async def close(self) -> None:
        await self._page.close()
