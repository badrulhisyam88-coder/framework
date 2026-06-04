"""Page object: admin conductor panel.

Wraps the /admin/conductor and /admin/conductor/refresh surfaces.
Exposes assertable properties without tests needing raw CSS selectors.
"""
from __future__ import annotations


class AdminConductorPage:
    """Page object for /admin/conductor."""

    def __init__(self, page):
        self._page = page

    @classmethod
    async def open(cls, context, base_url: str) -> "AdminConductorPage":
        page = await context.new_page()
        await page.goto(f"{base_url}/admin/conductor")
        return cls(page)

    async def heading_text(self) -> str:
        """Return the text of the first h1 heading."""
        return (await self._page.text_content("h1") or "").strip()

    async def investigation_ids(self) -> list[str]:
        """Return the list of investigation IDs shown in the conductor table."""
        rows = await self._page.query_selector_all("tbody tr td:first-child")
        texts = [(await r.text_content() or "").strip() for r in rows]
        return [t for t in texts if t and t != "No active investigations."]

    async def current_phases(self) -> list[str]:
        """Return the list of current_phase values shown in column 4 of the table."""
        cells = await self._page.query_selector_all("tbody tr td:nth-child(4)")
        return [(await c.text_content() or "").strip() for c in cells]

    async def has_mark_done_button(self) -> bool:
        """Return True if a 'Mark Done' button is visible in the table."""
        btn = await self._page.query_selector("button[hx-post='/admin/exploitation/complete']")
        return btn is not None

    async def close(self) -> None:
        await self._page.close()
