"""Page object: exploitation mindmap + right-side panel.

Wraps the three-level mindmap surface (#exploit-tree-root) and the right-side
panel (#ws-panel / #ws-panel-body) rendered by exploitation-mindmap.js.

React Flow renders nodes as .react-flow__node divs inside the container.
Each node is identified by text content, state badge text, or button label —
there are no data-layer DOM attributes added by the mindmap (by design, to keep
the JS small). Locators below are stable against panel re-rendering.

Used by V2.3 closeout milestone browser scenarios. The browser scenarios are
documented-skip in test_v23_milestone.py when workspace routes are not mounted
in the test server — but this page object documents the intended interaction
surface for future full-workspace milestone runs.
"""
from __future__ import annotations


class MindmapPage:
    """Page object for the exploitation mindmap and panel."""

    _WORKSPACE_PATH = "/api/v1/validation/workspace/investigations/{investigation_id}"

    def __init__(self, page):
        self._page = page

    @classmethod
    async def open(
        cls,
        context,
        base_url: str,
        investigation_id: str,
        phase: str = "exploitation",
    ) -> "MindmapPage":
        path = cls._WORKSPACE_PATH.format(investigation_id=investigation_id)
        page = await context.new_page()
        await page.goto(f"{base_url}{path}?phase={phase}")
        return cls(page)

    # ── Mindmap container ─────────────────────────────────────────────────────

    async def mindmap_container_present(self) -> bool:
        """Return True if the React Flow mindmap container is in the DOM."""
        el = await self._page.query_selector("#exploit-tree-root")
        return el is not None

    async def wait_for_react_flow(self, timeout: float = 5.0) -> bool:
        """Wait up to timeout seconds for React Flow to mount its viewport."""
        try:
            await self._page.wait_for_selector(
                ".react-flow__viewport",
                timeout=int(timeout * 1000),
            )
            return True
        except Exception:
            return False

    # ── Node queries ──────────────────────────────────────────────────────────

    async def all_react_flow_nodes(self):
        """Return all .react-flow__node elements (all layers combined)."""
        return await self._page.query_selector_all(".react-flow__node")

    async def nodes_with_text(self, text: str):
        """Return nodes whose text content contains the given string."""
        nodes = await self.all_react_flow_nodes()
        result = []
        for node in nodes:
            content = (await node.text_content() or "").strip()
            if text in content:
                result.append(node)
        return result

    async def arm_buttons(self):
        """Return all 'Arm exploit →' buttons (L1 nodes without a branch)."""
        return await self._page.query_selector_all("button:has-text('Arm exploit →')")

    async def execute_buttons(self):
        """Return all 'Execute →' buttons (L1 non-critical nodes without a branch)."""
        return await self._page.query_selector_all("button:has-text('Execute →')")

    async def running_badges(self):
        """Return all '⏳ Running…' state badge elements (L1 with running branch)."""
        return await self._page.query_selector_all("span:has-text('Running…')")

    async def done_badges(self):
        """Return all '✓ Done' state badge elements (L1 with succeeded branch)."""
        return await self._page.query_selector_all("span:has-text('✓ Done')")

    async def progress_nodes(self):
        """Return all L2 progress nodes (⏳ In progress text)."""
        return await self._page.query_selector_all("*:has-text('⏳ In progress')")

    async def result_artifact_nodes(self):
        """Return all L3 result nodes showing '✓ Artifact'."""
        return await self._page.query_selector_all("*:has-text('✓ Artifact')")

    async def result_exhausted_nodes(self):
        """Return all L3 result nodes showing '⊘ Exhausted'."""
        return await self._page.query_selector_all("*:has-text('⊘ Exhausted')")

    # ── Right-side panel ──────────────────────────────────────────────────────

    async def panel_is_visible(self) -> bool:
        """Return True if the right-side panel is shown (not hidden)."""
        panel = await self._page.query_selector("#ws-panel")
        if not panel:
            return False
        classes = (await panel.get_attribute("class") or "")
        return "hidden" not in classes

    async def panel_header_text(self) -> str:
        """Return the current panel header text (e.g. 'Branch State', 'Result')."""
        el = await self._page.query_selector("#ws-panel-header-text")
        return ((await el.text_content()) or "").strip() if el else ""

    async def panel_body_html(self) -> str:
        """Return the inner HTML of #ws-panel-body."""
        el = await self._page.query_selector("#ws-panel-body")
        return (await el.inner_html()) if el else ""

    async def panel_body_text(self) -> str:
        """Return the visible text of #ws-panel-body."""
        el = await self._page.query_selector("#ws-panel-body")
        return ((await el.text_content()) or "").strip() if el else ""

    async def wait_for_panel(self, timeout: float = 3.0) -> bool:
        """Wait for the panel to become visible."""
        try:
            await self._page.wait_for_function(
                """() => {
                    const p = document.getElementById('ws-panel');
                    return p && !p.classList.contains('hidden');
                }""",
                timeout=int(timeout * 1000),
            )
            return True
        except Exception:
            return False

    # ── Exploitation-data.json polling ────────────────────────────────────────

    async def wait_for_branch_state(
        self, expected_text: str, timeout: float = 10.0
    ) -> bool:
        """Wait until the React Flow container contains expected_text (poll arrives).

        Used to wait for a branch state transition (e.g., '✓ Done') to appear
        after the mindmap's _pollBranches() fetch cycle.
        """
        try:
            await self._page.wait_for_function(
                f"""() => {{
                    const c = document.getElementById('exploit-tree-root');
                    return c && c.textContent.includes({expected_text!r});
                }}""",
                timeout=int(timeout * 1000),
            )
            return True
        except Exception:
            return False

    # ── Network interception helpers ──────────────────────────────────────────

    async def block_all_except_exploitation_data(self) -> None:
        """Block all network requests except to exploitation-data.json.

        Used by the Panel Data Source Invariant browser scenario to verify
        that the panel renders entirely from cached _branchMap data — no
        secondary server fetch inside panel rendering functions (Pattern 19).

        Call before navigating to the workspace page.
        """
        await self._page.route(
            "**/*",
            lambda route, req: (
                route.continue_()
                if "exploitation-data.json" in req.url
                else route.abort()
            ),
        )

    async def close(self) -> None:
        await self._page.close()
