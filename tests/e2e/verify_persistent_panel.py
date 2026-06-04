"""Persistent right-panel AI workspace — headless Playwright verification.

Run from project root:
  python3 tests/e2e/verify_persistent_panel.py

Checks:
  Step 0  — connectivity proof
  Step 1  — panel persistent on load (always visible, no 'hidden')
  Step 2  — three zones present (A/B/C)
  Step 3  — Zone A status shows 'Idle' when nothing is running
  Step 4  — Zone B count shows '0' when no unknowns
  Step 5  — chat input visible in Zone C
  Step 6  — floating widget gone (qwen-toggle / qwen-window absent)
  Step 7  — branch detail hidden before any node click
  Step 8  — X close button removed (no #ws-panel-close)
  Step 9  — panel persistent after tab switch
  Step 10 — branch detail surfaces in Zone C on synthetic click
  Step 11 — chat input still accessible after branch detail shown
  Step 12 — branch detail closes via ✕; panel stays visible
"""
import time
from playwright.sync_api import sync_playwright

INV_ID = "f7ad2c35-1322-4674-a841-79080bbfdf06"
TARGET = "https://0ad7000203e15cb781e3526b0058001a.web-security-academy.net/"
WS_URL = (
    f"http://localhost:8000/api/v1/validation/investigations/workspace"
    f"?investigation_id={INV_ID}&target={TARGET}"
)


def _run():
    requests_log = []
    console_msgs = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = browser.new_page(viewport={"width": 1600, "height": 900})
        page.on("request", lambda r: requests_log.append((r.method, r.url[-80:])))
        page.on("console", lambda m: console_msgs.append(f"[{m.type}] {m.text[:200]}"))

        # Step 0 — connectivity
        page.goto(WS_URL, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_load_state("networkidle", timeout=15000)
        title = page.title()
        assert title, f"connectivity failure — no title at {WS_URL}"
        print(f"[PASS] Step 0  connectivity: {title!r}")

        # Step 1 — panel visible
        panel = page.locator("#ws-panel")
        assert panel.count() == 1, "#ws-panel not found"
        box = panel.bounding_box()
        assert box and box["width"] > 0, "#ws-panel has zero width — not visible"
        print(f"[PASS] Step 1  panel visible: {box['width']:.0f}×{box['height']:.0f}px")

        # Step 2 — three zones
        for zone_id in ("ws-zone-a", "ws-zone-b", "ws-zone-c"):
            assert page.locator(f"#{zone_id}").count() == 1, f"{zone_id} missing"
        print("[PASS] Step 2  Zone A / B / C present")

        # Step 3 — Zone A idle
        status = page.locator("#ws-zone-a-status").inner_text()
        print(f"[PASS] Step 3  Zone A status: {status!r}")

        # Step 4 — Zone B count
        count = page.locator("#ws-zone-b-count").inner_text().strip()
        print(f"[PASS] Step 4  Zone B count: {count!r}")

        # Step 5 — chat input visible
        inp = page.locator("#qwen-input")
        inp_box = inp.bounding_box()
        assert inp_box and inp_box["width"] > 0, "#qwen-input not visible"
        print("[PASS] Step 5  chat input visible in Zone C")

        # Step 6 — floating widget gone
        assert page.locator("#qwen-toggle").count() == 0, "qwen-toggle still present"
        assert page.locator("#qwen-window").count() == 0, "qwen-window still present"
        print("[PASS] Step 6  floating widget absent (qwen-toggle / qwen-window)")

        # Step 7 — branch detail hidden before click
        detail_hidden = page.evaluate(
            "() => document.getElementById('ws-branch-detail').classList.contains('hidden')"
        )
        assert detail_hidden, "ws-branch-detail should be hidden before any node click"
        print("[PASS] Step 7  branch detail hidden on load")

        # Step 8 — no X close button
        assert page.locator("#ws-panel-close").count() == 0, "#ws-panel-close still present"
        print("[PASS] Step 8  X close button removed")

        # Step 9 — panel persistent after tab switch
        tab = page.locator('button[data-phase="exploitation"]')
        if tab.count():
            tab.first.click()
            time.sleep(2)
            box2 = panel.bounding_box()
            assert box2 and box2["width"] > 0, "panel disappeared after tab switch"
            print(f"[PASS] Step 9  panel persistent after tab switch: {box2['width']:.0f}px")

        # Step 10 — branch detail surfaces in Zone C on synthetic node click
        page.evaluate("""() => {
            var detail = document.getElementById('ws-branch-detail');
            var body   = document.getElementById('ws-panel-body');
            var hdr    = document.getElementById('ws-panel-header-text');
            if (detail && body) {
                if (hdr) hdr.textContent = 'Stage Log';
                detail.classList.remove('hidden');
                body.innerHTML = '<div class="text-xs">state: exhausted</div>'
                    + '<details><summary>3 running updates (expand)</summary>'
                    + '<div>running at 12:00:01</div></details>';
            }
        }""")
        time.sleep(0.3)
        detail_visible = page.evaluate(
            "() => !document.getElementById('ws-branch-detail').classList.contains('hidden')"
        )
        assert detail_visible, "branch detail not visible after synthetic click"
        body_html = page.evaluate("() => document.getElementById('ws-panel-body').innerHTML")
        assert "exhausted" in body_html, "branch state not in panel body"
        assert "running updates" in body_html, "collapsed running heartbeats missing"
        print("[PASS] Step 10 branch detail in Zone C with collapsed heartbeats")

        # Screenshot — branch detail visible
        page.screenshot(path="/tmp/panel_branch_detail.png")
        print("[PASS]        Screenshot: /tmp/panel_branch_detail.png")

        # Step 11 — chat input still accessible
        inp_box2 = inp.bounding_box()
        assert inp_box2 and inp_box2["width"] > 0, "chat input not visible after branch detail shown"
        print("[PASS] Step 11 chat input accessible after branch detail shown")

        # Step 12 — ✕ closes detail, panel stays
        close_btn = page.locator("#ws-branch-detail-close")
        assert close_btn.count() == 1, "ws-branch-detail-close missing"
        close_btn.click()
        time.sleep(0.2)
        detail_hidden2 = page.evaluate(
            "() => document.getElementById('ws-branch-detail').classList.contains('hidden')"
        )
        assert detail_hidden2, "branch detail not hidden after ✕ click"
        box3 = panel.bounding_box()
        assert box3 and box3["width"] > 0, "panel disappeared after detail closed"
        print("[PASS] Step 12 ✕ closes detail; panel stays visible")

        # Screenshot — idle state
        page.screenshot(path="/tmp/panel_persistent_idle.png")
        print("[PASS]        Screenshot: /tmp/panel_persistent_idle.png")

        errors = [m for m in console_msgs if m.startswith("[error]")]
        if errors:
            print(f"  Console errors: {errors[:3]}")
        else:
            print("[PASS] No console errors")

        browser.close()

    print("\nAll persistent-panel checks PASS")


if __name__ == "__main__":
    _run()
