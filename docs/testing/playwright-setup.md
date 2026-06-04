# Playwright Milestone Harness — Setup

Playwright runs at milestone closeout gates only (V2.2, V2.3, V2.4 closeout).
Never per-PR. See CLAUDE.md locked decision.

---

## Test environment setup

Playwright tests run inside the Docker container or in a Python environment
that has the project dependencies installed. They do NOT run in the bare
host Python environment (no fastapi/uvicorn/starlette).

### 1. Install Playwright Python package

Already included in the container dependencies. In a dev environment:

```
pip install playwright
```

### 2. Install Chromium browser binary

```
python -m playwright install chromium
```

### 3. Install Chromium system dependencies (Linux / WSL2)

If Chromium fails with missing shared libraries (`libnspr4.so`, `libnss3.so`):

```
python -m playwright install --with-deps chromium
```

On WSL2 without sudo, install the packages directly:

```
sudo apt-get install -y libnspr4 libnss3 libnssutil3 libasound2
```

### 4. Verify the browser launches

```
python -c "
import asyncio
from playwright.async_api import async_playwright
async def check():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        await page.set_content('<h1>ok</h1>')
        print(await page.text_content('h1'))
        await b.close()
asyncio.run(check())
"
```

Expected output: `ok`

---

## Running milestone tests

### Per-PR runs (DO NOT run milestone tests)

Standard per-PR invocation omits `tests/milestone/`:

```
pytest tests/conductor/ tests/investigation_workspace/ tests/scanner_orchestration/ tests/frontend/
```

Or equivalently, exclude by marker:

```
pytest -m "not milestone"
```

### Milestone closeout run

```
pytest tests/milestone/ -m milestone -v
```

This runs all Playwright scenarios for the current milestone gate.

### Graceful skip in bare environments

If Playwright or Chromium are unavailable, milestone tests skip automatically:

```
SKIPPED [1] tests/milestone/test_harness_sanity.py::test_harness_loads_admin_conductor_panel
  Reason: Playwright environment not available: Chromium launch failed: ...
```

No failures, no errors — the skip is silent and does not affect CI green/red status
for per-PR runs.

---

## Milestone schedule

| Gate | Scope |
|------|-------|
| V2.2 closeout | All engine lift surfaces; exploitation tab JS wiring; category filter clicks |
| V2.3 closeout | Graph wiring + handover verification; workspace data polling |
| V2.4 closeout | Suggestion layer retirement; legacy workspace route deprecation |

Scenarios for each gate are written in that gate's PR, not here.

---

## Files

```
tests/milestone/
  conftest.py             — browser_context fixture, live_server_url, skip guard
  pages/
    admin_page.py         — AdminConductorPage page object
    workspace_page.py     — WorkspacePage page object
  test_harness_sanity.py  — single sanity scenario (harness smoke only)
docs/testing/
  playwright-setup.md     — this file
```
