"""Top-level pytest configuration — registers custom markers.

Markers registered here are available across all test directories without
requiring pyproject.toml modification (which is a protected build file).
"""


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "milestone: milestone closeout gate test (requires Playwright + Chromium). "
        "Run with: pytest tests/milestone/ — skipped by default in per-PR runs.",
    )
