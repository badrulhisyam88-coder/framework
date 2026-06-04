"""Seam tests: adapter input/output shape contracts.

Pattern: ADAPTER SHAPE MISMATCH (PR E-fix bug: nuclei v2 flag; PR F bug: ZAP spider count)
  Bug example 1 (nuclei): nuclei_adapter.py was written for v2 using -json flag.
    nuclei v3.3.5 removed -json. Subprocess exited code 2; adapter didn't check
    returncode; returned 0 findings as "success." Three compounding failures:
    no returncode check, wrong CLI flag, no integration test.
  Bug example 2 (ZAP spider): old adapter returned int count instead of URL list.
    Engine code expected a list to iterate; silently received 0 findings.

  Test assertion: adapter output shapes match what engines expect to consume.
  Adapters must check subprocess exit codes and return correct types.
"""
from __future__ import annotations

import ast


def _read_adapter(name: str) -> str:
    with open(f"apps/scanner_orchestration/adapters/{name}") as f:
        return f.read()


def test_nuclei_adapter_uses_v3_jsonl_flag():
    """nuclei v3 requires -jsonl-export, not -json.

    The -json flag was removed in v3.3.5. Using it exits with code 2.
    This test guards against regression to the v2 flag.
    """
    src = _read_adapter("nuclei_adapter.py")
    assert "-jsonl-export" in src, (
        "nuclei adapter does not use -jsonl-export flag. "
        "nuclei v3.3.5 removed -json; adapter must use -jsonl-export."
    )
    assert " -json" not in src.replace("-jsonl", ""), (
        "nuclei adapter still references -json flag (not -jsonl-export). "
        "This flag was removed in nuclei v3.3.5 and causes subprocess exit code 2."
    )


def test_nuclei_adapter_checks_returncode():
    """Subprocess adapters must check returncode != 0.

    Ignoring returncode means failed scans (exit 2) silently return 0 findings.
    This was the root cause of the nuclei v2-flag bug.
    """
    src = _read_adapter("nuclei_adapter.py")
    assert "returncode" in src, (
        "nuclei_adapter does not check subprocess returncode. "
        "A non-zero exit (e.g., bad flag, binary not found) would silently return 0 findings."
    )


def test_nmap_adapter_checks_returncode():
    """nmap adapter must also check returncode."""
    src = _read_adapter("nmap_adapter.py")
    assert "returncode" in src, (
        "nmap_adapter does not check subprocess returncode."
    )


def test_zap_adapter_spider_returns_url_list():
    """run_spider() must return a dict with a 'urls' key containing a list.

    The old adapter returned an integer count. Engine code iterates the result
    expecting a list; returning int means 0 findings silently.
    """
    src = _read_adapter("zap_adapter.py")
    # The fixed adapter returns {"urls": [...], "status": ..., "error": ...}
    assert '"urls"' in src or "'urls'" in src, (
        "zap_adapter run_spider does not return a dict with 'urls' key. "
        "Engine code expects a list of URLs, not an integer count."
    )
    # Verify it's not returning a bare integer (old bug)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run_spider":
            for child in ast.walk(node):
                # A return of a plain int literal would be the bug
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                    if isinstance(child.value.value, int):
                        raise AssertionError(
                            f"run_spider returns bare integer {child.value.value} — "
                            "must return dict with 'urls' list."
                        )
