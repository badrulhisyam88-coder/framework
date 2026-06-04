"""Phase 50 — Investigation finding categories.

Findings are grouped into semantic categories at the topology layer so the
graph reads as an investigation map (SQL Injection, Cross-Site Scripting,
Security Misconfiguration, …) rather than as a flat list of observations.

The mapping lives in catalog.py as a static dict. Categories are a UI
concept — they're synthesized at serialization time, not stored on
findings. Adding a new finding_type means adding one row to the catalog.
"""
