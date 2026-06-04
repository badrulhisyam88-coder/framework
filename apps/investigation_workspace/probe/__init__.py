"""Phase 44 — passive probe + event stream.

Replaces the Phase 40-43 canned bootstrap script with a real HTTP probe
that emits events as it discovers things about the target. The bootstrap
runtime no longer claims findings exist; it executes a probe and surfaces
whatever the probe actually observes.

Deterministic — given the same response from the target, the same events
fire in the same order. No LLM, no scoring. Real evidence-driven.
"""
