"""Generators: independent processes, one per derived artifact.

Each generator reads only Registry + Discovery Index and produces a single,
deterministic, disposable artifact. Output carries zero authority — if it
disagrees with Registry, Registry wins and the disagreement is drift to fix.
"""
