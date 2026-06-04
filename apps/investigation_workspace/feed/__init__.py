"""Guided Investigation Feed — chronological aggregation of investigation events.

The feed is the primary investigation experience: findings interpreted into
investigation language, inline guided actions, CTF opportunities, learning
updates, and evidence captures — all in one chronological stream.

This module aggregates reads from multiple bounded contexts. It does not
own state, mutate data, or perform execution.
"""
