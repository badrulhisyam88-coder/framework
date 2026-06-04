"""ASGI entrypoint for the AI Factory Core backend."""

from core.api.app import create_app

app = create_app()
