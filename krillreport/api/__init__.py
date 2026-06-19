"""Web API package. Exposes the FastAPI ``app`` and the :func:`create_app` factory."""

from __future__ import annotations

from .app import app, create_app

__all__ = ["app", "create_app"]
