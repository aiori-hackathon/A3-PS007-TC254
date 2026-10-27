"""
PRIV6GUARD Backend Application Entrypoint
Exposes the FastAPI instance from backend.main for ASGI servers and runners.
"""
from backend.main import app

__all__ = ["app"]
