from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.app_config import settings
from backend.logging_config import setup_logging, logger
from backend.storage.database import Database

# Initialize structured logging
setup_logging(json_logs=False, log_level="INFO" if not settings.debug else "DEBUG")

# Initialize database
db = Database(settings.db_path)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing PRIV6GUARD backend service...")
    try:
        # Validate configuration files
        settings.load_lab_config()
        settings.load_detection_rules()
        logger.info("Configuration files loaded and validated successfully.")
    except Exception as e:
        logger.error(f"Configuration validation error: {e}")
        raise e

    # Initialize SQLite tables
    await db.init_db()
    logger.info(f"Database schema initialized at {settings.db_path}")

    yield

    logger.info("Shutting down PRIV6GUARD backend service...")

app = FastAPI(
    title="PRIV6GUARD API",
    description="Privacy-Aware IPv6 IoT Security Monitoring Prototype API",
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.
    Returns operational status and application version without disclosing
    internal filesystem paths, secrets, or environment variables.
    """
    is_lab_valid = False
    is_rules_valid = False
    try:
        settings.load_lab_config()
        is_lab_valid = True
    except Exception:
        pass

    try:
        settings.load_detection_rules()
        is_rules_valid = True
    except Exception:
        pass

    return {
        "status": "healthy",
        "app": "PRIV6GUARD",
        "version": settings.version,
        "mode": "LAB_SIMULATION",
        "config_loaded": is_lab_valid and is_rules_valid,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=settings.debug)
