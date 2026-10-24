import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict

# Sensitive fields to mask if encountered
REDACT_KEYS = {"secret", "token", "password", "key", "authorization", "bearer"}

class SensitiveDataFilter(logging.Filter):
    """Filter that sanitizes sensitive tokens or credential fields from log records."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for key in REDACT_KEYS:
                if key in record.msg.lower() and "=" in record.msg:
                    # Generic masking heuristic
                    parts = record.msg.split(" ")
                    safe_parts = []
                    for part in parts:
                        if any(part.lower().startswith(f"{k}=") for k in REDACT_KEYS):
                            safe_parts.append(f"{part.split('=')[0]}=[REDACTED]")
                        else:
                            safe_parts.append(part)
                    record.msg = " ".join(safe_parts)
        return True

class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON without leaking sensitive state."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

def setup_logging(json_logs: bool = False, log_level: str = "INFO"):
    """Configure structured logging for PRIV6GUARD backend."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers
    while root_logger.handlers:
        root_logger.handlers.pop()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SensitiveDataFilter())

    if json_logs:
        handler.setFormatter(StructuredJsonFormatter())
    else:
        standard_format = "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
        handler.setFormatter(logging.Formatter(standard_format, datefmt="%Y-%m-%d %H:%M:%S"))

    root_logger.addHandler(handler)
    
    # Silence overly verbose third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    return root_logger

logger = logging.getLogger("priv6guard")
