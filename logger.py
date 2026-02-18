import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict


def new_correlation_id() -> str:
    return str(uuid.uuid4())


_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text",
    "filename", "funcName", "levelname", "levelno", "lineno",
    "module", "msecs", "message", "msg", "name", "pathname",
    "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName",
    "taskName",  # <-- add this
}



def get_logger(name: str = "api_client") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload: Dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "event": record.getMessage(),
            }

            for k, v in record.__dict__.items():
                if k.startswith("_") or k in _RESERVED or k in payload:
                    continue
                payload[k] = v

            return json.dumps(payload, ensure_ascii=False)

    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger
