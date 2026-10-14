import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Try importing python-json-logger if available
try:
    from pythonjsonlogger import jsonlogger
    BaseJsonFormatter = jsonlogger.JsonFormatter
except ImportError:
    BaseJsonFormatter = logging.Formatter


class AuditJsonFormatter(logging.Formatter):
    """
    Structured JSON Formatter for security audit events.
    Emits single-line JSON objects tailored for ingestion by Promtail/Loki and LogQL querying.

    Mandatory baseline top-level keys:
    - timestamp (ISO 8601 UTC)
    - level (INFO / WARNING / ERROR)
    - logger ('tenantguard.audit')
    - event (high-level audit event name e.g. AUTH_LOGIN_SUCCESS)
    - message (summary description string)
    plus all domain/context fields passed at the top level (user_id, tenant_id, ip, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        event_name = (
            getattr(record, "audit_event", None)
            or getattr(record, "event", None)
            or "AUDIT"
        )
        msg_str = getattr(record, "audit_message", None) or record.getMessage()

        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": event_name,
            "message": msg_str,
        }

        # Include domain-specific audit fields at the top level
        audit_fields = getattr(record, "audit_fields", None)
        if isinstance(audit_fields, dict):
            for k, v in audit_fields.items():
                if k not in log_entry:
                    log_entry[k] = v
        else:
            # Fallback for extra kwargs passed via standard logger.log(..., extra={...})
            standard_attrs = {
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "id", "levelname", "levelno", "lineno", "module",
                "msecs", "message", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread",
                "threadName", "audit_event", "audit_fields", "audit_message", "event"
            }
            for k, v in record.__dict__.items():
                if k not in standard_attrs and not k.startswith("_"):
                    log_entry[k] = v

        return json.dumps(log_entry, default=str)


def setup_logging() -> logging.Logger:
    """
    Configures standard application logging.
    General logs (uvicorn, startup, database) use standard human-readable formatting.
    The 'tenantguard.audit' logger emits strictly single-line structured JSON.
    """
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Root logger for general application messages
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Dedicated logger for security & audit events
    logger = logging.getLogger("tenantguard.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Isolate audit stream from root human-readable formatter

    # Clear existing handlers to avoid duplicates on reloads
    logger.handlers.clear()

    json_handler = logging.StreamHandler(sys.stdout)
    json_handler.setFormatter(AuditJsonFormatter())
    logger.addHandler(json_handler)

    return logger


audit_logger = setup_logging()

# Default security severity mapping
WARNING_EVENTS = {
    "AUTH_LOGIN_FAILED",
    "AUTH_TOKEN_EXPIRED",
    "DOCUMENT_ACCESS_DENIED",
    "UPLOAD_REJECTED",
}


def log_audit(
    event: str,
    level: Optional[str] = None,
    message: Optional[str] = None,
    **fields: Any
) -> None:
    """
    Helper function to emit a structured security audit event.

    - event: High-level event identifier (e.g. AUTH_LOGIN_SUCCESS, DOCUMENT_ACCESS_DENIED).
    - level: Optional log level string ("INFO", "WARNING", "ERROR"). Defaults to WARNING
             for rejection/failure events, INFO otherwise.
    - message: Optional human-readable message. Defaults to '[<event>]'.
    - **fields: Context fields placed as top-level JSON keys (user_id, tenant_id, ip, etc.).
    """
    if "level" in fields and level is None:
        level = fields.pop("level")
    if "message" in fields and message is None:
        message = fields.pop("message")

    if level is None:
        level = "WARNING" if event in WARNING_EVENTS else "INFO"

    if message is None:
        message = f"[{event}]"

    log_level = getattr(logging, str(level).upper(), logging.INFO)

    audit_logger.log(
        log_level,
        message,
        extra={
            "audit_event": event,
            "audit_message": message,
            "audit_fields": fields,
        }
    )
