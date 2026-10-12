import logging
import sys

def setup_logging():
    """
    Configures standard application logging.
    Structured output is formatted to support log aggregation (e.g., Promtail/Loki in later phases).
    """
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Specific logger for security & audit events
    audit_logger = logging.getLogger("tenantguard.audit")
    audit_logger.setLevel(logging.INFO)

    return audit_logger

audit_logger = setup_logging()
