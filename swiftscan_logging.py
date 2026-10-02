"""Logging setup for SwiftScan.

Two outputs, both size-rotated:
  * swiftscan_error.log  - human-readable warnings/errors (same file name as before)
  * swiftscan_audit.log  - one JSON object per line recording who scanned what:
        {"ts": "...", "level": "INFO", "event": "scan_started",
         "client_ip": "...", "target": "...", "consent": true, ...}

Set SWIFTSCAN_LOG_DIR to put both files somewhere other than the working
directory, and SWIFTSCAN_DEBUG=1 for debug-level error logging. If the log
directory is not writable we fall back to stderr instead of crashing.
"""
import json
import logging
import logging.handlers
import os
import time

_STANDARD_ATTRS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "fields"}
_CONFIGURED = False

AUDIT_LOGGER_NAME = "swiftscan.audit"


class JsonFormatter(logging.Formatter):
    """One JSON object per record; keyword fields passed via audit() are merged in."""

    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}) or {})
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=False)


def audit(event, **fields):
    """Write one structured audit record (always INFO)."""
    logging.getLogger(AUDIT_LOGGER_NAME).info(event, extra={"fields": fields})


def _file_handler(path, formatter, level):
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(formatter)
    handler.setLevel(level)
    return handler


def setup_logging(log_dir=None):
    """Configure the 'swiftscan' and 'swiftscan.audit' loggers. Safe to call repeatedly."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    log_dir = log_dir or os.environ.get("SWIFTSCAN_LOG_DIR") or os.getcwd()
    debug = bool(os.environ.get("SWIFTSCAN_DEBUG"))

    app_logger = logging.getLogger("swiftscan")
    app_logger.setLevel(logging.DEBUG if debug else logging.INFO)
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False  # audit records go only to the audit file

    text_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    try:
        os.makedirs(log_dir, exist_ok=True)
        app_logger.addHandler(_file_handler(os.path.join(log_dir, "swiftscan_error.log"), text_fmt,
                                            logging.DEBUG if debug else logging.WARNING))
        audit_logger.addHandler(_file_handler(os.path.join(log_dir, "swiftscan_audit.log"),
                                              JsonFormatter(), logging.INFO))
    except OSError as e:
        fallback = logging.StreamHandler()
        fallback.setFormatter(text_fmt)
        app_logger.addHandler(fallback)
        audit_logger.addHandler(fallback)
        app_logger.warning("Could not open log files in %s (%s); logging to stderr", log_dir, e)
