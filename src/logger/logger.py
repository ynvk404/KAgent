from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LOG_GENERATIONS = 3

BASE_LOGGER_NAME = "kagent"


def _base_logger() -> logging.Logger:
    log = logging.getLogger(BASE_LOGGER_NAME)
    log.propagate = False
    if not log.handlers:
        log.addHandler(logging.NullHandler())
    return log


_current_logger: logging.Logger = _base_logger()
_init_error: Exception | None = None


class JsonFormatter(logging.Formatter):
    _STANDARD_FIELDS = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "asctime",
    }

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": self.formatTime(
                record,
                "%Y-%m-%dT%H:%M:%S%z",
            ),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
            "pid": record.process,
        }

        for key, value in record.__dict__.items():
            if key not in self._STANDARD_FIELDS:
                data[key] = value

        if record.exc_info:
            data["exception"] = self.formatException(
                record.exc_info,
            )

        return json.dumps(
            data,
            ensure_ascii=False,
        )

_RESERVED_EXTRA_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "asctime",
}


def _safe_extra(args: dict[str, Any] | None) -> dict[str, Any]:
    if not args:
        return {}

    return {
        (f"{key}_" if key in _RESERVED_EXTRA_KEYS else key): value
        for key, value in args.items()
    }


def default_log_path() -> Path:
    return (
        Path.home()
        / ".kagent"
        / "logs"
        / "kagent.log"
    )


def _log_level() -> int:
    level = os.getenv(
        "KAgent_LOG_LEVEL",
        "INFO",
    ).upper()

    return getattr(
        logging,
        level,
        logging.INFO,
    )


def init(path: str | Path | None = None) -> None:
    global _current_logger, _init_error

    log = _base_logger()

    try:
        target = Path(path) if path else default_log_path()

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        handler = RotatingFileHandler(
            filename=target,
            maxBytes=MAX_LOG_BYTES,
            backupCount=MAX_LOG_GENERATIONS,
            encoding="utf-8",
        )

        handler.setFormatter(JsonFormatter())

        log.handlers.clear()
        log.addHandler(handler)
        log.setLevel(_log_level())
        log.disabled = False

        _init_error = None
        _current_logger = log

    except Exception as err:
        log.handlers.clear()
        log.addHandler(logging.NullHandler())
        log.disabled = True

        _init_error = err
        _current_logger = log


def init_error() -> Exception | None:
    """The failure that disabled file logging during the last init(), if any."""
    return _init_error


def logger() -> logging.Logger:
    return _current_logger


def get_logger(name: str) -> logging.Logger:
    """A namespaced logger routed into the KAgent log file.

    Modules use this instead of logging.getLogger() so their records never
    escape to stderr and corrupt the TUI when logging has not been set up.
    """
    _base_logger()
    return logging.getLogger(f"{BASE_LOGGER_NAME}.{name}")


def info(
    msg: str,
    args: dict[str, Any] | None = None,
) -> None:
    _current_logger.info(
        msg,
        extra=_safe_extra(args),
    )


def warn(
    msg: str,
    args: dict[str, Any] | None = None,
) -> None:
    _current_logger.warning(
        msg,
        extra=_safe_extra(args),
    )


def error(
    msg: str,
    args: dict[str, Any] | None = None,
) -> None:
    _current_logger.error(
        msg,
        extra=_safe_extra(args),
    )


def debug(
    msg: str,
    args: dict[str, Any] | None = None,
) -> None:
    _current_logger.debug(
        msg,
        extra=_safe_extra(args),
    )