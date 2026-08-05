from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LOG_GENERATIONS = 3

_current_logger: logging.Logger = logging.getLogger("pentestagent-disabled")
_current_logger.disabled = True


class JsonFormatter(logging.Formatter):
    """JSON Lines formatter."""

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


# Các tên field chuẩn của logging.LogRecord — nếu `extra` chứa key trùng,
# stdlib logging sẽ raise KeyError khi tạo LogRecord. Đổi tên (thêm hậu tố
# "_") thay vì âm thầm bỏ qua, để không mất dữ liệu người gọi truyền vào.
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
        / ".pentestagent"
        / "logs"
        / "pentestagent.log"
    )


def _log_level() -> int:
    level = os.getenv(
        "PENTESTAGENT_LOG_LEVEL",
        "INFO",
    ).upper()

    return getattr(
        logging,
        level,
        logging.INFO,
    )


def init(path: str | Path | None = None) -> None:
    """
    Initialize logger.

    Phải được caller gọi tường minh (ví dụ ở entrypoint CLI) — module này
    KHÔNG tự init khi import, để giữ đúng nguyên tắc "no-op mặc định,
    không side-effect ghi file cho tới khi được yêu cầu rõ ràng".

    Nếu initialization lỗi, logger giữ nguyên trạng thái disabled.
    """

    global _current_logger

    try:
        target = Path(path) if path else default_log_path()

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger = logging.getLogger("pentestagent")
        logger.handlers.clear()

        handler = RotatingFileHandler(
            filename=target,
            maxBytes=MAX_LOG_BYTES,
            backupCount=MAX_LOG_GENERATIONS,
            encoding="utf-8",
        )

        handler.setFormatter(JsonFormatter())

        logger.addHandler(handler)
        logger.setLevel(_log_level())
        logger.propagate = False
        logger.disabled = False

        _current_logger = logger

    except Exception:
        disabled = logging.getLogger("pentestagent-disabled")
        disabled.handlers.clear()
        disabled.disabled = True
        _current_logger = disabled


def logger() -> logging.Logger:
    return _current_logger


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