from __future__ import annotations

import json
import asyncio
import threading
from src.async_io import run_sync
from src.logger.writer import BackgroundWriter
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, cast

from src.paths import user_data_root
from src.redaction.redact import redact_payload

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LOG_GENERATIONS = 3
LOG_DIR_MODE = 0o700
LOG_FILE_MODE = 0o600

BASE_LOGGER_NAME = "kagent"


def _base_logger() -> logging.Logger:
    log = logging.getLogger(BASE_LOGGER_NAME)
    log.propagate = False
    if not log.handlers:
        log.addHandler(logging.NullHandler())
    return log


_current_logger: logging.Logger = _base_logger()
_init_error: Exception | None = None

# Attributes `logging` itself owns on a LogRecord: never emitted as JSON payload
# fields, and suffixed when a caller passes one as `extra`.
LOG_RECORD_FIELDS = frozenset(
    {
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
)


class JsonFormatter(logging.Formatter):
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
            if key not in LOG_RECORD_FIELDS:
                data[key] = value

        if record.exc_info:
            data["exception"] = self.formatException(
                record.exc_info,
            )

        return json.dumps(
            redact_payload(data),
            ensure_ascii=False,
            default=str,
        )


def _safe_extra(args: dict[str, Any] | None) -> dict[str, Any]:
    if not args:
        return {}

    return {
        (f"{key}_" if key in LOG_RECORD_FIELDS else key): value
        for key, value in args.items()
    }


def default_log_path() -> Path:
    return user_data_root() / "logs" / "kagent.log"


def _ensure_private_directory(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=LOG_DIR_MODE)
        except FileExistsError:
            continue
        directory.chmod(LOG_DIR_MODE)


def _restrict_existing_log_files(target: Path) -> None:
    for path in (target, *(Path(f"{target}.{i}") for i in range(1, MAX_LOG_GENERATIONS + 1))):
        if path.exists():
            os.chmod(path, LOG_FILE_MODE)


class SecureRotatingFileHandler(RotatingFileHandler):
    """Rotating file handler that creates every active log with mode 0600."""

    def __init__(self, *args, **kwargs):
        self._io_lock = threading.RLock()
        self.writer = BackgroundWriter(self._write_line, drop_record=lambda count: json.dumps({
            "level": "warning", "message": "log records dropped", "count": count}))
        super().__init__(*args, **kwargs)

    def emit(self, record):
        try:
            line = self.format(record)
            if self.writer.closed:
                self.writer.submit(line)
                return
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                if self.writer.thread is None:
                    self._write_line(line)
                else:
                    self.writer.submit(line)
                    self.writer.flush()
            else:
                self.writer.submit(line)
        except Exception as error:
            self.writer.last_error = type(error).__name__
            self.writer.failed_records += 1

    def _write_line(self, line: str) -> None:
        # The logging Handler lock belongs only to producers. A slow writer
        # must never hold it while the Textual thread emits another record.
        with self._io_lock:
            stream = self.stream if self.stream is not None else self._open()
            self.stream = cast(Any, stream)
            if self.maxBytes > 0:
                stream.seek(0, 2)
                if stream.tell() + len((line + "\n").encode("utf-8")) >= self.maxBytes:
                    self.doRollover()
                    stream = self.stream
                    if stream is None:
                        raise OSError("log rotation did not reopen the private stream")
            stream.write(line + "\n")
            stream.flush()

    def flush(self):
        self.writer.flush()
        with self._io_lock:
            if self.stream is not None:
                self.stream.flush()

    def close(self):
        self.writer.close()
        with self._io_lock:
            super().close()

    def _open(self):
        fd = os.open(
            self.baseFilename,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            LOG_FILE_MODE,
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, LOG_FILE_MODE)
            else:
                os.chmod(self.baseFilename, LOG_FILE_MODE)
            return os.fdopen(
                fd,
                self.mode,
                encoding=self.encoding,
                errors=self.errors,
            )
        except BaseException:
            os.close(fd)
            raise


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
        is_default_path = path is None
        target = Path(path) if path else default_log_path()

        _ensure_private_directory(target.parent)
        if is_default_path:
            target.parent.chmod(LOG_DIR_MODE)
        _restrict_existing_log_files(target)

        handler = SecureRotatingFileHandler(
            filename=target,
            maxBytes=MAX_LOG_BYTES,
            backupCount=MAX_LOG_GENERATIONS,
            encoding="utf-8",
        )

        handler.setFormatter(JsonFormatter())

        _close_handlers(log)
        log.addHandler(handler)
        log.setLevel(_log_level())
        log.disabled = False

        _init_error = None
        _current_logger = log

    except Exception as err:
        _close_handlers(log)
        log.addHandler(logging.NullHandler())
        log.disabled = True

        _init_error = err
        _current_logger = log


def _close_handlers(log: logging.Logger) -> None:
    for handler in list(log.handlers):
        log.removeHandler(handler)
        handler.close()


async def aclose() -> None:
    for handler in list(_current_logger.handlers):
        await run_sync(handler.close)


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
