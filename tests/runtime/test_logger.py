from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path

import pytest

from src.logger import logger as kagent_logger
from src.llm.errors import classify_backend


@pytest.fixture(autouse=True)
def restore_logging():
    base = logging.getLogger(kagent_logger.BASE_LOGGER_NAME)
    handlers, level, disabled = list(base.handlers), base.level, base.disabled

    yield

    for handler in list(base.handlers):
        if handler not in handlers:
            base.removeHandler(handler)
            handler.close()
    base.handlers[:] = handlers
    base.level = level
    base.disabled = disabled


def test_module_loggers_never_escape_to_the_root_handlers():
    log = kagent_logger.get_logger("unit.test")

    assert log.name == "kagent.unit.test"
    assert logging.getLogger(kagent_logger.BASE_LOGGER_NAME).propagate is False


def test_module_loggers_write_into_the_kagent_log_file(tmp_path):
    target = tmp_path / "logs" / "kagent.log"
    kagent_logger.init(target)

    assert kagent_logger.init_error() is None

    kagent_logger.get_logger("unit.test").warning("something went wrong")
    logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0].flush()

    record = json.loads(target.read_text(encoding="utf-8").splitlines()[-1])
    assert record["message"] == "something went wrong"
    assert record["level"] == "warning"


def test_init_reports_why_file_logging_was_disabled(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")

    kagent_logger.init(blocker / "logs" / "kagent.log")

    assert isinstance(kagent_logger.init_error(), OSError)
    kagent_logger.get_logger("unit.test").warning("dropped silently")


def test_successful_reinitialization_recovers_after_failed_init(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    target = tmp_path / "kagent.log"

    kagent_logger.init(blocker / "kagent.log")
    kagent_logger.init(target)
    kagent_logger.info("logging recovered")
    logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0].flush()

    assert kagent_logger.init_error() is None
    assert "logging recovered" in target.read_text(encoding="utf-8")


def test_reinitialization_closes_replaced_handler_and_writes_once(tmp_path):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    kagent_logger.init(first)
    old_handler = logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0]
    assert isinstance(old_handler, logging.FileHandler)

    kagent_logger.init(second)
    kagent_logger.info("after reinitialization")
    logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0].flush()

    assert old_handler.stream is None
    assert len(second.read_text(encoding="utf-8").splitlines()) == 1


def test_json_formatter_serializes_runtime_extra_values(tmp_path):
    target = tmp_path / "kagent.log"
    path_value = Path("logs") / "nested"
    kagent_logger.init(target)

    kagent_logger.info("runtime value", {"path": path_value})
    logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0].flush()

    record = json.loads(target.read_text(encoding="utf-8").splitlines()[-1])
    assert record["path"] == str(path_value)


def _logged_records(path: Path) -> list[dict]:
    for handler in logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers:
        handler.flush()
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_redacts_provider_error_before_persistent_logging(tmp_path):
    path = tmp_path / "provider.log"
    kagent_logger.init(path)
    secret = "provider-marker-abcdefghijklmnopqrstuvwxyz"
    error = classify_backend(
        "fake-provider",
        None,
        500,
        json.dumps({"error": {"message": f"upstream rejected Bearer {secret}"}}),
    )

    kagent_logger.error("provider request failed", {"detail": error.detail})

    record = _logged_records(path)[-1]
    assert secret not in path.read_text(encoding="utf-8")
    assert "upstream rejected" in record["detail"]
    assert "[REDACTED" in record["detail"]


def test_redacts_tool_parse_error_and_nested_extra(tmp_path):
    path = tmp_path / "tool.log"
    kagent_logger.init(path)
    password = "short-parse-secret"
    cookie = "short-cookie-secret"
    api_key = "nested-api-key-marker-1234567890"

    kagent_logger.error(
        "agent: tool failed",
        {
            "err": f'could not parse arguments (raw: {{"password":"{password}"}})',
            "response": {
                "headers": {"Set-Cookie": cookie},
                "items": [{"api_key": api_key}],
                "sequence": ("ordinary-long-random-looking-value", {"Cookie": cookie}),
            },
        },
    )

    body = path.read_text(encoding="utf-8")
    record = _logged_records(path)[-1]
    assert all(secret not in body for secret in (password, cookie, api_key))
    assert "could not parse arguments" in record["err"]
    assert record["response"]["headers"]["Set-Cookie"] == "[REDACTED]"
    assert record["response"]["items"][0]["api_key"] == "[REDACTED]"
    assert record["response"]["sequence"] == [
        "ordinary-long-random-looking-value",
        {"Cookie": "[REDACTED]"},
    ]


def test_redacts_exception_text_and_exc_info(tmp_path):
    path = tmp_path / "exception.log"
    kagent_logger.init(path)
    secret = "exception-api-key-marker-1234567890"

    try:
        raise RuntimeError(f"provider failed api_key={secret}")
    except RuntimeError:
        kagent_logger.get_logger("unit.test").exception(
            "provider exception", extra={"context": {"token": secret}}
        )

    body = path.read_text(encoding="utf-8")
    record = _logged_records(path)[-1]
    assert secret not in body
    assert "RuntimeError" in record["exception"]
    assert "provider failed" in record["exception"]
    assert "Traceback" in record["exception"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_log_directory_file_and_rotated_files_have_private_modes(tmp_path):
    directory = tmp_path / "created-logs"
    target = directory / "kagent.log"
    kagent_logger.init(target)
    handler = logging.getLogger(kagent_logger.BASE_LOGGER_NAME).handlers[0]
    assert isinstance(handler, kagent_logger.SecureRotatingFileHandler)
    handler.maxBytes = 1

    kagent_logger.info("first line")
    kagent_logger.info("second line")
    handler.flush()

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    rotated = Path(f"{target}.1")
    assert rotated.exists()
    assert stat.S_IMODE(rotated.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_init_restricts_existing_log_and_rotated_files(tmp_path):
    target = tmp_path / "kagent.log"
    rotated = Path(f"{target}.1")
    target.write_text("old current log", encoding="utf-8")
    rotated.write_text("old rotated log", encoding="utf-8")
    target.chmod(0o644)
    rotated.chmod(0o644)

    kagent_logger.init(target)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(rotated.stat().st_mode) == 0o600
