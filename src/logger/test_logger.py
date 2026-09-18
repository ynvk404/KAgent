from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.logger import logger as kagent_logger


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
