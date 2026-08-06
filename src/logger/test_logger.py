from __future__ import annotations

import json
import logging

import pytest

from src.logger import logger as kagent_logger


@pytest.fixture(autouse=True)
def restore_logging():
    base = logging.getLogger(kagent_logger.BASE_LOGGER_NAME)
    handlers, level, disabled = list(base.handlers), base.level, base.disabled

    yield

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
