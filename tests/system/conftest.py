"""Reuse scenario isolation, admitting only the fixture's exact socket address."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.local_lab import LocalLab
from tests.scenarios.conftest import _offline_scenario


@pytest.fixture
async def local_lab():
    lab = LocalLab()
    await lab.start()
    try:
        yield lab
    finally:
        await lab.close()


@pytest.fixture(autouse=True)
async def system_boundary(tmp_path, local_lab):
    guard = pytest.MonkeyPatch()
    try:
        with_guard = _offline_scenario(tmp_path, guard, allowed_address=local_lab.address,
                                      process_check=lambda args, kwargs: local_lab.process_check(args, kwargs),
                                      allowed_special_files=(Path("/dev/null"),))
        next(with_guard)
        await local_lab.ready()
        yield
        with pytest.raises(StopIteration):
            next(with_guard)
    finally:
        guard.undo()
