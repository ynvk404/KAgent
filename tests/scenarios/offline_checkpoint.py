"""Install the scenario isolation guard on audited legacy responsibility tests.

Their fixture construction may create a sibling of the execution-policy root
(for example a fake outside-root secret). Both paths must remain inside this
pytest invocation's newly allocated scratch container. Stores, cwd and user
data still use each test's own tmp_path; only filesystem containment uses the
enclosing scratch container. The scenario group's default guard is unchanged.
"""
import pytest

from tests.scenarios.conftest import _offline_scenario


@pytest.fixture(autouse=True)
def offline_checkpoint(tmp_path, tmp_path_factory):
    guard = pytest.MonkeyPatch()
    try:
        yield from _offline_scenario(tmp_path, guard, allowed_root=tmp_path_factory.getbasetemp())
    finally:
        guard.undo()
