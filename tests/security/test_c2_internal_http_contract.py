"""Internal HTTP callers obey the same strict input contract as dispatch."""
import pytest

from tests.security.test_execution_policy import runtime  # fixture
from tests.security.test_generic_validation import setup


async def test_generic_anonymous_baseline_omits_optional_identity(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    http = env[0].get('http')
    prepare = http.prepare
    calls = []

    def checked(args):
        calls.append(dict(args))
        assert 'auth_context_ref' not in args
        return prepare(args)

    monkeypatch.setattr(http, 'prepare', checked)
    request = env[2].generic_validation.baseline(http, env[5])
    assert calls and request.method == env[5].method
    assert 'authorization' not in request.headers and 'cookie' not in request.headers
    # External null values remain invalid; fixing a trusted caller grants no
    # new wire shape and cannot import an unrelated identity.
    with pytest.raises(ValueError, match='auth_context_ref must be a string'):
        prepare({'url': env[5].endpoint, 'auth_context_ref': None})
