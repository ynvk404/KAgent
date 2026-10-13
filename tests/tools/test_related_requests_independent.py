"""Independent QA: payload/principal fields cannot create request identities."""
from copy import deepcopy

import pytest

from tests.tools.test_related_request_associations import (
    candidate_for, declaration, dispatch,
)


@pytest.mark.parametrize("extra", ["body", "payload", "identity"])
async def test_unadmitted_observation_fields_are_rejected_without_dropping_them(dispatch, extra):
    state, tool, registry, prompter = dispatch
    candidate = await candidate_for(dispatch)
    args = {"action": "start_validation", "candidate_id": candidate.id,
            "related_requests": [declaration(**{extra: "fixture-a"}),
                                 declaration("trigger", **{extra: "fixture-b"})]}
    original = deepcopy(args)
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    result = await registry.execute("workflow", args, None, prompter)
    assert result.status == "error" and result.error_kind == "invalid_args"
    assert "related_requests needs at most 16 objects" in result
    # Invalid fields precede duplicate classification under the current contract.
    assert "DUPLICATE_REQUEST_ASSOCIATION" not in result
    assert args == original and state.to_dict() == before
    assert state.committed_revision == revision and tool.active_attempt is None
