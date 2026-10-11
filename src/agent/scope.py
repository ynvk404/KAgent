"""Transient event ownership; scope fingerprints never confer authority."""
from __future__ import annotations

import hashlib
from typing import Any

from src.permission.runtime.execution import policy_for
from src.workflow.state import candidate_origin


def runtime_scope(agent: Any) -> str:
    """Read the canonical scope without synchronizing or mutating permissions."""
    engagement = getattr(agent, 'engagement_state', None)
    policy = policy_for(getattr(agent, 'prompter', None))
    objective = getattr(getattr(agent, 'workflow', None), 'objective', None)
    return hashlib.sha256(str((candidate_origin(agent.target.base_url()),
        getattr(agent.target, 'revision', None), getattr(engagement, 'revision', None),
        getattr(getattr(engagement, 'http_permissions', None), 'epoch', None),
        getattr(policy, 'session_id', None), objective.id if objective else None)).encode()).hexdigest()
