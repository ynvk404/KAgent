"""Invocation ownership for asynchronous native workflow producers.

This token controls state attribution only; registry and network permission
checks remain authoritative for execution.
"""
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Any


def _objective_identity(objective):
    return tuple(getattr(objective, name, None) for name in ('id', 'mode', 'target_origin', 'candidate_id'))


@dataclass(frozen=True)
class WorkflowOwner:
    tool: Any
    state: Any
    generation: str | None
    objective: Any
    objective_identity: tuple
    target: Any
    target_revision: int
    origin: str
    engagement: Any
    scope_revision: int
    epoch: int
    policy: Any
    policy_revision: int | None
    session_id: str | None

    @classmethod
    def capture(cls, tool, prompter):
        from src.permission.runtime.execution import policy_for
        state = tool.workflow
        policy = policy_for(prompter)
        return cls(tool, state, state.generation if state is not None else None,
                   state.objective if state is not None else None,
                   _objective_identity(state.objective if state is not None else None),
                   tool.target, tool.target.revision, tool.target.base_url(),
                   tool.engagement, tool.engagement.revision,
                   tool.engagement.http_permissions.epoch, policy,
                   policy.revision if policy else None, policy.session_id if policy else None)

    def current(self):
        return (self.state is not None and self.tool.workflow is self.state
                and self.state.generation == self.generation
                and self.state.objective is self.objective
                and _objective_identity(self.objective) == self.objective_identity
                and self.tool.target is self.target
                and self.target.revision == self.target_revision
                and self.target.base_url() == self.origin
                and self.tool.engagement is self.engagement
                and self.engagement.revision == self.scope_revision
                and self.engagement.http_permissions.epoch == self.epoch
                and (self.policy is None or (
                    self.policy.revision == self.policy_revision
                    and self.policy.session_id == self.session_id)))


_owner: ContextVar[WorkflowOwner | None] = ContextVar('native_workflow_owner', default=None)


def invocation(function):
    @wraps(function)
    async def run(tool, args, signal, prompter):
        token = _owner.set(WorkflowOwner.capture(tool, prompter))
        try:
            return await function(tool, args, signal, prompter)
        finally:
            _owner.reset(token)
    return run


def current(tool):
    owner = _owner.get()
    return owner is not None and owner.tool is tool and owner.current()
