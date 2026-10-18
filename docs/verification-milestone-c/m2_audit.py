"""Characterize goal synchronization without altering its production contract."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
import tempfile

from src.session.store import Store
from src.workflow.state import Candidate
from tests.integration.test_requested_goal_lifecycle import _direct_goal_agent


async def main():
    with tempfile.TemporaryDirectory(prefix='kagent-m2-audit-') as directory:
        root = Path(directory)
        agent, _ = _direct_goal_agent(root)
        agent._initialize_request_objective('Perform a whole-target assessment; test SQL injection', True)
        state = agent.workflow
        objective = state.objective
        goal = objective.requested_goals[0]
        agent.store = Store.new_with_id(root / 'sessions', 'offline-audit')

        def snapshot():
            return dict(workflow=deepcopy(state.to_dict()), revision=state.committed_revision)

        no_candidate = snapshot()
        agent._whole_target_state()
        no_candidate_unchanged = snapshot() == no_candidate
        candidate, _ = state.add_candidate(Candidate(
            candidate_class='sql-injection', target=agent.target.base_url(),
            endpoint='/search', method='GET', parameter='q', objective_id=objective.id))
        before = snapshot()
        await agent.save()
        saved_before = json.loads(agent.store.path.read_text())['workflow']
        status = agent._whole_target_state()
        after = snapshot()
        repeated = agent._whole_target_state()
        idempotent = snapshot() == after and status == repeated
        dirty = agent._workflow_saved_revision != state.committed_revision
        await agent._finish_tool_results()
        saved_after = json.loads(agent.store.path.read_text())['workflow']
        result = dict(
            no_candidate_read_unchanged=no_candidate_unchanged,
            candidate_status=state.candidates[candidate.id].status,
            before_goal=before['workflow']['objective']['requested_goals'][0],
            after_goal=after['workflow']['objective']['requested_goals'][0],
            changed_workflow_keys=[key for key in before['workflow']
                                   if before['workflow'][key] != after['workflow'][key]],
            revision_delta=after['revision'] - before['revision'],
            repeated_read_idempotent=idempotent,
            dirty_before_checkpoint=dirty,
            checkpoint_saved_goal=saved_after['objective']['requested_goals'][0],
            saved_before_matched=before['workflow'] == saved_before,
            saved_after_matched=after['workflow'] == saved_after,
            no_attempts_or_results=not state.attempts and not state.validation_results,
            final_goal_status=goal.status,
        )
        print(json.dumps(result, indent=2))
        # The committed historical result is immutable; a new run prints fresh data.


asyncio.run(main())
