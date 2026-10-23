"""Local, operator-invoked CWE review; never a model tool or Finding creator."""
from __future__ import annotations

import asyncio
from typing import Any

from src.findings.cwe_review import review_finding, brief
from src.permission.runtime.execution import policy_for
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.core.state import Append, TranscriptEntry
from src.ui.widgets.text_input_modal import TextInputRequest


def start_cwe_review(app: Any, args: list[str]) -> asyncio.Task | None:
    def notice(text: str, error: bool = False):
        app.dispatch(Append(entry=TranscriptEntry(kind='error' if error else 'system', text=text)))
    agent = app.agent
    task = getattr(app, '_skill_task', None)
    if agent.is_running() or (task is not None and not task.done()):
        notice('CWE review: finish or cancel the current operation first.', True)
        return None
    if len(args) != 1:
        ids = ', '.join(sorted(agent.workflow.persisted_findings)) or 'none'
        notice('Use /cwe <candidate_id> for an existing Finding. Persisted candidates: ' + ids)
        return None
    tool = agent.tools.get('confirm_finding')
    if not isinstance(tool, ConfirmFindingTool):
        notice('CWE review: persisted Finding store unavailable.', True)
        return None
    policy = policy_for(agent.prompter)
    def identity():
        return (id(agent.workflow), agent.target.base_url(), getattr(agent.target, 'revision', 0),
                getattr(agent.engagement_state, 'revision', 0), policy_for(agent.prompter))
    captured = identity()
    def guard():
        if identity() != captured or agent.is_running():
            raise ValueError('CWE review context changed; retry against the current Finding')
    async def prompt(title: str, question: str) -> str | None:
        guard()
        return await app.prompt_text(TextInputRequest(header=title, question=question,
            placeholder='Enter a response or cancel', resolve=lambda _: None,
            reject=lambda _: None, scrollable=True))
    async def run():
        try:
            notice(await review_finding(tool, args[0], policy, prompt, context_check=guard))
        except asyncio.CancelledError:
            raise
        except ValueError as exc:
            notice('CWE review: ' + brief(str(exc)), True)
        except Exception:
            notice('CWE review stopped; reload the persisted report to inspect its current classification.', True)
    app._skill_task = asyncio.create_task(run())
    return app._skill_task
