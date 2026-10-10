"""Explicit operator command; never exposed as a promotion tool to the model."""
from __future__ import annotations

from typing import Any

from src.findings.store import ClassificationCommittedError
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.core.state import Append, TranscriptEntry
from src.ui.widgets.text_input_modal import TextInputRequest


async def enrich_cwe(app: Any, rest: list[str]) -> None:
    try:
        if len(rest) != 1:
            raise ValueError('usage: /enrich-cwe <candidate-id>')
        # Optional component imports must stay inside the command's error
        # boundary: older editable installs may only expose the src package.
        try:
            from src.findings.cwe_enrichment import Enrichment, plain_data
        except ModuleNotFoundError as exc:
            if exc.name in {'components', 'components.cwe_mcp', 'components.cwe_mcp.contract'}:
                raise ValueError(
                    'CWE component is unavailable in this Python environment. '
                    'From the repository root, reinstall KAgent using the Python '
                    'environment that runs it: python -m pip install --no-deps -e . '
                    'Then restart KAgent.'
                ) from None
            raise
        finding_tool = app.agent.tools.get('confirm_finding')
        if type(finding_tool) is not ConfirmFindingTool:
            raise ValueError('persisted finding store unavailable')
        controller = Enrichment(app.agent, finding_tool.store, rest[0])

        async def choose(candidates):
            detail = ('Search ranking is a lexical score, not confidence or proof. '
                      'Select a numbered candidate for mechanism review, or 0 to abstain. '
                      'PageUp/PageDown scroll source metadata.\n\n')
            detail += '\n\n'.join(f'{i}. Source data:\n{plain_data(c.model_dump())}'
                                   for i, c in enumerate(candidates, 1))
            value = await app.prompt_text(TextInputRequest(header='CWE classification review',
                question=detail, placeholder=f'0–{len(candidates)}', resolve=lambda _: None,
                reject=lambda _: None, scrollable=True))
            if value.strip() == '0':
                return None
            if value.strip() not in {str(i) for i in range(1, len(candidates) + 1)}:
                raise ValueError('select a displayed candidate number or 0')
            return int(value.strip())

        def publish(finding, path):
            # Notifications always use the committed report snapshot.
            finding_tool.notifier(finding, path)

        result = await controller.run(choose, publish)
        try:
            await finding_tool.write_summary(rest[0])
        except Exception:
            result += (' Compact report refresh failed; canonical classification remains persisted. '
                       'Retry /enrich-cwe with the same candidate ID to refresh the report.')
        app.dispatch(Append(entry=TranscriptEntry(kind='system', text=result)))
    except Exception as exc:
        # Source/model payloads and sensitive filesystem errors never become UI
        # exception strings. The finding remains valid on enrichment failure.
        message = str(exc) if type(exc) is ValueError or isinstance(exc, ClassificationCommittedError) else type(exc).__name__
        app.dispatch(Append(entry=TranscriptEntry(kind='error', text=f'CWE enrichment: {message}')))
