"""Offline calls through the production controller; no model or target I/O."""
import json

from src.llm.core.types import ToolCall, FunctionCall
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import make_runtime, ingest, ORIGIN


async def execute(runtime, name, args, *, success=True):
    agent = runtime.agent
    call = ToolCall('discovery-call', FunctionCall(name, json.dumps(args)))
    parsed = agent.parse_tool_call(call)
    agent._tool_call_event(call, parsed)
    output = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    agent.record_tool_result(call, parsed, output, lambda _: None, [])
    if success:
        assert output.status in {'success', 'observation'}, output.result
    return output


async def captured(tmp_path, body='<form method="post" action="submit"><input name="q"></form>'):
    runtime = make_runtime(tmp_path)
    runtime.workflow.objective = WorkflowObjective('discovery', 'whole_target', ORIGIN)
    row = ingest(runtime, path='/app/document.html', respBody=body, responseComplete=True, status=200)
    await execute(runtime, 'browser_capture_get', {'id': row['id']})
    return runtime, next(iter(runtime.workflow.discovery_sources.values()))


def attribution(source, location='form[method=post] input[name=q]'):
    return {'discovery_source_id': source.id, 'retained_ref': source.retained_ref,
            'retained_hash': source.retained_hash, 'document_location': location}
