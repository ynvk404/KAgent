"""Slash commands only select local observations; never run testing work."""
import asyncio
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from src.ui.commands.slash_handler import build_help_text, handle_slash
from src.ui.core.app import KAgent
from tests.helpers.burp_selection import ORIGIN, ingest, make_runtime, notice


def slash(runtime, command):
    assert handle_slash(cast(KAgent, runtime.app), command)


@pytest.fixture
def runtime(tmp_path):
    return make_runtime(tmp_path)


@pytest.mark.parametrize('count', [0, 1, 10, 50, 61])
def test_all_and_list_limits_count_only_readable_matching_records(runtime, count):
    ids = [ingest(runtime, str(i))['id'] for i in range(count)]
    runtime.agent.add_scope_origin('http://secondary.test')
    for i in range(65):
        ingest(runtime, f'chrome-{i}', kind='fetch')
        ingest(runtime, f'secondary-{i}', origin='http://secondary.test')
        ingest(runtime, f'foreign-{i}', origin='http://foreign.test')
    slash(runtime, '/burp list')
    assert f'Showing {min(20, count)}/{count} requests' in notice(runtime)
    assert 'secondary-' not in notice(runtime) and 'chrome-' not in notice(runtime)
    slash(runtime, '/burp all')
    assert f'Selected {min(50, count)}/{count} requests' in notice(runtime)
    selected = runtime.agent.pending_capture_selection
    if count:
        assert selected is not None
        assert [row.retrieval_id for row in selected.requests] == list(reversed(ids))[:50]
    else:
        assert selected is None
        assert 'No matching Burp requests' in notice(runtime)
    if count > 50:
        assert '50 most recent' in notice(runtime)
    assert not runtime.client.requests and not runtime.workflow.candidates and not runtime.operator.requests
    assert runtime.policy.used == 0 and not runtime.policy._receipts


def test_latest_specific_and_cancel_keep_store(runtime):
    first = ingest(runtime, 'first')['id']
    latest = ingest(runtime, 'latest')['id']
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and selected.requests[0].retrieval_id == latest
    slash(runtime, f'/burp use {first}')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and selected.requests[0].retrieval_id == first
    slash(runtime, '/burp use cancel')
    assert runtime.agent.pending_capture_selection is None
    assert len(runtime.capture.requests) == 2


@pytest.mark.parametrize('command', ['/burp use missing', '/burp all extra', '/burp use one two'])
def test_failed_replacement_clears_old_pending(runtime, command):
    ingest(runtime)
    slash(runtime, '/burp use')
    slash(runtime, command)
    assert runtime.agent.pending_capture_selection is None
    assert 'selection cleared' in notice(runtime)


@pytest.mark.parametrize('command', ['/burp use', '/burp all', '/burp use cancel', '/burp use other'])
def test_busy_refuses_selection_changes(runtime, command):
    ingest(runtime)
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    runtime.agent.running = True
    slash(runtime, command)
    assert 'already running' in notice(runtime)
    assert runtime.agent.pending_capture_selection is selected
    slash(runtime, '/burp list')
    assert 'Showing 1/1' in notice(runtime)
    assert runtime.agent.pending_capture_selection is selected


def test_display_commands_preserve_selection_and_help_is_precise(runtime):
    ingest(runtime)
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    slash(runtime, '/burp list')
    slash(runtime, '/help')
    assert runtime.agent.pending_capture_selection is selected
    text = build_help_text(runtime.agent, runtime.app.read_config)
    assert 'at most 50 most recent requests' in text
    assert 'use [id|cancel]' in text


def test_requires_active_target_and_refuses_policy_deny(runtime):
    ingest(runtime)
    runtime.agent.apply_target_clear()
    slash(runtime, '/burp use')
    assert '/target <url>' in notice(runtime)
    assert runtime.agent.pending_capture_selection is None
    runtime.agent.apply_target_base_url(ORIGIN)
    runtime.engagement.http_permissions.deny_session()
    slash(runtime, '/burp list')
    assert 'revoked' in notice(runtime)
    assert 'burp:one' not in notice(runtime)


@pytest.mark.parametrize('tool', ['*', 'browser_capture_get', 'browser_capture_requests'])
def test_revoked_capture_tools_block_selection(runtime, tool):
    ingest(runtime)
    runtime.policy.revoke(tool)
    slash(runtime, '/burp use')
    assert 'revoked' in notice(runtime)
    assert runtime.agent.pending_capture_selection is None


@pytest.mark.parametrize('origin', ['http://127.0.0.1:3001', 'https://127.0.0.1:3000',
                                   'http://127.0.0.1.evil.test:3000', 'http://secondary.test'])
def test_specific_id_cannot_select_wrong_exact_origin(runtime, origin):
    runtime.agent.add_scope_origin(origin)
    row = ingest(runtime, 'foreign', origin=origin)
    slash(runtime, f"/burp use {row['id']}")
    assert runtime.agent.pending_capture_selection is None
    assert 'Selected 0/0 requests' in notice(runtime)


@pytest.mark.parametrize('target, origin', [('https://lab.test', 'https://LAB.TEST.:443'),
                                          ('http://lab.test:80', 'http://LAB.TEST')])
def test_default_ports_are_equivalent(runtime, target, origin):
    runtime.agent.apply_target_base_url(target)
    row = ingest(runtime, origin=origin)
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and selected.requests[0].retrieval_id == row['id']


def test_redacted_display_and_snapshot_never_copy_raw_request(runtime):
    ingest(runtime, path='/search?token=query-secret&q=header-secret',
           requestHeaders=[{'name': 'Authorization', 'value': 'Bearer header-secret'},
                           {'name': 'Cookie', 'value': 'sid=cookie-secret'}],
           rawRequestB64='cmF3LXNlY3JldA==', requestBody='password=body-secret')
    slash(runtime, '/burp list')
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None
    data = notice(runtime) + selected.observation()
    for secret in ('query-secret', 'header-secret', 'cookie-secret', 'body-secret', 'cmF3LXNlY3JldA=='):
        assert secret not in data
    assert 'request_headers' not in data and 'request_body' not in data


@pytest.mark.asyncio
async def test_reset_invalidates_synchronously_but_retains_capture(runtime):
    ingest(runtime)
    slash(runtime, '/burp use')
    slash(runtime, '/reset')
    assert runtime.agent.pending_capture_selection is None
    await asyncio.sleep(0)
    assert len(runtime.capture.requests) == 1


@pytest.mark.asyncio
async def test_existing_bridge_subcommands_still_work(runtime):
    state = SimpleNamespace(url='http://localhost:9876', port=9876, token='bridge-fixture')
    runtime.app.start_burp_bridge = AsyncMock(return_value=SimpleNamespace(status='started', state=state))
    runtime.app.close_burp_bridge = AsyncMock(return_value=SimpleNamespace(status='stopped', old_port=9876))
    runtime.app.burp_bridge_status = AsyncMock(return_value=SimpleNamespace(status='running', state=state))
    for command in ('/burp', '/burp 9876', '/burp status', '/burp stop'):
        slash(runtime, command)
        await asyncio.sleep(0)
    assert runtime.app.start_burp_bridge.call_args_list[0].args == (None,)
    assert runtime.app.start_burp_bridge.call_args_list[1].args == (9876,)
    runtime.app.burp_bridge_status.assert_awaited_once()
    runtime.app.close_burp_bridge.assert_awaited_once()
    slash(runtime, '/burp nonsense')
    assert 'usage: /burp' in notice(runtime)


def test_policy_filter_precedes_limit_and_denominator(runtime, monkeypatch):
    from src.permission.runtime.execution import ExecutionBlocked
    original = runtime.policy.require_network
    def readable(url, **kwargs):
        original(url, **kwargs)
        if '/denied' in url:
            raise ExecutionBlocked('fixture policy denies this observation')
    monkeypatch.setattr(runtime.policy, 'require_network', readable)
    ids = [ingest(runtime, f'allowed-{i}')['id'] for i in range(10)]
    for i in range(60):
        ingest(runtime, f'denied-{i}', path='/denied')
    slash(runtime, '/burp list')
    assert 'Showing 10/10 requests' in notice(runtime)
    slash(runtime, '/burp all')
    assert 'Selected 10/10 requests' in notice(runtime)
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and [row.retrieval_id for row in selected.requests] == list(reversed(ids))


@pytest.mark.asyncio
async def test_each_of_fifty_selected_ids_is_available_through_native_registry(runtime):
    for i in range(55):
        ingest(runtime, str(i))
    slash(runtime, '/burp all')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and len(selected.requests) == 50
    import json
    for row in selected.requests:
        data = json.loads(await runtime.registry.execute('browser_capture_get',
                          {'id': row.retrieval_id, 'baseline_request_ref': row.baseline_request_ref},
                          None, runtime.prompter))
        assert data['id'] == row.retrieval_id and data['baseline_request_ref'] == row.baseline_request_ref
    assert len(runtime.workflow.candidates) == 0 and runtime.policy.used == 50
    assert runtime.agent.pending_capture_selection is selected


def test_counts_records_not_number_of_ingest_events(runtime):
    for _ in range(100):
        ingest(runtime, 'same', status=200)
    slash(runtime, '/burp list')
    assert 'Showing 1/1 requests' in notice(runtime)
    slash(runtime, '/burp all')
    assert 'Selected 1/1 requests' in notice(runtime)


def test_selection_url_removes_entire_userinfo_and_preserves_runtime_baseline(runtime):
    row = ingest(runtime, origin='http://fixture-user:fixture-password@127.0.0.1:3000')
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None
    data = selected.observation() + notice(runtime)
    assert 'fixture-user' not in data and 'fixture-password' not in data
    baseline = runtime.capture.resolve_baseline(row['baseline_request_ref'])
    assert baseline is not None and 'fixture-user:fixture-password@' in baseline.url


def test_selection_redacts_url_echo_of_known_response_cookie(runtime):
    ingest(runtime, path='/search?q=fixture-session-secret',
           responseHeaders=[{'name': 'Set-Cookie', 'value': 'sid=fixture-session-secret'}])
    slash(runtime, '/burp list')
    assert 'fixture-session-secret' not in notice(runtime)
    slash(runtime, '/burp use')
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and 'fixture-session-secret' not in selected.observation()


@pytest.mark.parametrize('seed', ['burp-' + 'a' * 16, 'b' * 32, 'c' * 40, 'd' * 64])
def test_adapter_and_opaque_hash_retrieval_ids_remain_exact(runtime, seed):
    row = ingest(runtime, seed)
    slash(runtime, '/burp use ' + row['id'])
    selected = runtime.agent.pending_capture_selection
    assert selected is not None and selected.requests[0].retrieval_id == row['id']
    assert row['id'] in selected.observation()
