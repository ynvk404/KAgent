"""Phase B: exercise real admission/receipt pipeline, never scanner processes."""
from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import httpx
import pytest

from src.engagement.state import EngagementState, OutOfScopeError, parse_tcp_ports, format_tcp_ports
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import AlwaysAllow, Decision, Prompter, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy, invocation_digest
from src.permission.runtime.invocations import review_turn
from src.target.target import Target
from src.tools.common.capabilities import CapabilityInventory
from src.tools.common.registry import InvalidToolArguments, Registry
from src.tools.execution.scanners import ScannerBinding
from src.tools.execution.shell import ShellTool, BashTool
from src.tools.http.http_tool import HTTPTool

ORIGIN = 'http://127.0.0.1:8080'
FFUF = {'scanner': 'ffuf', 'url': ORIGIN + '/FUZZ', 'wordlist_id': 'web-common'}
NMAP = {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '8080'}


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    install = tmp_path / 'trusted-install'
    install.mkdir()
    binaries = {}
    for name in ('nmap', 'ffuf'):
        path = install / name
        # Real ELF bytes used only as file identity fixtures. Never executed.
        shutil.copyfile('/bin/true', path)
        path.chmod(0o755)
        binaries[name] = str(path)
    state = EngagementState()
    state.add_origin(ORIGIN)
    target = Target(ORIGIN)
    state.http_permissions.bind_target(lambda: target.revision)
    policy = ExecutionPolicy(state, root)
    caps = CapabilityInventory(which=lambda name: binaries.get(name))
    tool = ShellTool(scanner_binding=ScannerBinding(policy, target, caps))
    operator = SimpleNamespace(ask=AsyncMock(return_value=Decision.ALLOW_ONCE))
    prompter = YoloPrompter(cast(Prompter, operator), False)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    forbidden_spawn = AsyncMock(side_effect=AssertionError('Phase B must not spawn any process'))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden_spawn)
    monkeypatch.setattr('src.tools.execution.shell.run_with_capture', forbidden_spawn)
    # Only the former terminal stub is replaced. This fixture continues to
    # exercise real preparation/review/dispatch/start and forbids every spawn.
    async def fake_executor(*_args):
        raise ExecutionBlocked('blocked: host-scanner-execution-unavailable (admission fixture executor)')
    assert tool.scanner_binding is not None
    monkeypatch.setattr(tool.scanner_binding.runtime, 'run', fake_executor)
    yield SimpleNamespace(root=root, state=state, target=target, policy=policy,
        tool=tool, caps=caps, binaries=binaries, operator=operator,
        prompter=prompter, registry=registry, spawn=forbidden_spawn)
    assert not forbidden_spawn.called
    assert not policy._receipts and not policy._active_receipts and policy.active == 0
    assert not (root / '.kagent/tmp/scanners').exists()


async def prepared(runtime, args=None):
    args = dict(FFUF if args is None else args)
    tool = runtime.tool.freeze_for_execution()
    await tool.prepare_scanner(args, runtime.policy, None)
    return tool, args


def custom_wordlist(runtime, tmp_path, data='admin\napi/v1\n'):
    source = tmp_path / 'approved-words.txt'
    source.write_text(data)
    runtime.tool.scanner_binding = replace(runtime.tool.scanner_binding, wordlists=(('approved', source),))
    return source, {**FFUF, 'wordlist_id': 'approved'}


@pytest.mark.parametrize('args', [
    {'scanner': 'katana'}, {'scanner': 'gobuster'}, {'scanner': []},
    {**NMAP, 'argv': ['-A']}, {**NMAP, 'command': 'id'},
    {**NMAP, 'executable': '/bin/sh'}, {**NMAP, 'env': {}},
    {**NMAP, 'output_path': '/tmp/arbitrary'}, {**FFUF, 'config': '/etc/ffufrc'},
    {**FFUF, 'proxy': 'http://elsewhere'}, {**FFUF, 'headers': {'Host': 'other.test'}},
    {**FFUF, 'extra_args': ['-input-cmd', 'id']},
    {**NMAP, 'target': '127.0.0.1; id'}, {**NMAP, 'target': '127.0.0.0/24'},
    {**NMAP, 'target': 'example.test'}, {**NMAP, 'ports': '-'},
    {**NMAP, 'ports': '0'}, {**NMAP, 'ports': '65536'}, {**NMAP, 'ports': [True]},
    {**FFUF, 'threads': True}, {**FFUF, 'threads': 0},
    {**FFUF, 'rate': 0}, {**FFUF, 'rate': 0.5}, {**NMAP, 'rate': float('nan')},
    {**FFUF, 'timeout_seconds': True}, {**FFUF, 'timeout_seconds': 1801},
    {**FFUF, 'calibration': 'yes'}, {**FFUF, 'filter_size': [-1]},
    {**FFUF, 'match_status': '200;id'}, {**FFUF, 'filter_status': '80'},
    {**FFUF, 'url': ORIGIN}, {**FFUF, 'url': ORIGIN + '/FUZZ?x=1'},
    {**FFUF, 'url': ORIGIN + '/a?FUZZ=1'}, {**FFUF, 'url': ORIGIN + '/FUZZ/FUZZ'},
    {**FFUF, 'url': 'http://FUZZ.test/FUZZ'},
    {**FFUF, 'url': 'http://u:p@127.0.0.1:8080/FUZZ'},
    {**FFUF, 'url': ORIGIN + '/%2e%2e/FUZZ'},
    {**FFUF, 'url': ORIGIN + '/%0a/FUZZ'}, {**FFUF, 'url': ORIGIN + '//FUZZ'},
    {**FFUF, 'url': ORIGIN + '/%46UZZ/FUZZ'},
])
async def test_malformed_scanner_calls_reject_before_review(runtime, args):
    with pytest.raises(InvalidToolArguments):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert not runtime.operator.ask.called


def test_schema_exposes_typed_parameters_without_arbitrary_execution_fields():
    schema = ShellTool().schema()
    assert schema['properties']['scanner']['enum'] == ['nmap', 'ffuf']
    assert schema['properties']['threads']['default'] == 40
    assert not {'argv', 'executable', 'env', 'config', 'output_path', 'extra_args'} & schema['properties'].keys()
    assert 'scanner' not in BashTool().schema()['properties']


@pytest.mark.parametrize('args', [FFUF, NMAP])
@pytest.mark.parametrize('yolo', [False, True])
async def test_allow_admits_reviewed_job_but_never_executes_host(runtime, args, yolo):
    runtime.prompter.set_yolo(yolo)
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert runtime.operator.ask.call_count == (0 if yolo else 1)
    if not yolo:
        request = runtime.operator.ask.call_args.args[0]
        detail = json.loads(request.detail)
        assert detail['scanner'] == args['scanner']
        assert detail['target_origin'] == ORIGIN
        assert detail['plan_digest'] and detail['binary_sha256']
        assert detail['permission_unit'] == 'scanner_job'
        assert 'multiple requests/connections' in detail['approval']
        assert 'do not authorize this job' in detail['http_permissions']
        assert not request.supports_session
    assert runtime.tool.scanner_plan is None


async def test_deny_is_sticky_for_equivalent_plan_despite_repreparation(runtime):
    runtime.operator.ask.return_value = Decision.DENY
    with review_turn():
        with pytest.raises(UserControlledRefusal, match='permission denied'):
            await runtime.registry.execute('shell', FFUF, None, runtime.prompter)
        with pytest.raises(ExecutionBlocked, match='invocation-declined'):
            await runtime.registry.execute('shell', FFUF, None, runtime.prompter)
    assert runtime.operator.ask.call_count == 1


@pytest.mark.parametrize('args', [
    {**FFUF, 'url': 'https://127.0.0.1:8080/FUZZ'},
    {**FFUF, 'url': 'http://127.0.0.1:8081/FUZZ'},
    {**FFUF, 'url': 'http://localhost:8080/FUZZ'},
    {**NMAP, 'ports': '80,8080'}, {**NMAP, 'target': '127.0.0.2'},
])
async def test_yolo_does_not_broaden_http_or_tcp_scope(runtime, args):
    runtime.prompter.set_yolo(True)
    with pytest.raises(ExecutionBlocked):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert not runtime.operator.ask.called


async def test_explicit_tcp_scope_allows_full_range_without_legacy_cap(runtime):
    runtime.state.add_tcp('192.0.2.10', '1-65535')
    tool, args = await prepared(runtime, {**NMAP, 'target': '192.0.2.10', 'ports': '1-65535'})
    plan = tool.scanner_plan
    assert len(plan.ports) == 65535
    assert plan.argv[:3] == ('-sT', '-n', '-Pn')
    assert plan.argv[plan.argv.index('-p') + 1] == '1-65535'
    assert plan.argv[-1] == '192.0.2.10'
    assert '--max-rate' not in plan.argv and '--max-parallelism' not in plan.argv
    assert not runtime.state.is_in_scope('http://192.0.2.10')


async def test_ffuf_native_controls_are_independent_of_native_http_limits(runtime, monkeypatch):
    grant = runtime.state.http_permissions.activate(ORIGIN, HTTPLimits(requests=1, rate=3, burst=3))
    monkeypatch.setattr(runtime.state.http_permissions, '_budget', lambda *a: pytest.fail('Native HTTP budget used'))
    monkeypatch.setattr(runtime.state.http_permissions, 'reserve', lambda *a: pytest.fail('Native HTTP receipt used'))
    tool, _ = await prepared(runtime, {**FFUF, 'threads': 80, 'rate': 500,
        'calibration': True, 'match_status': '200-299,403', 'filter_size': [42, 100]})
    argv = tool.scanner_plan.argv
    assert argv[argv.index('-t') + 1] == '80'
    assert argv[argv.index('-rate') + 1] == '500'
    assert '-ac' in argv and '-ignore-body' not in argv and '-r' not in argv
    assert grant.limits == HTTPLimits(requests=1, rate=3, burst=3)
    assert grant.limits.response_bytes == 64 * 1024
    default, _ = await prepared(runtime)
    assert '-rate' not in default.scanner_plan.argv


@pytest.mark.parametrize('yolo', [False, True])
@pytest.mark.parametrize('args', [FFUF, NMAP])
@pytest.mark.parametrize('limits', [
    HTTPLimits(seconds=None, requests=1),
    HTTPLimits(seconds=30, requests=None),
    HTTPLimits.session(rate=0.5),
    HTTPLimits.session(burst=1),
    HTTPLimits.session(concurrency=1),
    HTTPLimits.session(request_bytes=4096),
    HTTPLimits.session(response_bytes=8192),
])
async def test_http_constraints_do_not_authorize_or_limit_scanner_job(runtime, monkeypatch, yolo, args, limits):
    rights = runtime.state.http_permissions
    grant = rights.activate(ORIGIN, limits)
    runtime.prompter.set_yolo(yolo)
    for name in ('_budget', 'authorize', 'authorize_adapter', 'reserve', 'reserve_when_ready'):
        monkeypatch.setattr(rights, name, lambda *a, **kw: pytest.fail('Scanner used HTTP authorization/accounting'))
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert runtime.operator.ask.call_count == (0 if yolo else 1)
    assert rights.grants[runtime.target.origin()] is grant
    assert rights._budgets[grant.id].used == 0
    assert not rights._inflight and not rights._receipts
    assert runtime.policy.used == 1


@pytest.mark.parametrize('yolo', [False, True])
@pytest.mark.parametrize('args', [FFUF, NMAP])
async def test_confirm_each_scanner_follows_current_yolo_mode(runtime, yolo, args):
    runtime.state.http_permissions.activate(ORIGIN, HTTPLimits.session(), 'confirm-each')
    runtime.prompter.set_yolo(yolo)
    with review_turn():
        for _ in range(2):
            with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
                await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert runtime.operator.ask.call_count == (0 if yolo else 2)
    assert runtime.policy.used == 2


@pytest.mark.parametrize('args', [FFUF, NMAP])
async def test_http_session_grant_cannot_make_scanner_approval_reusable(runtime, args):
    runtime.state.http_permissions.activate(ORIGIN, HTTPLimits.session())
    runtime.operator.ask.return_value = Decision.ALLOW_SESSION
    with pytest.raises(UserControlledRefusal, match='permission denied'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert not runtime.operator.ask.call_args.args[0].supports_session
    assert runtime.policy.used == 0


@pytest.mark.parametrize('args', [FFUF, NMAP])
@pytest.mark.parametrize('expired', [False, True])
async def test_scanner_job_preserves_native_http_quota_and_expiry(runtime, monkeypatch, args, expired):
    now = [100.0]
    runtime.policy.clock = runtime.state.http_permissions.clock = lambda: now[0]
    rights = runtime.state.http_permissions
    grant = rights.activate(ORIGIN, HTTPLimits(seconds=10, requests=1))
    http_tool = HTTPTool(runtime.target, runtime.state)
    runtime.registry.register(http_tool)
    sent = []
    original = httpx.AsyncClient

    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=b'bounded native response')

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    if expired:
        now[0] += 11
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert rights._budgets[grant.id].used == 0
    if not expired:
        await runtime.registry.execute('http', {'url': '/one', 'phase': 'recon'}, None, runtime.prompter)
    with pytest.raises(HTTPBlocked, match='expired' if expired else 'budget exhausted'):
        await runtime.registry.execute('http', {'url': '/two', 'phase': 'recon'}, None, runtime.prompter)
    assert len(sent) == (0 if expired else 1)
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert rights._budgets[grant.id].used == (0 if expired else 1)
    assert rights.grants[runtime.target.origin()] is grant


@pytest.mark.parametrize('args', [FFUF, NMAP])
@pytest.mark.parametrize('initial_grant', [False, True])
async def test_grant_replacement_during_review_invalidates_scanner(runtime, args, initial_grant):
    rights = runtime.state.http_permissions
    if initial_grant:
        rights.activate(ORIGIN, HTTPLimits.session())

    async def review(request, signal=None):
        assert request.is_current()
        rights.activate(ORIGIN, HTTPLimits.session())
        assert not request.is_current()
        return Decision.ALLOW_ONCE

    runtime.operator.ask.side_effect = review
    with pytest.raises(ExecutionBlocked, match='stale'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert runtime.operator.ask.call_count == 1
    assert runtime.policy.used == 0


@pytest.mark.parametrize('phase', ['dispatch', 'start'])
@pytest.mark.parametrize('replacement', ['same', 'quota', 'confirm-each'])
@pytest.mark.parametrize('args', [FFUF, NMAP])
@pytest.mark.parametrize('initial_grant', [False, True])
async def test_grant_replacement_invalidates_prepared_receipt(runtime, phase, replacement, args, initial_grant):
    rights = runtime.state.http_permissions
    if initial_grant:
        rights.activate(ORIGIN, HTTPLimits.session())
    tool, args = await prepared(runtime, args)
    review = runtime.policy.prepare(tool, args, reviewing=True)
    receipt = (runtime.policy.dispatch_receipt(review, tool, args, None)
               if phase == 'start' else review)
    limits = HTTPLimits(seconds=None, requests=1) if replacement == 'quota' else HTTPLimits.session()
    rights.activate(ORIGIN, limits, 'confirm-each' if replacement == 'confirm-each' else 'autonomous')
    token = None
    try:
        assert not runtime.policy.review_is_current(receipt, tool, args)
        with pytest.raises(ExecutionBlocked, match='stale'):
            if phase == 'dispatch':
                runtime.policy.dispatch_receipt(receipt, tool, args, None)
            else:
                token = runtime.policy.start(receipt, tool, args, None)
    finally:
        if token is not None:
            runtime.policy.stop(token)
        runtime.policy.finish_review(receipt)
    assert runtime.policy.used == 0


@pytest.mark.parametrize('args', [FFUF, NMAP])
async def test_unrelated_origin_grant_replacement_does_not_invalidate_job(runtime, args):
    other = 'http://127.0.0.1:8081'
    runtime.state.add_origin(other)
    rights = runtime.state.http_permissions
    rights.activate(other, HTTPLimits.session())

    async def review(request, signal=None):
        rights.activate(other, HTTPLimits(requests=1), 'confirm-each')
        assert request.is_current()
        return Decision.ALLOW_ONCE

    runtime.operator.ask.side_effect = review
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert runtime.operator.ask.call_count == 1


async def test_native_http_usage_does_not_stale_reviewed_scanner(runtime, monkeypatch):
    rights = runtime.state.http_permissions
    grant = rights.activate(ORIGIN, HTTPLimits.session())
    runtime.registry.register(HTTPTool(runtime.target, runtime.state))
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'one native request')), **kw))
    monkeypatch.setattr('src.tools.http.http_tool.gate_private_request', AsyncMock(return_value=''))
    tool, args = await prepared(runtime)
    with review_turn():
        review = runtime.policy.prepare(tool, args, reviewing=True)
        try:
            await runtime.registry.execute('http', {'url': '/native', 'phase': 'recon'}, None, runtime.prompter)
            assert rights._budgets[grant.id].used == 1
            assert runtime.policy.review_is_current(review, tool, args)
            receipt = runtime.policy.dispatch_receipt(review, tool, args, None)
            token = runtime.policy.start(receipt, tool, args, None)
            try:
                with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
                    await tool.run(args, None, runtime.prompter)
            finally:
                runtime.policy.stop(token)
        finally:
            runtime.policy.finish_review(review)


@pytest.mark.parametrize('same_origin', [False, True])
async def test_async_preparation_binds_origin_grant_authority(runtime, monkeypatch, same_origin):
    other = 'http://127.0.0.1:8081'
    runtime.state.add_origin(other)
    snapshot = ScannerBinding.snapshot_wordlist

    async def replace_grant(binding, name):
        await asyncio.sleep(0)
        runtime.state.http_permissions.activate(ORIGIN if same_origin else other, HTTPLimits.session())
        return await snapshot(binding, name)

    monkeypatch.setattr(ScannerBinding, 'snapshot_wordlist', replace_grant)
    reason = 'authority changed during preparation' if same_origin else 'host-scanner-execution-unavailable'
    with pytest.raises(ExecutionBlocked, match=reason):
        await runtime.registry.execute('shell', FFUF, None, runtime.prompter)
    assert runtime.operator.ask.call_count == (0 if same_origin else 1)


@pytest.mark.parametrize('phase', ['dispatch', 'start'])
@pytest.mark.parametrize('change', ['revoke', 'deny', 'tool', 'private', 'yolo', 'reset'])
async def test_permission_controls_invalidate_job_before_dispatch(runtime, phase, change):
    rights = runtime.state.http_permissions
    grant = rights.activate(ORIGIN, HTTPLimits.session())
    tool, args = await prepared(runtime)
    review = runtime.policy.prepare(tool, args, reviewing=True)
    receipt = runtime.policy.dispatch_receipt(review, tool, args, None) if phase == 'start' else review
    if change == 'revoke':
        rights.revoke(grant.id)
    elif change == 'deny':
        rights.deny_session()
    elif change == 'tool':
        runtime.policy.revoke('shell')
    elif change == 'private':
        rights.pause_private(runtime.target.origin())
    elif change == 'yolo':
        runtime.prompter.set_yolo(True)
    else:
        rights.reset()
    token = None
    try:
        assert not runtime.policy.review_is_current(receipt, tool, args)
        with pytest.raises(ExecutionBlocked):
            if phase == 'dispatch':
                runtime.policy.dispatch_receipt(receipt, tool, args, None)
            else:
                token = runtime.policy.start(receipt, tool, args, None)
    finally:
        if token is not None:
            runtime.policy.stop(token)
        runtime.policy.finish_review(receipt)
    assert runtime.policy.used == 0


@pytest.mark.parametrize('restriction', ['tool', 'session', 'origin', 'private'])
@pytest.mark.parametrize('yolo', [False, True])
async def test_existing_denials_apply_before_review(runtime, restriction, yolo):
    if restriction == 'tool':
        runtime.policy.revoke('shell')
    elif restriction == 'session':
        runtime.state.http_permissions.deny_session()
    elif restriction == 'origin':
        grant = runtime.state.http_permissions.activate(ORIGIN, HTTPLimits.session())
        runtime.state.http_permissions.revoke(grant.id)
    else:
        runtime.state.http_permissions.pause_private(runtime.target.origin())
    runtime.prompter.set_yolo(yolo)
    with pytest.raises(ExecutionBlocked):
        await runtime.registry.execute('shell', FFUF, None, runtime.prompter)
    assert not runtime.operator.ask.called


@pytest.mark.parametrize('change', ['scope', 'target', 'binary', 'wordlist', 'private', 'tool', 'tcp'])
async def test_changes_during_permission_review_invalidate_plan(runtime, tmp_path, change):
    source, args = custom_wordlist(runtime, tmp_path)
    if change == 'tcp':
        runtime.state.add_tcp('192.0.2.10', '80,443')
        args = {**NMAP, 'target': '192.0.2.10', 'ports': '80,443'}

    async def review(request, signal=None):
        assert request.is_current()
        if change == 'scope':
            runtime.state.add_origin('http://127.0.0.1:8081')
        elif change == 'target':
            runtime.target.set_base_url(ORIGIN + '/changed')
        elif change == 'binary':
            path = Path(runtime.binaries['ffuf'])
            path.write_bytes(path.read_bytes() + b'changed')
        elif change == 'wordlist':
            source.write_text('different\n')
        elif change == 'private':
            runtime.state.http_permissions.pause_private(runtime.target.origin())
        elif change == 'tcp':
            runtime.state.remove_tcp('192.0.2.10', '443')
        else:
            runtime.policy.revoke('shell')
        assert not request.is_current()
        return Decision.ALLOW_ONCE

    runtime.operator.ask.side_effect = review
    with pytest.raises(ExecutionBlocked, match='stale'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)


async def test_receipt_replay_expiry_and_review_dispatch_binding(runtime):
    tool, args = await prepared(runtime)
    with review_turn():
        review = runtime.policy.prepare(tool, args, reviewing=True)
        with pytest.raises(ExecutionBlocked, match='review-ticket'):
            runtime.policy.start(review, tool, args, None)
        receipt = runtime.policy.dispatch_receipt(review, tool, args, None)
        assert receipt.digest == invocation_digest(tool, args)
        with pytest.raises(ExecutionBlocked):
            runtime.policy.start(replace(receipt, expires=0), tool, args, None)
        token = runtime.policy.start(receipt, tool, args, None)
        try:
            runtime.policy.revalidate_active(tool, args, None)
            with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
                await tool.run(args, None, runtime.prompter)
        finally:
            runtime.policy.stop(token)
        with pytest.raises(ExecutionBlocked, match='stale/replayed'):
            runtime.policy.start(receipt, tool, args, None)


async def test_prepared_plan_and_wordlist_are_immutable(runtime, tmp_path):
    source, args = custom_wordlist(runtime, tmp_path)
    tool, args = await prepared(runtime, args)
    plan = tool.scanner_plan
    with pytest.raises(FrozenInstanceError):
        plan.timeout_seconds = 1
    with pytest.raises(TypeError):
        plan.argv[0] = 'sh'
    with pytest.raises(FrozenInstanceError):
        plan.wordlist.data = b'other\n'
    with pytest.raises(ExecutionBlocked, match='arguments differ'):
        runtime.policy.prepare(tool, {**args, 'threads': 80})
    source.write_text('different\n')
    assert plan.wordlist.data == b'admin\napi/v1\n'
    with pytest.raises(ExecutionBlocked, match='wordlist changed'):
        runtime.policy.prepare(tool, args)


async def test_replacing_effective_argv_after_review_breaks_receipt(runtime):
    tool, args = await prepared(runtime)
    receipt = runtime.policy.prepare(tool, args)
    tool.scanner_plan = replace(tool.scanner_plan, argv=tool.scanner_plan.argv + ('-r',))
    with pytest.raises(ExecutionBlocked, match='arguments-changed'):
        runtime.policy.start(receipt, tool, args, None)
    runtime.policy.finish_review(receipt)


async def test_registry_freezes_nested_arguments_and_review_matches_plan(runtime):
    args = {**FFUF, 'filter_size': [42]}

    async def review(request, signal=None):
        args['filter_size'].append(100)
        args['threads'] = 1
        assert request.is_current()
        detail = json.loads(request.detail)
        argv = detail['effective_argv']
        assert argv[argv.index('-fs') + 1] == '42'
        assert argv[argv.index('-t') + 1] == '40'
        return Decision.ALLOW_ONCE

    runtime.operator.ask.side_effect = review
    with pytest.raises(ExecutionBlocked, match='host-scanner-execution-unavailable'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)


@pytest.mark.parametrize('data', ['../secret\n', '//other.test\n', 'https://other.test\n',
    '%2e%2e/private\n', 'admin?FUZZ=x\n', 'admin\x00x\n', ''])
async def test_controlled_wordlist_still_validates_content(runtime, tmp_path, data):
    _, args = custom_wordlist(runtime, tmp_path, data)
    with pytest.raises(InvalidToolArguments):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert not runtime.operator.ask.called


async def test_arbitrary_wordlist_id_and_missing_binary_fail_closed(runtime):
    with pytest.raises(ExecutionBlocked, match='wordlist_id'):
        await runtime.registry.execute('shell', {**FFUF, 'wordlist_id': '/etc/passwd'}, None, runtime.prompter)
    runtime.caps.mark_unavailable('ffuf')
    with pytest.raises(ExecutionBlocked, match='binary unavailable'):
        await runtime.registry.execute('shell', FFUF, None, runtime.prompter)


async def test_model_writable_binary_and_script_wrapper_rejected(runtime):
    path = runtime.root / 'nmap'
    path.write_bytes(Path(runtime.binaries['nmap']).read_bytes())
    path.chmod(0o755)
    runtime.tool.scanner_binding = replace(runtime.tool.scanner_binding,
        capabilities=CapabilityInventory(which=lambda name: str(path)))
    with pytest.raises(ExecutionBlocked, match='model-writable'):
        await runtime.registry.execute('shell', NMAP, None, runtime.prompter)
    path.unlink()
    path.symlink_to(runtime.binaries['nmap'])
    with pytest.raises(ExecutionBlocked, match='model-writable'):
        await runtime.registry.execute('shell', NMAP, None, runtime.prompter)
    path = Path(runtime.binaries['nmap'])
    path.write_text('#!/bin/sh\nexit 0\n')
    runtime.tool.scanner_binding = replace(runtime.tool.scanner_binding, capabilities=runtime.caps)
    with pytest.raises(ExecutionBlocked, match='ELF'):
        await runtime.registry.execute('shell', NMAP, None, runtime.prompter)


async def test_unbound_direct_bash_and_ordinary_strings_cannot_gain_host_path(runtime):
    with pytest.raises(ExecutionBlocked, match='bound execution policy'):
        await ShellTool().run(FFUF, None, AlwaysAllow())
    with pytest.raises(ExecutionBlocked):
        await runtime.tool.run(FFUF, None, runtime.prompter)
    with pytest.raises(ValueError, match='only available on shell'):
        await BashTool().run(FFUF, None, runtime.prompter)
    for command in ('nmap 127.0.0.1', 'ffuf -u http://127.0.0.1/FUZZ', 'env nmap 127.0.0.1'):
        with pytest.raises(ExecutionBlocked, match='isolated filesystem'):
            await runtime.registry.execute('shell', {'command': command}, None, runtime.prompter)
    assert not runtime.operator.ask.called


async def test_target_hostname_is_pinned_in_plan_without_network_send(runtime, monkeypatch):
    origin = 'https://app.example.test:8443'
    runtime.target.set_base_url(origin)
    runtime.state.reset_to_origin(origin)
    monkeypatch.setattr('src.tools.execution.scanners.resolve_addresses', lambda host: ('192.0.2.10',))
    tool, _ = await prepared(runtime, {**FFUF, 'url': origin + '/dir/FUZZ'})
    plan = tool.scanner_plan
    assert plan.address == '192.0.2.10'
    assert plan.argv[plan.argv.index('-u') + 1] == 'https://192.0.2.10:8443/dir/FUZZ'
    assert plan.argv[plan.argv.index('-H') + 1] == 'Host: app.example.test:8443'
    assert plan.argv[plan.argv.index('-sni') + 1] == 'app.example.test'


def test_tcp_scope_roundtrip_merge_partial_revoke_reset_and_legacy_defaults():
    state = EngagementState()
    state.add_origin(ORIGIN)
    state.add_tcp('2001:db8::1', '80,443')
    state.add_tcp('2001:0db8::1', '8000-8100')
    assert len(state.allowed_tcp) == 1
    assert state.tcp_allows('2001:db8::1', '80,443,8000-8100')
    restored = EngagementState.from_dict(state.to_dict())
    assert restored.allowed_tcp == state.allowed_tcp
    other = EngagementState()
    other.replace_from(restored)
    assert other.allowed_tcp == state.allowed_tcp
    assert other.remove_tcp('2001:db8::1', '443')
    assert not other.tcp_allows('2001:db8::1', '443')
    assert other.tcp_allows('2001:db8::1', '80')
    assert other.reset_to_origin(ORIGIN)[1]
    assert not other.allowed_tcp
    state.reset_to_origin('http://127.0.0.1:8081')
    assert not state.allowed_tcp
    restored.clear()
    assert not restored.allowed_tcp
    assert not EngagementState.from_dict({'allowed_origins': [next(iter(state.allowed_origins)).to_dict()]}).allowed_tcp


@pytest.mark.parametrize('ip,ports', [('example.test', '80'), ('127.0.0.0/24', '80'),
    ('::', '80'), ('fe80::1%eth0', '80'), ('127.0.0.1', '1-65536'),
    ('127.0.0.1', '80,'), ('127.0.0.1', [False])])
def test_invalid_serialized_tcp_scope_never_broadens_authority(ip, ports):
    state = EngagementState.from_dict({'allowed_tcp': [{'address': ip, 'ports': ports}]})
    assert not state.allowed_tcp


def test_tcp_port_format_is_exact_without_artificial_count_cap():
    assert format_tcp_ports(parse_tcp_ports('1-65535')) == '1-65535'
    assert format_tcp_ports(parse_tcp_ports('80,443,8000-8100,80')) == '80,443,8000-8100'


@pytest.mark.parametrize('resource', ['binary', 'wordlist', 'target', 'scope'])
async def test_dispatch_rechecks_resources_and_authority_after_receipt(runtime, tmp_path, resource):
    source, args = custom_wordlist(runtime, tmp_path)
    tool, args = await prepared(runtime, args)
    review = runtime.policy.prepare(tool, args, reviewing=True)
    receipt = runtime.policy.dispatch_receipt(review, tool, args, None)
    try:
        if resource == 'binary':
            path = Path(runtime.binaries['ffuf'])
            original = path.with_suffix('.original')
            path.rename(original)
            path.symlink_to(original)
        elif resource == 'wordlist':
            source.write_text('after-receipt\n')
        elif resource == 'target':
            runtime.target.set_base_url(ORIGIN + '/other')
        else:
            runtime.state.reset_to_origin('http://127.0.0.1:8081')
        # Keep the existing policy's OutOfScopeError contract for removed origins.
        with pytest.raises(OutOfScopeError if resource == 'scope' else ExecutionBlocked):
            runtime.policy.start(receipt, tool, args, None)
    finally:
        runtime.policy.finish_review(receipt)


async def test_wordlist_symlink_cannot_turn_approved_id_into_arbitrary_host_read(runtime, tmp_path):
    source, args = custom_wordlist(runtime, tmp_path)
    original = source.with_suffix('.original')
    source.rename(original)
    source.symlink_to(original)
    with pytest.raises(ExecutionBlocked, match='symlink/hardlink'):
        await runtime.registry.execute('shell', args, None, runtime.prompter)
    assert not runtime.operator.ask.called


async def test_async_preparation_scope_change_fails_before_review(runtime, monkeypatch):
    snapshot = ScannerBinding.snapshot_wordlist
    async def change_scope(binding, name):
        await asyncio.sleep(0)
        runtime.state.add_origin('http://127.0.0.1:8081')
        return await snapshot(binding, name)
    monkeypatch.setattr(ScannerBinding, 'snapshot_wordlist', change_scope)
    with pytest.raises(ExecutionBlocked, match='authority changed during preparation'):
        await runtime.registry.execute('shell', FFUF, None, runtime.prompter)
    assert not runtime.operator.ask.called


async def test_cancelled_preparation_mints_no_receipt_and_creates_no_scratch(runtime, monkeypatch):
    waiting = asyncio.Event()
    async def wait_for_cancel(binding, name):
        waiting.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(ScannerBinding, 'snapshot_wordlist', wait_for_cancel)
    task = asyncio.create_task(runtime.registry.execute('shell', FFUF, None, runtime.prompter))
    await waiting.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not runtime.operator.ask.called


async def test_scanner_paths_do_not_inherit_legacy_discovery_length_cap(runtime, tmp_path):
    from src.tools.discovery.common import validate_relative_path
    word = 'a' * 512
    _, args = custom_wordlist(runtime, tmp_path, word + '\n')
    with pytest.raises(ValueError):
        validate_relative_path(word)  # Legacy/native caller defaults stay intact.
    tool, _ = await prepared(runtime, {**args, 'url': ORIGIN + '/' + word + '/FUZZ'})
    assert tool.scanner_plan.wordlist.data == (word + '\n').encode()
