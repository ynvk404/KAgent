"""Loaded playbook instruction contracts; these do not verify LLM behavior."""
from pathlib import Path
import hashlib
import json
import re

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.permission.permission import AlwaysAllow
from src.tools.common.outcome import ToolOutput
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.skills.paths import MAX_BYTES, MAX_PREVIEW_BYTES


@pytest.fixture
def skills():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['sql-injection', 'cross-site-scripting'])
async def test_loaded_validation_guidance_binds_claims_to_captures_and_new_repair_snapshots(skills, name):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split())
    for contract in ('observation ID', 'request_preview_complete: false',
                     'execution status' if name == 'sql-injection' else 'completed execution',
                     'Metadata-only capture', 'record_evidence', 'correct `observation_ids`',
                     'new immutable snapshot', '`evidence_refs` before resubmitting',
                     'registered snapshots in place', 'retry at most once',
                     '`insufficient-evidence` and stop'):
        assert contract.lower() in loaded.lower()
    metadata = skills.get(name)
    assert metadata is not None
    assert 'workflow' in metadata.tools
    assert not any('browser' in tool for tool in metadata.tools)


@pytest.mark.asyncio
async def test_sql_diagnostics_revise_quote_hypothesis_for_discriminating_tests(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'sql-injection'})).split())
    for contract in ('inside a SQL string literal', 'unless later observations contradict it',
                     'ordinary application text do not establish SQL context',
                     'retain an ambiguous context', 'After consecutive probes',
                     'same expression-type error', 'before another request',
                     'type error is distinct from a syntax error',
                     'discriminating context-compatible hypothesis', 'do not require every technique',
                     'any terminal assessment', 'distinct executed observations',
                     'reusing an observation ID does not establish repeatability'):
        assert contract in loaded


@pytest.mark.asyncio
async def test_xss_context_and_transformation_remain_bounded_without_execution_inference(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'cross-site-scripting'})).split())
    for contract in ('neither `<html>` nor `<body>` wrappers are required',
                     'a prior close variant is not a stopping rule',
                     'existing or new observations support a different meaningful prediction', 'every delimiter',
                     'Compare distinct captured requests', 'Content-Type, surrounding syntax',
                     'encoding, inert context and CSP',
                     'Neither raw reflection nor HTML fragment parsing alone establishes execution',
                     'not observed browser execution', 'retain `browser-required`'):
        assert contract in loaded


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['sql-injection', 'cross-site-scripting'])
async def test_repair_guidance_matches_loaded_preface_without_changing_runtime_ceiling(skills, monkeypatch, name):
    from src.permission.runtime import execution
    from src.workflow.evidence.recovery import MAX_EVIDENCE_RECOVERY_RETRIES

    # Exercise the production loader preface, without creating runtime rights.
    monkeypatch.setattr(execution, 'policy_for', lambda _: object())
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split()).lower()
    assert 'retry at most once' in loaded
    assert 'at most two repair submissions' not in loaded
    assert 'remaining recovery budget' in loaded
    assert 'runtime retry ceiling' in loaded
    assert MAX_EVIDENCE_RECOVERY_RETRIES == 2


async def test_xss_opening_contract_prepares_only_known_associations_and_preserves_active_declaration(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'cross-site-scripting'})).split())
    for contract in ('complete current prerequisites', 'read the current skill',
                     'prepare primary/supplementary requests and roles', 'successfully call `start_validation`',
                     'candidate ID alone', '`POST /comments`', '`GET /comments`', 'role `readback`',
                     'different method is a different request identity', 'payload variations are observations',
                     'only known endpoints', 'Association grants no permission',
                     'do not amend it retrospectively', 'repeat HTTP just to repair association',
                     'Continue if the current declaration', 'honest unresolved outcome', 'explicit retest contract'):
        assert contract in loaded
    assert '/api/Feedbacks' not in loaded and 'Juice Shop' not in loaded


async def test_input_analysis_does_not_promote_json_markup_to_unsupported_xss_or_require_exploit(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'web-input-analysis'})).split())
    for contract in ('HTML markup or an inert marker in JSON remains an observation',
                     'rendering context nor a compatible source-to-sink path',
                     'Do not send a mutation to rescue an unsupported XSS hypothesis',
                     'JSON readback, persistence, executable rendering and execution proof',
                     'without browser execution or a confirmed exploit',
                     'valid request association likewise does not establish confirmed XSS'):
        assert contract in loaded
    assert 'unique, inert marker' in loaded and 'minimal syntax perturbation' in loaded


@pytest.mark.parametrize('name,obligations', [
    ('sql-injection', ['without query text leaves SQL shape a hypothesis',
        'same error or the same empty result do not establish a differential',
        'Record only requests, timeouts and responses actually observed', 'raw wire encoding from decoded application input',
        'new immutable snapshot', 'Usable metadata is not impact proof']),
    ('cross-site-scripting', ['API negative applies only to the tested sink',
        'cannot exclude DOM or stored XSS', 'actual exposed and allowed browser capabilities',
        'Registration alone does not make a terminal result eligible']),
    ('web-input-analysis', ['sanitized sample, even with a marker', 'not automatically promoted',
        'invalid credentials and format errors', 'request body, never response Content-Type']),
    ('web-enumeration', ['including password fields', 'not automatically synchronized',
        'not semantic completeness of Markdown', 'within 240 characters']),
])
async def test_loaded_lan02_evidence_handoff_guidance(skills, name, obligations):
    # These verify the supplied playbook contract, not model compliance.
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split()).lower()
    for obligation in obligations:
        assert obligation.lower() in loaded


async def test_sql_decision_checkpoint_is_early_and_conditions_boolean_sequencing(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'sql-injection'})).split())
    checkpoint = loaded.split('## Decision checkpoint', 1)[1].split('## Runtime completion contract', 1)[0]
    for rule in ('observed facts from assumptions', 'prefix', 'suffix', 'parentheses',
                 'known match', 'before dispatching dependent FALSE', 'do not blindly batch',
                 'If TRUE loses that marker', 'reassess context compatibility and the oracle',
                 'Equal empty responses do not establish SQLi absence',
                 'Suitable existing observations need no extra compatibility request',
                 'Boolean testing is not required for every Candidate',
                 'no numeric syntax-shape adjustment cap',
                 'One unsuccessful probe does not rule out every useful hypothesis',
                 'Avoid equivalent probes without information gain',
                 'Sufficient evidence needs no additional requests',
                 'scope, permissions and runtime/operator limits'):
        assert rule in checkpoint
    assert len(checkpoint.split('Stop when evidence is sufficient', 1)[0]) < 3200


async def test_xss_early_checkpoint_grounds_adaptation_and_optional_detection(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'cross-site-scripting'})).split()).lower()
    checkpoint = loaded.split('## decision checkpoint', 1)[1].split('## runtime completion contract', 1)[0]
    for concept in ('input source', 'output/dom sink', 'execution context', 'transformations',
                    'reflection, neutralization and execution', 'discriminating prediction',
                    'encoding or transformation uncertainty', 'even after a prior close variant',
                    'no numeric variant cap', 'redundant equivalent', 'payload spraying',
                    'no corpus exhaustion or minimum variants', 'evidence is sufficient',
                    'adequately ruled out', 'no useful authorized test remains', 'execution is blocked',
                    'runtime/operator limits', 'browser-required'):
        assert concept in checkpoint
    assert len(checkpoint) < 1800


@pytest.mark.parametrize('relative_path', [
    'skills/sql-injection/SKILL.md', 'skills/sql-injection/payloads.txt',
    'skills/cross-site-scripting/SKILL.md', 'skills/cross-site-scripting/payloads.txt',
    'src/agent/validation_guidance.py',
])
def test_active_guidance_has_no_technique_adjustment_caps(relative_path):
    # Check current policy, never rewrite expectations in historical evidence.
    text = ' '.join((Path(__file__).resolve().parents[2] / relative_path).read_text().lower().split())
    obsolete = (r'(?:cap|at most|limit of|maximum of).{0,45}(?:three|3).{0,60}(?:shape|adjustment)',
                r'(?:three|3)[ -](?:syntax.shape )?adjustments? (?:after|limit|allowance)',
                r'(?:at most|maximum of|permits|allowed|permitted) one.{0,50}(?:close.variant|compensating variant)',
                r'one (?:close.variant|probe per sub.case)',
                r'(?:consumes|replaces).{0,60}close.variant',
                r'spend at most this one probe')
    for cap in obsolete:
        assert not re.search(cap, text), f'{relative_path}: obsolete cap {cap}'


async def test_xss_css_breakout_and_detection_depend_on_context_not_probe_counts(skills):
    text = ' '.join((await LoadSkillTool(skills).run({'name': 'cross-site-scripting'})).split()).lower()
    context = text.split('## 2. determine', 1)[1].split('## 3. confirm', 1)[0]
    assert 'reuse adequate existing observations' in context
    assert 'only for unresolved encoding or transformation uncertainty' in context
    assert 'no extra detection request' in context
    css = context.split('**css context**', 1)[1].split('**fully encoded', 1)[0]
    for concept in ('unsupported path', 'already discredited', 'distinct html breakout',
                    'captured syntax and transformations', 'execution-evidence requirements',
                    'without forcing a negative result'):
        assert concept in css
    corpus = ' '.join((Path(__file__).resolve().parents[2] / 'skills/cross-site-scripting/payloads.txt')
                      .read_text().lower().split())
    assert 'unresolved encoding/transformation uncertainty' in corpus
    assert 'always run first' not in corpus and 'second detection request' not in corpus


@pytest.mark.parametrize('name', ['web-enumeration', 'web-input-analysis'])
async def test_source_first_handoff_preserves_request_and_operator_distinctions(skills, name):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split()).lower()
    for rule in ('bound `ask_user` calls/results', 'transitions', 'exact input ids',
                 'unexecuted post', 'behaviorally probed', 'validation result', 'finding',
                 'deterministic', 'hypothes', 'declared response length', 'retained bytes',
                 'inspected', 'http solely to repair prose'):
        assert rule in loaded
    if name == 'web-enumeration':
        for rule in ('likely http method', 'request contract', 'controllability',
                     'response schemas do not establish request fields',
                     'arrays and objects are supported inputs', 'json-containing string stays a string',
                     'serialization', 'request headers', 'actual named form controls'):
            assert rule in loaded
    else:
        for rule in ('authentication endpoint', 'protected endpoint', 'unknown request contract',
                     'submitting credentials differs from requiring an existing authenticated session',
                     'missing schema is a discovery gap', 'separate questions', 'csrf', 'captcha',
                     'client-authentication', 'genuine unmet prerequisite'):
            assert rule in loaded


@pytest.mark.parametrize('name', ['sql-injection', 'cross-site-scripting'])
async def test_loaded_reasoning_allows_existing_ambiguous_evidence_without_inventing_proof(skills, name):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split()).lower()
    checkpoint = loaded.split('## decision checkpoint', 1)[1].split('## runtime completion contract', 1)[0]
    assert 'observe → hypothesize → discriminate → predict → execute → interpret → reassess → decide' in checkpoint
    assert 'ambiguous existing observations' in checkpoint
    assert 'competing hypotheses' in checkpoint
    assert 'browser-required' in loaded and 'insufficient-evidence' in loaded
    assert re.search(r'synthetic.{0,70}not.{0,50}session evidence', loaded)
    assert 'planning' in loaded and 'owned' in loaded and 'captured' in loaded
    if name == 'sql-injection':
        assert 'no precise parser error is required' in checkpoint
        assert 'new http observation is not required to reconsider existing evidence' in loaded
        assert 'base interpretations on executed requests and actual responses, not predicted results' in loaded
    else:
        assert 'no new http observation is needed merely to reconsider' in checkpoint
        assert 'never reconstruct it or use an inadmissible capture as terminal proof' in loaded
        assert 'do not become owned proof for this attempt' in loaded
    for stale_gate in ('when new observations support', 'needs new observations',
                       'without using the returned parser position/message'):
        assert stale_gate not in loaded


@pytest.mark.parametrize('name', ['sql-injection', 'cross-site-scripting'])
@pytest.mark.parametrize('limit', [13, 5000])
async def test_new_context_examples_are_delivered_verbatim_through_bounded_resources(skills, name, limit):
    tool = ReadPayloadsTool(skills)
    raw_bytes = (Path(__file__).resolve().parents[2] / 'skills' / name / 'payloads.txt').read_bytes()
    assert len(raw_bytes) <= MAX_BYTES
    raw = raw_bytes.decode('utf-8')
    args = {'skill': name, 'file': 'payloads.txt', 'limit': limit}
    chunks = []
    offset = 0
    while True:
        output = await tool.run(args, None, AlwaysAllow())
        assert isinstance(output, ToolOutput)
        rendered, footer = output.rsplit('\nContinuation: ', 1)
        page = json.loads(footer)
        assert page['start_char'] == offset
        assert page['sha256'] == hashlib.sha256(raw_bytes).hexdigest()
        assert page['end_char'] > offset
        body = rendered.split('\n', 1)[1][:page['end_char'] - offset]
        assert body == raw[offset:page['end_char']]
        assert len(body.encode('utf-8')) <= MAX_PREVIEW_BYTES
        chunks.append(body)
        offset = page['end_char']
        if page['next_start_char'] is None:
            assert not output.truncated
            break
        assert output.truncated
        call = json.loads(rendered.splitlines()[0].split('Next page: ', 1)[1])
        assert call['tool'] == 'read_payloads'
        args = call['arguments']  # Never invent offsets or source identities.
    delivered = ''.join(chunks)
    assert delivered == raw

    if name == 'sql-injection':
        phase1 = delivered.split('PHASE 1 — DETECTION', 1)[1].split('PHASE 2 — VALIDATION', 1)[0]
        line = next(line for line in phase1.splitlines() if line.startswith("'))  "))
        payload, note = re.split(r' {2,}# purpose: ', line, maxsplit=1)
        assert payload == "'))" and '# purpose:' not in payload
        assert 'applies:' in note and 'limit:' in note
        assert 'no diagnostic counting layers required' in note
        assert 'syntax compatibility only, not SQLI-2' in note
    else:
        phase2 = delivered.split('PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION', 1)[1]
        for payload in ("><script>document.title='xsspoc-{MARKER}'</script>",
                        "${document.title='xsspoc-{MARKER}'}"):
            # The reader preserves separate annotation lines; they are not input.
            entry = phase2.split('\n' + payload + '\n', 1)[1].split('\n\n', 1)[0]
            assert all(line.startswith('    # ') for line in entry.splitlines())
            assert all(field in entry for field in ('purpose:', 'applies:', 'limit:'))
