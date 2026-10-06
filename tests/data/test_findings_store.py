import asyncio
import os
import stat
import shutil
import tempfile
from pathlib import Path

import pytest

from src.findings.store import Finding, Severity, Store, slugify, render


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="pf-findings-")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def make_finding(
    *,
    title: str = "Finding",
    severity: Severity = "high",
    url: str = "https://app.example.com/api/x",
    observed_impact: str = "Observed impact.",
    potential_impact: str = "Potential impact not assessed.",
    createdAt: str = "2026-06-06T00:00:00.000Z",
    slug: str = "finding",
    parameter: str | None = None,
    payload: str | None = None,
    method: str | None = None,
    responseExcerpt: str | None = None,
    curl: str | None = None,
    remediation: str | None = None,
    vulnerabilityType: str | None = None,
    cwe: list[str] | None = None,
    owasp: list[str] | None = None,
    candidate_id: str | None = "cand_default",
    evidence_refs: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        url=url,
        observed_impact=observed_impact,
        potential_impact=potential_impact,
        createdAt=createdAt,
        slug=slug,
        parameter=parameter,
        payload=payload,
        method=method,
        responseExcerpt=responseExcerpt,
        curl=curl,
        remediation=remediation,
        vulnerabilityType=vulnerabilityType,
        cwe=cwe,
        owasp=owasp,
        candidate_id=candidate_id,
        evidence_refs=evidence_refs if evidence_refs is not None else ["ev_default"],
    )

@pytest.mark.asyncio
async def test_saved_finding_file_has_owner_only_permissions(temp_dir: str):
    store = Store(temp_dir)
    path = await store.save(make_finding(slug="perm-check"))

    mode = stat.S_IMODE(Path(path).stat().st_mode)
    assert mode == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "finding",
    [
        make_finding(candidate_id=None),
        make_finding(evidence_refs=[]),
    ],
)
async def test_save_requires_candidate_and_evidence_provenance(temp_dir: str, finding):
    with pytest.raises(ValueError, match="candidate and evidence provenance"):
        await Store(temp_dir).save(finding)


@pytest.mark.asyncio
async def test_legacy_finding_is_read_for_candidate_dedup_without_copy(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "findings" / "legacy-single-impact.md"
    legacy = tmp_path / "findings" / fixture.name
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(fixture.read_bytes())
    canonical_store = Store(project_directory=tmp_path)

    repeated = await canonical_store.save(make_finding(
        slug="new-name", candidate_id="cand_legacy0123456789"
    ))
    assert Path(repeated) == legacy
    assert not (tmp_path / "artifacts/findings").exists()

    fresh = await canonical_store.save(make_finding(
        slug="fresh-finding", candidate_id="cand_new"
    ))
    assert Path(fresh) == tmp_path / "artifacts/findings/fresh-finding.md"
    assert Path(legacy).exists()


def test_current_report_fixture_restores_markdown_headings_in_body():
    from src.findings.store import read_report

    fixture = Path(__file__).parent / "fixtures" / "findings" / "current-with-headings.md"
    finding = read_report(fixture)

    assert finding.title == "Current finding format"
    assert finding.observed_impact == (
        "The linked proof demonstrates the response difference.\n"
        "## Evidence notes\n### Repeated observation\n#### Detail"
    )
    assert finding.potential_impact == (
        "Additional impact remains unassessed.\n## Conditional scenario\n"
        "### Boundary"
    )
    assert finding.payload == "id=1 OR 1=1\n## Payload-looking evidence"
    assert finding.remediation == "Use parameterized queries.\n## Rollout notes"


def test_legacy_single_impact_report_from_repository_history_restores():
    from src.findings.store import read_report

    fixture = Path(__file__).parent / "fixtures" / "findings" / "legacy-single-impact.md"
    finding = read_report(fixture)

    assert finding.title == "Legacy SQL injection report"
    assert finding.candidate_id == "cand_legacy0123456789"
    assert finding.observed_impact == "A repeatable boolean difference was recorded."
    assert finding.potential_impact == ""
    assert finding.evidence_refs is None

@pytest.mark.asyncio
async def test_save_rejects_path_traversal_slug(temp_dir: str):
    store = Store(temp_dir)

    with pytest.raises(ValueError):
        await store.save(make_finding(slug="../../evil"))


@pytest.mark.asyncio
async def test_save_rejects_slug_with_path_separator(temp_dir: str):
    store = Store(temp_dir)

    with pytest.raises(ValueError):
        await store.save(make_finding(slug="sub/dir"))


@pytest.mark.asyncio
async def test_concurrent_saves_with_same_slug_never_collide(temp_dir: str):
    store = Store(temp_dir)

    findings = [
        make_finding(
            slug="race",
            url=f"https://app.example.com/api/{i}",
            candidate_id=f"cand_{i}",
            evidence_refs=[f"ev_{i}"],
        )
        for i in range(8)
    ]

    paths = await asyncio.gather(*(store.save(f) for f in findings))

    assert len(set(paths)) == len(paths)  
    for path in paths:
        assert Path(path).exists()


@pytest.mark.asyncio
async def test_failed_write_removes_reserved_partial_file(temp_dir: str, monkeypatch):
    store = Store(temp_dir)
    real_fdopen = os.fdopen

    class BrokenFile:
        def __init__(self, fd):
            self.fd = fd

        def __enter__(self):
            return self

        def __exit__(self, *_):
            os.close(self.fd)
            return False

        def write(self, _):
            raise OSError("disk full")

    monkeypatch.setattr(
        os,
        "fdopen",
        lambda fd, *_args, **_kwargs: BrokenFile(fd),
    )

    with pytest.raises(OSError, match="disk full"):
        await store.save(make_finding(slug="write-failure"))

    assert not (Path(temp_dir) / "write-failure.md").exists()
    # Keep the monkeypatch local to this test while documenting the real API.
    assert real_fdopen is not None

@pytest.mark.parametrize(
    "title,expected",
    [
        ("SQL Injection in /login", "sql-injection-in-login"),
        ("  leading and trailing spaces  ", "leading-and-trailing-spaces"),
        ("Café Ñandú", "cafe-n-andu"),
        ("hello北京world", "hello-world"),
        ("!!!", ""),
        ("", ""),
    ],
)
def test_slugify_cases(title: str, expected: str):
    assert slugify(title) == expected


def test_slugify_caps_length_at_64_chars():
    title = "x" * 100
    result = slugify(title)
    assert len(result) == 64
    assert result == "x" * 64


def test_render_includes_all_populated_sections():
    f = make_finding(
        title="Reflected XSS",
        severity="medium",
        url="https://app.example.com/search?q=1",
        method="GET",
        parameter="q",
        observed_impact="Session takeover via stolen cookies.",
        potential_impact="Further impact was not assessed.",
        payload="<script>alert(1)</script>",
        responseExcerpt="<div>1<script>alert(1)</script></div>",
        curl='curl "https://app.example.com/search?q=<script>alert(1)</script>"',
        remediation="Encode output before rendering.",
        createdAt="2026-06-06T00:00:00.000Z",
        slug="xss",
    )

    content = render(f)

    assert content.startswith("# Reflected XSS\n")
    assert "- **Severity:** medium" in content
    assert "- **URL:** https://app.example.com/search?q=1" in content
    assert "- **Method:** GET" in content
    assert "- **Parameter:** q" in content
    assert "- **Reported at:** 2026-06-06T00:00:00.000Z" in content
    assert "## Observed impact\n\nSession takeover via stolen cookies." in content
    assert "## Potential impact\n\nFurther impact was not assessed." in content
    assert "## Payload\n\n```\n<script>alert(1)</script>\n```" in content
    assert "## Response excerpt" in content
    assert "## Reproduce\n\n```sh" in content
    assert "## Remediation\n\nEncode output before rendering." in content


def test_render_omits_optional_sections_when_absent():
    f = make_finding(
        title="Minimal finding",
        observed_impact="Some impact.",
        potential_impact="No further impact assessed.",
        slug="minimal",
        candidate_id=None,
        evidence_refs=[],
    )

    content = render(f)

    assert "## Payload" not in content
    assert "## Response excerpt" not in content
    assert "## Reproduce" not in content
    assert "## Remediation" not in content
    assert "- **Method:**" not in content
    assert "- **Parameter:**" not in content
    assert "Candidate ID" not in content


def test_render_includes_optional_candidate_metadata():
    content = render(make_finding(candidate_id="cand_0123456789abcdef0123"))

    assert "- **Candidate ID:** cand_0123456789abcdef0123" in content


def test_render_includes_classification_after_severity():
    content = render(
        make_finding(
            vulnerabilityType="SQL Injection",
            cwe=["CWE-89"],
            owasp=["A03:2021 Injection"],
        )
    )

    severity = content.index("- **Severity:**")
    vulnerability_type = content.index("- **Vulnerability Type:**")
    cwe = content.index("- **CWE:**")
    owasp = content.index("- **OWASP:**")
    assert severity < vulnerability_type < cwe < owasp
    assert "- **CWE:** CWE-89" in content
    assert "- **OWASP:** A03:2021 Injection" in content


def test_render_omits_classification_when_absent():
    content = render(make_finding())

    assert "Vulnerability Type" not in content
    assert "- **CWE:**" not in content
    assert "- **OWASP:**" not in content


def test_render_keeps_backticks_in_evidence_inside_a_single_code_block():
    content = render(
        make_finding(
            payload="proof\n```\n# not a report heading",
            responseExcerpt="response\n````\n## also evidence",
            curl="curl x\n```\necho evidence",
        )
    )

    assert "````\nproof\n```\n# not a report heading\n````" in content
    assert "`````\nresponse\n````\n## also evidence\n`````" in content
    assert "````sh\ncurl x\n```\necho evidence\n````" in content


def test_render_keeps_metadata_on_its_own_lines():
    content = render(
        make_finding(title="A title\n## injected section", url="https://x\n- injected")
    )

    assert content.startswith("# A title ## injected section\n")
    assert "- **URL:** https://x - injected" in content


@pytest.mark.asyncio
async def test_retry_restores_entire_legacy_markdown_snapshot_including_fenced_evidence(tmp_path):
    from src.findings.store import read_report
    store = Store(project_directory=tmp_path)
    original = make_finding(
        title='Legacy report', slug='legacy', payload='marker\n```\n## CWE: not metadata',
        responseExcerpt='response\n````\n## Severity: not metadata',
        vulnerabilityType='Broken Access Control', cwe=None, owasp=['A01:2021 Broken Access Control'],
    )
    path = await store.save(original)
    content = Path(path).read_text()
    retry = make_finding(title='Proposed new title', slug='new-name', cwe=['CWE-639'])
    assert await store.save(retry) == path
    assert retry == read_report(Path(path)) == original
    assert retry.cwe is None and Path(path).read_text() == content


@pytest.mark.asyncio
async def test_cancelled_store_write_holds_lock_until_background_write_finishes(tmp_path, monkeypatch):
    import threading
    store = Store(project_directory=tmp_path)
    entered = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    original_write = store._write
    def slow_write(slug, content):
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(timeout=5):
            raise TimeoutError('test did not release writer')
        return original_write(slug, content)
    monkeypatch.setattr(store, '_write', slow_write)
    first = asyncio.create_task(store.save(make_finding(title='Original', slug='first')))
    await asyncio.wait_for(entered.wait(), 2)
    first.cancel()
    retry_finding = make_finding(title='Retry', slug='retry')
    retry = asyncio.create_task(store.save(retry_finding))
    await asyncio.sleep(0)
    assert not retry.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    path = await retry
    assert retry_finding.title == 'Original'
    assert list(store.dir.glob('*.md')) == [Path(path)]


@pytest.mark.parametrize("name", ["current-with-headings.md", "legacy-single-impact.md"])
def test_byte_parser_matches_path_parser(name):
    from src.findings.store import read_report, read_report_bytes
    path = Path(__file__).parent / "fixtures" / "findings" / name
    assert read_report_bytes(path.read_bytes(), slug=path.stem) == read_report(path)


def test_byte_parser_uses_supplied_snapshot_and_slug():
    from src.findings.store import read_report_bytes
    raw = render(make_finding(payload="## Impact\n- **Severity:** critical")).encode()
    parsed = read_report_bytes(raw, slug="detached")
    assert parsed.slug == "detached"
    assert parsed.severity == "high"
    assert parsed.payload == "## Impact\n- **Severity:** critical"
    with pytest.raises(UnicodeDecodeError):
        read_report_bytes(b"\xff", slug="bad")
