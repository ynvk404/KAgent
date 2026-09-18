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
    impact: str = "Impact.",
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
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        url=url,
        impact=impact,
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
    )

@pytest.mark.asyncio
async def test_saved_finding_file_has_owner_only_permissions(temp_dir: str):
    store = Store(temp_dir)
    path = await store.save(make_finding(slug="perm-check"))

    mode = stat.S_IMODE(Path(path).stat().st_mode)
    assert mode == 0o600

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
        make_finding(slug="race", url=f"https://app.example.com/api/{i}")
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
        impact="Session takeover via stolen cookies.",
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
    assert "## Impact\n\nSession takeover via stolen cookies." in content
    assert "## Payload\n\n```\n<script>alert(1)</script>\n```" in content
    assert "## Response excerpt" in content
    assert "## Reproduce\n\n```sh" in content
    assert "## Remediation\n\nEncode output before rendering." in content


def test_render_omits_optional_sections_when_absent():
    f = make_finding(
        title="Minimal finding",
        impact="Some impact.",
        slug="minimal",
    )

    content = render(f)

    assert "## Payload" not in content
    assert "## Response excerpt" not in content
    assert "## Reproduce" not in content
    assert "## Remediation" not in content
    assert "- **Method:**" not in content
    assert "- **Parameter:**" not in content


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
