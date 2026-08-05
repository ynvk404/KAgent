import asyncio
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