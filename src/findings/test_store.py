import tempfile
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from src.findings.store import Finding, Store


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="pf-findings-")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_does_not_overwrite_existing_findings_with_same_slug(
    temp_dir: str,
):
    store = Store(temp_dir)

    finding = Finding(
        title="IDOR",
        severity="high",
        url="https://app.example.com/api/orders/1",
        impact="Cross-account read.",
        createdAt="2026-06-06T00:00:00.000Z",
        slug="idor",
    )

    first = await store.save(finding)

    second = await store.save(
        replace(
            finding,
            url="https://app.example.com/api/orders/2",
        )
    )

    assert Path(first).resolve() == (
        Path(temp_dir) / "idor.md"
    ).resolve()

    assert Path(second).resolve() == (
        Path(temp_dir) / "idor-2.md"
    ).resolve()