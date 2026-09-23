from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Severity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "info",
]

_SAFE_SLUG_RE = re.compile(r"^[a-z0-9-]+$")


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    url: str

    impact: str

    parameter: str | None = None
    payload: str | None = None
    method: str | None = None
    responseExcerpt: str | None = None
    curl: str | None = None
    remediation: str | None = None
    vulnerabilityType: str | None = None
    cwe: list[str] | None = None
    owasp: list[str] | None = None

    createdAt: str = ""
    slug: str = ""
    candidate_id: str | None = None


class Store:

    def __init__(
        self,
        directory: str = "findings",
    ) -> None:

        self.dir = Path(directory).resolve()


    async def save(
        self,
        finding: Finding,
    ) -> str:
        
        if not _SAFE_SLUG_RE.match(finding.slug):
            raise ValueError(
                f"unsafe finding slug: {finding.slug!r}"
            )

        content = render(finding)

        return await asyncio.to_thread(
            self._write,
            finding.slug,
            content,
        )


    def _write(
        self,
        slug: str,
        content: str,
    ) -> str:

        self.dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        i = 1

        while True:

            filename = (
                f"{slug}.md"
                if i == 1
                else f"{slug}-{i}.md"
            )

            path = self.dir / filename

            try:
                fd = os.open(
                    path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )

                try:
                    f = os.fdopen(fd, "w", encoding="utf-8")
                    fd = None  # The file object now owns the descriptor.
                    with f:
                        f.write(content)
                except BaseException:
                    # The name was reserved before writing.  Never leave a
                    # partial report behind if writing or closing fails.
                    try:
                        if fd is not None:
                            os.close(fd)
                    finally:
                        try:
                            os.unlink(path)
                        except FileNotFoundError:
                            pass
                    raise

                return str(path)

            except FileExistsError:
                i += 1


def slugify(
    title: str,
) -> str:
    import unicodedata

    text = unicodedata.normalize(
        "NFKD",
        title.lower(),
    )

    text = re.sub(
        r"[^a-z0-9]+",
        "-",
        text,
    )

    text = re.sub(
        r"(^-+|-+$)",
        "",
        text,
    )

    return text[:64]


def render(
    f: Finding,
) -> str:

    lines: list[str] = []

    lines.append(f"# {_inline(f.title)}")
    lines.append("")

    lines.append(f"- **Severity:** {f.severity}")

    if f.candidate_id:
        lines.append(f"- **Candidate ID:** {_inline(f.candidate_id)}")

    if f.vulnerabilityType:
        lines.append(f"- **Vulnerability Type:** {f.vulnerabilityType}")

    if f.cwe:
        lines.append(f"- **CWE:** {', '.join(f.cwe)}")

    if f.owasp:
        lines.append(f"- **OWASP:** {', '.join(f.owasp)}")

    lines.append(f"- **URL:** {_inline(f.url)}")

    if f.method:
        lines.append(f"- **Method:** {_inline(f.method)}")

    if f.parameter:
        lines.append(f"- **Parameter:** {_inline(f.parameter)}")

    lines.append(f"- **Reported at:** {f.createdAt}")

    lines.extend(
        [
            "",
            "## Impact",
            "",
            f.impact,
            "",
        ]
    )

    if f.payload:
        lines.extend(
            [
                "## Payload",
                "",
                *_fenced(f.payload),
                "",
            ]
        )

    if f.responseExcerpt:
        lines.extend(
            [
                "## Response excerpt",
                "",
                *_fenced(f.responseExcerpt),
                "",
            ]
        )

    if f.curl:
        lines.extend(
            [
                "## Reproduce",
                "",
                *_fenced(f.curl, "sh"),
                "",
            ]
        )

    if f.remediation:
        lines.extend(
            [
                "## Remediation",
                "",
                f.remediation,
                "",
            ]
        )

    return "\n".join(lines)


def _inline(value: str) -> str:
    """Keep model-controlled metadata on its intended Markdown line."""
    return " ".join(value.splitlines())


def _fenced(value: str, language: str = "") -> list[str]:
    """Use a fence that cannot be closed by backticks in evidence."""
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{language}", value, fence]
