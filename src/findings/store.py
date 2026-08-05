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

    createdAt: str = ""
    slug: str = ""


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

                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)

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

    lines.append(f"# {f.title}")
    lines.append("")

    lines.append(f"- **Severity:** {f.severity}")
    lines.append(f"- **URL:** {f.url}")

    if f.method:
        lines.append(f"- **Method:** {f.method}")

    if f.parameter:
        lines.append(f"- **Parameter:** {f.parameter}")

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
                "```",
                f.payload,
                "```",
                "",
            ]
        )

    if f.responseExcerpt:
        lines.extend(
            [
                "## Response excerpt",
                "",
                "```",
                f.responseExcerpt,
                "```",
                "",
            ]
        )

    if f.curl:
        lines.extend(
            [
                "## Reproduce",
                "",
                "```sh",
                f.curl,
                "```",
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