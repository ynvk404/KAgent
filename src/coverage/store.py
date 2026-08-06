from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from src.logger.logger import get_logger

log = get_logger("coverage.store")

CoverageStatus = Literal[
    "tried",
    "passed",
    "failed",
    "waf-blocked",
    "skipped",
]

MAX_ENTRIES = 5000

STORE_DIR_MODE = 0o700
STORE_FILE_MODE = 0o600


@dataclass
class CoverageEntry:
    endpoint: str
    param: str
    vulnClass: str
    status: CoverageStatus
    count: int
    firstSeen: int
    lastSeen: int
    notes: str | None = None


@dataclass
class CoverageSummary:
    total: int
    byStatus: dict[CoverageStatus, int]
    byVulnClass: dict[str, int]


class CoverageStore:
    def __init__(self, path: str):
        self.path = Path(path).resolve()

        self.entries: dict[str, CoverageEntry] = {}

        self.loaded = False
        self.load_task: asyncio.Task | None = None

        self.dirty = False
        self.saving: asyncio.Task | None = None

        self.last_save_error: Exception | None = None

    async def load(self) -> None:
        if self.loaded:
            return

        if self.load_task is None:
            self.load_task = asyncio.create_task(
                self._do_load()
            )

        await self.load_task

    async def _do_load(self) -> None:
        if self.path.exists():
            try:
                self.entries = self._parse(
                    self.path.read_text(
                        encoding="utf8"
                    )
                )

            except Exception:
                log.warning(
                    "coverage: unreadable store %s; quarantining it and "
                    "starting from an empty store",
                    self.path,
                    exc_info=True,
                )
                self._quarantine()

        self.loaded = True

    @staticmethod
    def _parse(raw: str) -> dict[str, CoverageEntry]:
        parsed = json.loads(raw)

        entries: dict[str, CoverageEntry] = {}

        if (
            parsed.get("version") == 1
            and isinstance(
                parsed.get("entries"),
                list,
            )
        ):
            for item in parsed["entries"]:
                if _is_valid_entry(item):
                    entry = CoverageEntry(**item)
                    entries[
                        _key_of(
                            entry.endpoint,
                            entry.param,
                            entry.vulnClass,
                        )
                    ] = entry

        return entries

    def _quarantine(self) -> None:
        """Move an unusable store aside so the next save cannot destroy it."""
        backup = self.path.with_suffix(
            self.path.suffix + f".corrupt.{secrets.token_hex(3)}"
        )

        try:
            self.path.replace(backup)
            log.warning("coverage: previous store kept at %s", backup)

        except OSError:
            log.warning(
                "coverage: could not quarantine %s; it will be overwritten "
                "on the next save",
                self.path,
                exc_info=True,
            )

    async def mark(
        self,
        *,
        endpoint: str,
        param: str,
        vulnClass: str,
        status: CoverageStatus,
        notes: str | None = None,
    ) -> CoverageEntry:

        await self.load()

        endpoint = _normalize_endpoint(endpoint)
        param = param.strip()
        vulnClass = vulnClass.strip().lower()

        if not endpoint or not param or not vulnClass:
            raise ValueError(
                "mark: endpoint, param, and vulnClass are all required"
            )

        key = _key_of(
            endpoint,
            param,
            vulnClass,
        )

        now = int(time.time() * 1000)

        prev = self.entries.get(key)

        merged = CoverageEntry(
            endpoint=endpoint,
            param=param,
            vulnClass=vulnClass,
            status=status,
            count=(prev.count if prev else 0) + 1,
            firstSeen=prev.firstSeen if prev else now,
            lastSeen=now,
            notes=notes if notes is not None else (prev.notes if prev else None),
        )

        self.entries[key] = merged

        self._evict_if_needed()

        self._queue_save()

        return merged

    async def list(
        self,
        *,
        endpoint: str | None = None,
        param: str | None = None,
        vulnClass: str | None = None,
        status: CoverageStatus | None = None,
    ) -> list[CoverageEntry]:

        await self.load()

        rows = sorted(
            self.entries.values(),
            key=lambda e: e.lastSeen,
        )

        result = []

        for e in rows:

            if endpoint and endpoint not in e.endpoint:
                continue

            if param and e.param != param:
                continue

            if vulnClass and e.vulnClass != vulnClass.lower():
                continue

            if status and e.status != status:
                continue

            result.append(e)

        return result


    async def untested(
        self,
        candidates: list[dict[str, str]],
        vulnClasses: list[str],
    ) -> list[dict[str, str]]:

        await self.load()

        out: list[dict[str, str]] = []

        for candidate in candidates:

            ep = _normalize_endpoint(
                candidate["endpoint"]
            )

            param = candidate["param"]

            for vuln in vulnClasses:

                vuln = vuln.lower()

                key = _key_of(
                    ep,
                    param,
                    vuln,
                )

                if key not in self.entries:
                    out.append(
                        {
                            "endpoint": ep,
                            "param": param,
                            "vulnClass": vuln,
                        }
                    )

        return out


    async def summary(self) -> CoverageSummary:

        await self.load()

        by_status: dict[CoverageStatus, int] = {
            "tried": 0,
            "passed": 0,
            "failed": 0,
            "waf-blocked": 0,
            "skipped": 0,
        }

        by_vuln: dict[str, int] = {}

        for entry in self.entries.values():

            by_status[entry.status] += 1

            by_vuln[entry.vulnClass] = (
                by_vuln.get(
                    entry.vulnClass,
                    0,
                )
                + 1
            )

        return CoverageSummary(
            total=len(self.entries),
            byStatus=by_status,
            byVulnClass=by_vuln,
        )


    async def clear(self):

        await self.load()

        self.entries.clear()

        self._queue_save()


    async def flush(self):

        while self.saving:
            await self.saving


    def _evict_if_needed(self):

        if len(self.entries) <= MAX_ENTRIES:
            return

        ordered = sorted(
            self.entries.items(),
            key=lambda x: x[1].lastSeen,
        )

        drop = len(self.entries) - MAX_ENTRIES

        for key, _ in ordered[:drop]:
            self.entries.pop(key, None)

    def _queue_save(self):

        self.dirty = True

        if self.saving:
            return

        self.saving = asyncio.create_task(
            self._run_save_loop()
        )

    async def _run_save_loop(self):

        while self.dirty:

            self.dirty = False

            try:
                await self._persist()
                self.last_save_error = None

            except Exception as exc:
                self.last_save_error = exc
                log.error(
                    "coverage: failed to persist store to %s",
                    self.path,
                    exc_info=True,
                )

        self.saving = None

    async def _persist(self):

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=STORE_DIR_MODE,
        )

        payload = {
            "version": 1,
            "entries": [
                asdict(e)
                for e in self.entries.values()
            ],
        }

        tmp = self.path.with_suffix(
            self.path.suffix
            + f".tmp.{secrets.token_hex(3)}"
        )

        try:
            tmp.write_text(
                json.dumps(
                    payload,
                    indent=2,
                )
                + "\n",
                encoding="utf8",

        tmp.touch(mode=STORE_FILE_MODE)

        tmp.write_text(
            json.dumps(
                payload,
                indent=2,
            )

            tmp.replace(self.path)

        except Exception:
            tmp.unlink(missing_ok=True)
            raise

def _key_of(
    endpoint: str,
    param: str,
    vulnClass: str,
) -> str:

    return (
        f"{endpoint}\0"
        f"{param}\0"
        f"{vulnClass}"
    )


def _normalize_endpoint(
    endpoint: str,
) -> str:

    endpoint = endpoint.strip()

    index = endpoint.find("?")

    if index >= 0:
        return endpoint[:index]

    return endpoint


def _is_valid_entry(
    value,
) -> bool:

    if not isinstance(value, dict):
        return False

    required = (
        "endpoint",
        "param",
        "vulnClass",
        "status",
        "count",
        "firstSeen",
        "lastSeen",
    )

    return all(
        key in value
        for key in required
    )