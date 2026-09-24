from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from src.logger.logger import get_logger
from src.logger.hang_diagnostics import HangDiagnostics
from src.skills.registry import normalize_candidate_class

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
    def __init__(
        self,
        path: str,
        diagnostics: HangDiagnostics | None = None,
        legacy_path: str | None = None,
    ):
        self.path = Path(path).resolve()
        self.legacy_path = Path(legacy_path).resolve() if legacy_path else None
        self.diagnostics = diagnostics

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
        source = self.path
        if (
            not source.exists()
            and self.legacy_path is not None
            and self.legacy_path.exists()
        ):
            source = self.legacy_path
        if source.exists():
            try:
                self.entries = self._parse(
                    source.read_text(
                        encoding="utf8"
                    )
                )

            except Exception:
                action = (
                    "quarantining it and starting from an empty store"
                    if source == self.path
                    else "ignoring legacy fallback and starting from an empty store"
                )
                log.warning(
                    "coverage: unreadable store %s; %s",
                    source,
                    action,
                    exc_info=True,
                )
                if source == self.path:
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
                    entry.endpoint = _normalize_endpoint(entry.endpoint)
                    entry.param = entry.param.strip()
                    entry.vulnClass = normalize_candidate_class(entry.vulnClass)
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
        suffix = secrets.token_hex(3)
        backup: Path | None = None
        for i in range(100):
            candidate_suffix = suffix if i == 0 else f"{suffix}-{i + 1}"
            candidate = self.path.with_suffix(
                self.path.suffix + f".corrupt.{candidate_suffix}"
            )
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    STORE_FILE_MODE,
                )
                os.close(fd)
                backup = candidate
                break
            except FileExistsError:
                continue
            except OSError:
                break

        if backup is None:
            log.warning("coverage: could not reserve a quarantine path for %s", self.path)
            return

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
            backup.unlink(missing_ok=True)

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
        vulnClass = normalize_candidate_class(vulnClass)

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

    async def ensure_validation_mark(
        self, *, endpoint: str, param: str, vulnClass: str,
        status: CoverageStatus, notes: str,
    ) -> CoverageEntry:
        """Persist one validation outcome without inflating retry counts."""
        await self.load()
        key = _key_of(
            _normalize_endpoint(endpoint), param.strip(),
            normalize_candidate_class(vulnClass),
        )
        existing = self.entries.get(key)
        if existing and existing.status == status and existing.notes == notes:
            if self.last_save_error is not None:
                self._queue_save()
        else:
            existing = await self.mark(
                endpoint=endpoint, param=param, vulnClass=vulnClass,
                status=status, notes=notes,
            )
        await self.flush()
        if self.last_save_error is not None:
            raise OSError("coverage store could not be persisted") from self.last_save_error
        return existing

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
            key=lambda e: (
                e.lastSeen,
                e.endpoint,
                e.param,
                e.vulnClass,
            ),
        )

        result = []

        for e in rows:

            if endpoint and endpoint not in e.endpoint:
                continue

            if param and e.param != param:
                continue

            if vulnClass and e.vulnClass != normalize_candidate_class(vulnClass):
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

        out: dict[tuple[str, str, str], dict[str, str]] = {}

        for candidate in candidates:

            ep = _normalize_endpoint(
                candidate["endpoint"]
            )

            param = candidate["param"].strip()

            if not ep or not param:
                continue

            for vuln in vulnClasses:

                vuln = normalize_candidate_class(vuln)

                if not vuln:
                    continue

                key = _key_of(
                    ep,
                    param,
                    vuln,
                )

                if key not in self.entries:
                    out[(ep, param, vuln)] = {
                        "endpoint": ep,
                        "param": param,
                        "vulnClass": vuln,
                    }

        return [out[key] for key in sorted(out)]


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
        while self.saving is not None:
            saving = self.saving
            await saving
            # A cancelled/failed save loop may exit before clearing its own
            # reference. Never spin synchronously on an already-finished task.
            if self.saving is saving:
                self.saving = None


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

        if self.saving is not None:
            if not self.saving.done():
                return
            self.saving = None

        saving = asyncio.create_task(
            self._run_save_loop()
        )
        self.saving = saving
        # Textual installs asyncio.eager_task_factory on supported Python
        # versions. The coroutine can therefore finish, clear self.saving,
        # and return from create_task() before this assignment occurs. Avoid
        # retaining that completed task, which would make flush() busy-loop.
        if saving.done():
            self.saving = None

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
        operation = "coverage.save"
        tmp: Path | None = None
        created_tmp = False
        try:
            self._stage(f"{operation}.mkdir")
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=STORE_DIR_MODE,
            )

            self._stage(f"{operation}.serialize")
            payload = {
                "version": 1,
                "entries": [
                    asdict(e)
                    for e in self.entries.values()
                ],
            }
            body = json.dumps(payload, indent=2) + "\n"

            tmp = self.path.with_suffix(
                self.path.suffix
                + f".tmp.{secrets.token_hex(3)}"
            )

            self._stage(f"{operation}.open_temp")
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                STORE_FILE_MODE,
            )
            created_tmp = True
            with os.fdopen(fd, "w", encoding="utf8") as f:
                self._stage(f"{operation}.write")
                f.write(body)

            self._stage(f"{operation}.replace")
            tmp.replace(self.path)

        except Exception:
            if created_tmp and tmp is not None:
                tmp.unlink(missing_ok=True)
            raise
        finally:
            self._clear_stage(operation)

    def _stage(self, stage: str) -> None:
        if self.diagnostics is not None:
            self.diagnostics.set_stage(stage)

    def _clear_stage(self, operation: str) -> None:
        if self.diagnostics is not None and self.diagnostics.stage.startswith(operation):
            self.diagnostics.set_stage("idle")


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

    if not all(key in value for key in required):
        return False

    return (
        all(
            isinstance(value[key], str) and value[key]
            for key in ("endpoint", "param", "vulnClass")
        )
        and isinstance(value["status"], str)
        and value["status"] in {
            "tried", "passed", "failed", "waf-blocked", "skipped",
        }
        and isinstance(value["count"], int)
        and not isinstance(value["count"], bool)
        and value["count"] > 0
        and all(
            isinstance(value[key], int)
            and not isinstance(value[key], bool)
            and value[key] >= 0
            for key in ("firstSeen", "lastSeen")
        )
        and (value.get("notes") is None or isinstance(value.get("notes"), str))
    )
