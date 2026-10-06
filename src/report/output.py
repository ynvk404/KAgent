"""Private staging and descriptor-relative atomic no-replace publication."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from src.paths import project_artifact_root
from src.report.builder import open_directory
from src.report.model import MAX_PDF, ReportError
from src.tools.execution.sensitive import is_sensitive_path

FILENAME_ERROR = "Use /report [filename.pdf]; reports are saved under artifacts/reports/."
OUTPUT_ERROR = "Report output unavailable. Check artifacts/reports/ permissions, space and filesystem support."


def validate_filename(name: str) -> str:
    if (len(name.encode("utf-8", "replace")) > 100 or ".." in name or
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.pdf", name) is None):
        raise ReportError(FILENAME_ERROR)
    return name


def default_filename(session: str, objective: str, exported_at: str) -> str:
    def prefix(value: str, missing: str):
        # Presentation digest prefixes cannot leak operator-controlled IDs.
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12] if value else missing
    stamp = datetime.fromisoformat(exported_at.replace("Z", "+00:00")).strftime("%Y%m%dT%H%M%SZ")
    return f"kagent-report-{prefix(session, 'untracked')}-{prefix(objective, 'target')}-{stamp}.pdf"


def _directory(project: Path) -> tuple[Path, int]:
    directory = project_artifact_root(project) / "reports"
    if any(is_sensitive_path(str(p)) or is_sensitive_path(str(p.resolve())) for p in (project, directory)):
        raise ReportError(OUTPUT_ERROR)
    fd = open_directory(project)
    try:
        for component in ("artifacts", "reports"):
            try:
                os.mkdir(component, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return directory, fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(slots=True)
class StagedReport:
    directory: Path
    directory_fd: int
    name: str
    filename: str
    identity: tuple[int, int]
    size: int
    modified_at: int
    closed: bool = False

    def _remove_stage(self) -> None:
        try:
            current = os.stat(self.name, dir_fd=self.directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == self.identity:
                os.unlink(self.name, dir_fd=self.directory_fd)
        except FileNotFoundError:
            pass

    def cleanup(self) -> None:
        if self.closed:
            return
        try:
            self._remove_stage()
        finally:
            os.close(self.directory_fd)
            self.closed = True

    def publish(self) -> Path:
        """Called on controller only, after cancellation/assessment checks."""
        if self.closed:
            raise ReportError(OUTPUT_ERROR)
        final = None
        staged_fd = -1
        try:
            # Reopen all components to detect directory replacement/rename.
            current_fd = open_directory(self.directory)
            try:
                current, pinned = os.fstat(current_fd), os.fstat(self.directory_fd)
                if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                    raise ReportError(OUTPUT_ERROR)
            finally:
                os.close(current_fd)
            staged_fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory_fd)
            staged = os.fstat(staged_fd)
            if ((staged.st_dev, staged.st_ino) != self.identity or staged.st_nlink != 1 or
                not stat.S_ISREG(staged.st_mode) or (staged.st_size, staged.st_mtime_ns) != (self.size, self.modified_at)):
                raise ReportError(OUTPUT_ERROR)
            for index in range(1, 10_001):
                name = self.filename if index == 1 else f"{self.filename[:-4]}-{index}.pdf"
                try:
                    existing = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                if existing is not None and (not stat.S_ISREG(existing.st_mode)):
                    raise ReportError(OUTPUT_ERROR)
                try:
                    # Linux linkat follows this controller-authored proc fd
                    # reference, binding the verified inode even if its stage
                    # name is replaced. Unsupported primitives fail safely.
                    os.link(f"/proc/self/fd/{staged_fd}", name,
                            dst_dir_fd=self.directory_fd, follow_symlinks=True)
                except FileExistsError:
                    continue
                final = name
                check_fd = open_directory(self.directory)
                try:
                    check = os.fstat(check_fd)
                    if (check.st_dev, check.st_ino) != (pinned.st_dev, pinned.st_ino):
                        raise ReportError(OUTPUT_ERROR)
                finally:
                    os.close(check_fd)
                self._remove_stage()
                os.fsync(self.directory_fd)
                return self.directory / name
            raise ReportError("Report filename collision limit exceeded; choose another filename.")
        except BaseException:
            if final is not None:
                current = os.stat(final, dir_fd=self.directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == self.identity:
                    os.unlink(final, dir_fd=self.directory_fd)
            raise
        finally:
            if staged_fd >= 0:
                os.close(staged_fd)
            self.cleanup()


def stage_report(project: Path, filename: str, pdf: bytes) -> StagedReport:
    validate_filename(filename)
    if not pdf.startswith(b"%PDF-") or not 0 < len(pdf) <= MAX_PDF or not pdf.rstrip().endswith(b"%%EOF"):
        raise ReportError("Renderer did not produce a complete bounded PDF.")
    fd = -1
    name = ""
    directory_fd = -1
    identity = None
    try:
        directory, directory_fd = _directory(project)
        name = f".report-{secrets.token_hex(16)}.tmp"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        identity = os.fstat(fd)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(pdf)
            stream.flush()
            os.fsync(stream.fileno())
            identity = os.fstat(stream.fileno())
        return StagedReport(directory, directory_fd, name, filename, (identity.st_dev, identity.st_ino), identity.st_size, identity.st_mtime_ns)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if directory_fd >= 0:
            try:
                if name and identity is not None:
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                        os.unlink(name, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
        raise
