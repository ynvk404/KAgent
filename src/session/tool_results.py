"""Private, scoped retention of sanitized tool text. Never validation evidence.

Writes are bounded synchronous transactions: cancellation cannot leave an
offloaded writer running after its caller has fallen back to inline output.
Unsupported filesystem security primitives disable the optimization.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Callable
import uuid

REF_PATTERN = re.compile(r"tr_[0-9a-f]{32}\Z")
PER_RESULT_BYTES = 1024 * 1024
PER_SESSION_BYTES = 16 * 1024 * 1024
# Also bounds the structured continuation index, independently of payload size.
MAX_RESULTS = 32
MAX_READ_CHARS = 2000
MAX_HEADER_BYTES = 8192


class ResultUnavailable(ValueError):
    """Safe error text: never include content, paths, or underlying exceptions."""


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def valid_ref(value: Any) -> bool:
    return isinstance(value, str) and REF_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ResultReference:
    result_ref: str
    sha256: str
    byte_length: int
    char_length: int
    tool_name: str
    tool_call_id: str
    status: str
    error_kind: str | None
    http_status: int | None
    truncated: bool
    source_kind: str
    provenance_sha256: str

    @classmethod
    def from_dict(cls, raw: Any) -> ResultReference | None:
        if not isinstance(raw, dict):
            return None
        try:
            ref = cls(**raw)
        except TypeError:
            return None
        if (not valid_ref(ref.result_ref)
                or not isinstance(ref.sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", ref.sha256) is None
                or not isinstance(ref.provenance_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", ref.provenance_sha256) is None
                or any(type(n) is not int or not 0 <= n <= PER_RESULT_BYTES
                       for n in (ref.byte_length, ref.char_length))
                or not isinstance(ref.tool_name, str) or len(ref.tool_name) > 128
                or not isinstance(ref.tool_call_id, str) or len(ref.tool_call_id) > 256
                or not isinstance(ref.status, str) or ref.status not in {"success", "observation"}
                or ref.error_kind is not None
                or (ref.http_status is not None and type(ref.http_status) is not int)
                or type(ref.truncated) is not bool
                or not isinstance(ref.source_kind, str)
                or ref.source_kind not in {"shell", "http", "research", "file"}):
            return None
        return ref


def load_references(raw: Any) -> list[ResultReference]:
    if not isinstance(raw, list) or len(raw) > MAX_RESULTS:
        return []
    return [ref for item in raw if (ref := ResultReference.from_dict(item)) is not None]


class ToolResultStore:
    def __init__(self, project: Path, session_id: str, *,
                 per_result: int = PER_RESULT_BYTES, per_session: int = PER_SESSION_BYTES,
                 max_results: int = MAX_RESULTS):
        self.project = project.resolve()
        self.project_id = digest_text(str(self.project))
        self.session_id = digest_text(session_id)
        self.per_result = min(per_result, PER_RESULT_BYTES)
        self.per_session = per_session
        self.max_results = min(max_results, MAX_RESULTS)
        self._project_inode = self._inode(self.project.stat())
        self._pinned: dict[str, tuple[int, int]] = {}
        self._mutex = threading.RLock()

    @staticmethod
    def _inode(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    @contextmanager
    def _directory(self):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ResultUnavailable("tool result storage unavailable on this filesystem")
        import fcntl
        descriptors: list[int] = []
        lock = None
        with self._mutex:
            try:
                # Open every component without following symbolic links.
                fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                descriptors.append(fd)
                components = [*self.project.parts[1:], ".kagent", "tool-results", self.session_id]
                for part in self.project.parts[1:]:
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    descriptors.append(fd)
                if self._inode(os.fstat(fd)) != self._project_inode:
                    raise ResultUnavailable("tool result project binding changed")
                for part in (".kagent", "tool-results", self.session_id):
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    descriptors.append(fd)
                    info = os.fstat(fd)
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise ResultUnavailable("tool result directory ownership/permissions invalid")
                    if part != ".kagent":
                        os.fchmod(fd, 0o700)
                        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                            raise ResultUnavailable("tool result private directory unavailable")
                    inode = self._inode(info)
                    if self._pinned.setdefault(part, inode) != inode:
                        raise ResultUnavailable("tool result directory binding changed")
                # The serialization domain is the held session-directory inode,
                # not a replaceable .lock pathname. All instances/processes
                # using this directory remain serialized across lock replacement.
                fcntl.flock(fd, fcntl.LOCK_EX)
                lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                               0o600, dir_fd=fd)
                self._private_file(os.fstat(lock))

                def validate_binding() -> None:
                    # Verify every canonical edge from / through project and
                    # storage. Detached descriptors alone cannot prove binding.
                    for parent, child, name in zip(descriptors, descriptors[1:], components):
                        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if self._inode(current) != self._inode(os.fstat(child)) or not stat.S_ISDIR(current.st_mode):
                            raise ResultUnavailable("tool result directory binding changed")
                    for index, directory in enumerate(descriptors[-3:]):
                        info = os.fstat(directory)
                        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                            raise ResultUnavailable("tool result directory ownership/permissions invalid")
                        if index > 0 and stat.S_IMODE(info.st_mode) != 0o700:
                            raise ResultUnavailable("tool result private directory unavailable")
                    assert lock is not None
                    held = os.fstat(lock)
                    current = os.stat(".lock", dir_fd=fd, follow_symlinks=False)
                    self._private_file(held)
                    self._private_file(current)
                    if self._inode(current) != self._inode(held):
                        raise ResultUnavailable("tool result lock binding changed")

                validate_binding()
                yield fd, validate_binding
            except OSError:
                raise ResultUnavailable("tool result storage unavailable") from None
            finally:
                if lock is not None:
                    os.close(lock)
                for opened in reversed(descriptors):
                    os.close(opened)

    @staticmethod
    def _private_file(info: os.stat_result) -> None:
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ResultUnavailable("tool result file ownership/permissions invalid")

    def put(self, text: str, *, generation: str, provenance: dict[str, Any],
            tool_name: str, tool_call_id: str, status: str, error_kind: str | None,
            http_status: int | None, truncated: bool,
            check_cancelled: Callable[[], None] = lambda: None) -> ResultReference | None:
        """Accept only the controller's sanitized representation, never process bytes."""
        payload = text.encode("utf-8")
        if not payload or len(payload) > self.per_result:
            return None
        ref = ResultReference("tr_" + uuid.uuid4().hex, hashlib.sha256(payload).hexdigest(),
                              len(payload), len(text), tool_name, tool_call_id, status,
                              error_kind, http_status, truncated, provenance["kind"],
                              digest_text(json.dumps(provenance, sort_keys=True, separators=(",", ":"))))
        if ResultReference.from_dict(asdict(ref)) is None:
            return None
        header = {"reference": asdict(ref), "project": self.project_id,
                  "session": self.session_id, "generation": generation,
                  "provenance": provenance}
        metadata = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        if len(metadata) > MAX_HEADER_BYTES:
            return None
        encoded = metadata + payload
        if len(encoded) > self.per_result:
            return None
        with self._directory() as (fd, validate_binding):
            entries = [name for name in os.listdir(fd) if name.endswith(".result")]
            used = sum(os.stat(name, dir_fd=fd, follow_symlinks=False).st_size for name in entries)
            if len(entries) >= self.max_results or used + len(encoded) > self.per_session:
                return None
            temporary = ".tmp-" + uuid.uuid4().hex
            filename = ref.result_ref + ".result"
            created = False
            published = False
            output_inode = None

            def rollback(name: str) -> None:
                # Only remove this transaction's inode via the held directory;
                # never delete a substituted artifact belonging to another ref.
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    return
                if self._inode(info) == output_inode:
                    os.unlink(name, dir_fd=fd)

            try:
                check_cancelled()
                output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                created = True
                output_inode = self._inode(os.fstat(output))
                with os.fdopen(output, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                    self._private_file(os.fstat(stream.fileno()))
                    if self._inode(os.stat(temporary, dir_fd=fd, follow_symlinks=False)) != self._inode(os.fstat(stream.fileno())):
                        raise ResultUnavailable("tool result temporary file changed")
                    check_cancelled()
                    validate_binding()
                    # Atomic no-replace publication. Temporary link is removed
                    # before any reference can escape this transaction.
                    os.link(temporary, filename, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                    published = True
                    validate_binding()
                    os.unlink(temporary, dir_fd=fd)
                    created = False
                    validate_binding()
                    self._private_file(os.stat(filename, dir_fd=fd, follow_symlinks=False))
                    os.fsync(fd)
                    validate_binding()
                validate_binding()
                check_cancelled()
                return ref
            except BaseException:
                if published:
                    rollback(filename)
                raise
            finally:
                if created:
                    rollback(temporary)

    def provenance(self, ref: ResultReference, generation: str) -> dict[str, Any]:
        """Read only the bounded controller header before the sensitive read gate."""
        if ResultReference.from_dict(asdict(ref)) is None:
            raise ResultUnavailable("invalid tool result reference")
        with self._directory() as (fd, validate_binding):
            try:
                opened = os.open(ref.result_ref + ".result", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except FileNotFoundError:
                raise ResultUnavailable("tool result unavailable; preview remains usable; do not rerun the action") from None
            try:
                self._private_file(os.fstat(opened))
                # Unbuffered, delimiter-exact reads. A buffered readline can
                # prefetch protected payload before the sensitive-source gate.
                metadata = bytearray()
                for _ in range(MAX_HEADER_BYTES):
                    byte = os.read(opened, 1)
                    if not byte:
                        break
                    metadata.extend(byte)
                    if byte == b"\n":
                        break
                if not metadata.endswith(b"\n"):
                    raise ResultUnavailable("tool result header invalid")
                validate_binding()
            finally:
                os.close(opened)
        try:
            header = json.loads(metadata)
            if (header["reference"] != asdict(ref) or header["project"] != self.project_id
                    or header["session"] != self.session_id or header["generation"] != generation
                    or header["provenance"]["kind"] != ref.source_kind
                    or digest_text(json.dumps(header["provenance"], sort_keys=True, separators=(",", ":"))) != ref.provenance_sha256):
                raise ValueError
            return header["provenance"]
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ResultUnavailable("tool result integrity/scope mismatch") from None

    def resolve(self, ref: ResultReference, generation: str) -> tuple[str, dict[str, Any]]:
        if ResultReference.from_dict(asdict(ref)) is None:
            raise ResultUnavailable("invalid tool result reference")
        with self._directory() as (fd, validate_binding):
            try:
                opened = os.open(ref.result_ref + ".result", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except FileNotFoundError:
                raise ResultUnavailable("tool result unavailable; retained preview remains usable; do not rerun the action") from None
            with os.fdopen(opened, "rb") as stream:
                before = os.fstat(stream.fileno())
                self._private_file(before)
                if before.st_size > self.per_result:
                    raise ResultUnavailable("tool result integrity failure")
                encoded = stream.read(self.per_result + 1)
                after = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
                ):
                    raise ResultUnavailable("tool result changed during retrieval")
                self._private_file(after)
                validate_binding()
        try:
            metadata, payload = encoded.split(b"\n", 1)
            header = json.loads(metadata)
            text = payload.decode("utf-8")
            if (header["reference"] != asdict(ref) or header["project"] != self.project_id
                    or header["session"] != self.session_id or header["generation"] != generation
                    or len(payload) != ref.byte_length or len(text) != ref.char_length
                    or hashlib.sha256(payload).hexdigest() != ref.sha256
                    or digest_text(json.dumps(header["provenance"], sort_keys=True, separators=(",", ":"))) != ref.provenance_sha256
                    or header["provenance"]["kind"] != ref.source_kind):
                raise ValueError
            return text, header["provenance"]
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise ResultUnavailable("tool result integrity/scope mismatch") from None

    def cleanup(self, *, live_refs: set[str], saved_refs: set[str], stale_before: float) -> int:
        """Explicit controller maintenance only; caller must supply both reachability sets.

        Never run automatically on resume or quota pressure. Unknown/live
        sessions must be considered reachable by the caller.
        """
        removed = 0
        with self._directory() as (fd, validate_binding):
            validate_binding()
            for name in os.listdir(fd):
                ref = name.removesuffix(".result")
                if not (name.startswith(".tmp-") or (name.endswith(".result") and valid_ref(ref))):
                    continue
                if ref in live_refs | saved_refs:
                    continue
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if info.st_mtime >= stale_before:
                    continue
                self._private_file(info)
                os.unlink(name, dir_fd=fd)
                removed += 1
        return removed


def read_region(text: str, start_char: int, max_chars: int) -> dict[str, Any]:
    """Offsets count Python Unicode characters, never UTF-8 bytes."""
    start = min(len(text), max(0, start_char))
    end = min(len(text), start + min(MAX_READ_CHARS, max(0, max_chars)))
    return {"content": text[start:end], "actual_start": start, "actual_end": end,
            "total_length": len(text), "completeness": "complete" if end == len(text) else "partial",
            "next_offset": end if end < len(text) else None}
