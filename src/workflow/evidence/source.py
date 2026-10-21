"""Descriptor-bound proof reads; pathname checks are not read authority.

Proof sources must be regular single-link files. Stable aliases resolving inside
the project are bound before review; actual opens never traverse symlinks.
Open directories pin the authorized
namespace; edge checks reject renames/replacements before read and adoption.
This does not attempt to isolate a malicious process with the controller's UID.
"""
from __future__ import annotations

from contextlib import contextmanager, asynccontextmanager
import os
import io
from pathlib import Path
import stat
from src.async_io import run_sync


@asynccontextmanager
async def bind_source(path: Path, root: Path):
    # Retain the descriptor even if cancellation races worker completion.
    owned: list[EvidenceSource] = []
    def bind():
        binding = EvidenceSource(path, root)
        owned.append(binding)
        return binding
    try:
        yield await run_sync(bind)
    finally:
        if owned:
            await run_sync(owned[0].close)


def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def file_version(info: os.stat_result) -> tuple[int, ...]:
    return (*identity(info), info.st_mode, info.st_nlink,
            info.st_mtime_ns, info.st_ctime_ns)


def namespace_version(info: os.stat_result) -> tuple[int, ...]:
    return (*identity(info), info.st_mode) if stat.S_ISDIR(info.st_mode) else file_version(info)


class EvidenceSource:
    def __init__(self, path: Path, root: Path):
        requested = Path(os.path.abspath(path))
        self.path = requested.resolve()
        self.root = root.resolve()
        if not self.path.is_relative_to(self.root):
            raise ValueError('evidence path must stay inside the project')
        self.fds: list[int] = []
        self.names: list[str] = []
        self.resource_fd: int | None = None
        self.aliases = [(p, namespace_version(p.lstat())) for p in (*requested.parents, requested)
                        if p.is_relative_to(self.root)] if requested != self.path else []
        try:
            if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
                raise ValueError('descriptor-bound evidence capture unavailable on this platform')
            # O_PATH pins searchable directories without adding a directory
            # listing permission requirement to an otherwise valid file read.
            directory_flags = getattr(os, 'O_PATH', os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open('/', directory_flags)
            self.fds.append(fd)
            for name in self.path.parts[1:-1]:
                fd = os.open(name, directory_flags, dir_fd=fd)
                self.names.append(name)
                self.fds.append(fd)
            info = os.stat(self.path.name, dir_fd=fd, follow_symlinks=False)
            self._regular(info)
            # Pin the authorized inode before review as well as its namespace.
            # O_PATH grants no content read and prevents inode reuse while a
            # permission prompt is pending. The later read fd must match it.
            self.resource_fd = os.open(self.path.name,
                getattr(os, 'O_PATH', os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            pinned = os.fstat(self.resource_fd)
            self._regular(pinned)
            if file_version(pinned) != file_version(info):
                raise ValueError('evidence source changed during binding')
            self.version = file_version(pinned)
            self.validate()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _regular(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('evidence source must be a regular single-link file without symlinks')

    def validate(self) -> None:
        if not self.fds or self.resource_fd is None:
            raise ValueError('evidence source binding closed')
        for path, version in self.aliases:
            if namespace_version(path.lstat()) != version:
                raise ValueError('evidence source alias changed during capture')
        if self.aliases and self.aliases[-1][0].resolve() != self.path:
            raise ValueError('evidence source alias changed during capture')
        for parent, child, name in zip(self.fds, self.fds[1:], self.names):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or identity(info) != identity(os.fstat(child)):
                raise ValueError('evidence source namespace changed during capture')
        info = os.stat(self.path.name, dir_fd=self.fds[-1], follow_symlinks=False)
        self._regular(info)
        if file_version(info) != self.version:
            raise ValueError('evidence source changed during capture')
        if file_version(os.fstat(self.resource_fd)) != self.version:
            raise ValueError('authorized evidence inode changed during capture')

    @contextmanager
    def open(self):
        self.validate()
        fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=self.fds[-1])
        try:
            info = os.fstat(fd)
            self._regular(info)
            if file_version(info) != self.version:
                raise ValueError('evidence source changed during capture')
            self.validate()
            handle = io.FileIO(fd, 'rb', closefd=True)
        except BaseException:
            os.close(fd)
            raise
        with handle:
            yield handle
            self.validate()

    def close(self) -> None:
        if self.resource_fd is not None:
            os.close(self.resource_fd)
            self.resource_fd = None
        while self.fds:
            os.close(self.fds.pop())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
