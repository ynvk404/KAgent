"""Fail-closed scenario isolation, explicitly reused by the checkpoint plugin."""
from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from tests.helpers.scenarios import ScenarioRunner

REPO = Path(__file__).resolve().parents[2]


class OfflineBoundaryError(RuntimeError):
    pass


def _offline_scenario(tmp_path, monkeypatch, *, allowed_root=None):
    scratch = (allowed_root or tmp_path).resolve()
    assert tmp_path.resolve().is_relative_to(scratch)
    violations = []

    def deny(kind):
        def blocked(*args, **kwargs):
            violations.append(kind)
            raise OfflineBoundaryError(f"M1 offline boundary: {kind}")
        return blocked

    original_socket = socket.socket

    class OfflineSocket(original_socket):
        def __init__(self, family=socket.AF_INET, *args, **kwargs):
            if family != socket.AF_UNIX:
                deny("IPv4/IPv6 socket")()
            super().__init__(family, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", OfflineSocket)
    # Also deny connection methods on socket objects made before the guard.
    # asyncio's Unix socketpair needs neither bind/connect nor subprocesses.
    for name in ("connect", "connect_ex", "bind", "listen", "sendto", "sendmsg"):
        if hasattr(original_socket, name):
            monkeypatch.setattr(original_socket, name, deny("socket connection"))
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        monkeypatch.setattr(socket, name, deny("DNS"))
    monkeypatch.setattr(socket, "create_connection", deny("network connection"))
    monkeypatch.setattr(subprocess, "Popen", deny("subprocess"))
    for name in ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
                 "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
                 "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, deny("process launch"))

    # Resolve all production stores into scratch without changing HOME or
    # CODEX_HOME. Catch durable-state reads and accidental writes as well.
    import src.paths as paths
    original_user_root = paths.user_data_root
    for module in tuple(sys.modules.values()):
        if module and getattr(module, "__name__", "").startswith("src."):
            if getattr(module, "user_data_root", None) is original_user_root:
                monkeypatch.setattr(module, "user_data_root", lambda *a, **kw: tmp_path / "user/.kagent")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
    monkeypatch.delenv("KAgent_TRACE_AGENT", raising=False)

    def check_file(file, write=False):
        if isinstance(file, (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(file)).resolve()
            if not path.is_relative_to(scratch):
                durable = ".kagent" in path.parts or path.is_relative_to(REPO / "artifacts")
                if write or durable:
                    deny("outside scratch data")()

    real_open, real_io_open, real_os_open = builtins.open, io.open, os.open

    def guarded_open(file, mode="r", *args, **kwargs):
        check_file(file, any(c in mode for c in "wax+"))
        return real_open(file, mode, *args, **kwargs)

    def guarded_io_open(file, mode="r", *args, **kwargs):
        check_file(file, any(c in mode for c in "wax+"))
        return real_io_open(file, mode, *args, **kwargs)

    def guarded_os_open(file, flags, *args, **kwargs):
        check_file(file, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
        return real_os_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_io_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    yield violations
    assert not violations, "unexpected offline effects (including swallowed errors): " + repr(violations)


@pytest.fixture(autouse=True)
def offline_scenario(tmp_path):
    # Independent patch owner: a legacy test's monkeypatch.undo() cannot
    # uninstall fail-closed isolation. Faults use their own scoped contexts.
    guard = pytest.MonkeyPatch()
    try:
        yield from _offline_scenario(tmp_path, guard)
    finally:
        guard.undo()


@pytest.fixture
def scenario_runner(tmp_path, monkeypatch):
    return ScenarioRunner(tmp_path, monkeypatch)
