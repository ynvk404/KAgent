"""Reviewed Browser MCP launch; the root-owned deployment uses existing /usr RO bind.

The manifest digest is a controller trust anchor, never read from user/model
configuration. Changing dependencies requires explicit external maintenance and
review of the new lock/inventory. Runtime never invokes npm or downloads files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

BROWSER_MCP_VERSION = '0.1.3'
BROWSER_MCP_ROOT = Path('/usr/local/lib/kagent-browser-mcp') / BROWSER_MCP_VERSION
BROWSER_MCP_COMMAND = '/usr/bin/node'
BROWSER_MCP_ARGS = (str(BROWSER_MCP_ROOT / 'node_modules/@browsermcp/mcp/dist/index.js'),)
BROWSER_MCP_MANIFEST_SHA256 = '19bd4d4fa3b8454b54c4ebb8fa571f4ce23bdf31a94f8439ecb43f9916bb3a8b'
BROWSER_MCP_ADDRESS_SPACE = 1536 * 1024**2
BROWSER_LOCAL_PATCH = 'kagent-local-v3'
BROWSER_LOCAL_ROOT = BROWSER_MCP_ROOT.with_name(BROWSER_MCP_VERSION + '-' + BROWSER_LOCAL_PATCH)
BROWSER_LOCAL_ARGS = (str(BROWSER_LOCAL_ROOT / 'node_modules/@browsermcp/mcp/dist/index.js'),)
BROWSER_LOCAL_MANIFEST_SHA256 = '787b6f16b5b776f9f182df79041fee37cd0f0f351f0ef69a1ebd1d15ab4a2ae1'
BROWSER_NODE_SHA256 = 'd0efb6fcb9d023ba4e2b160ec2384dc28fe4f17732141ef47f676828fa960505'
BROWSER_LIMITER = '/usr/bin/prlimit'
BROWSER_LIMITER_SHA256 = 'cb28811cb3902773c1a0f3ac0ea554c7a1e232724e9d4cae055ede54b65a7bc4'


def _has_immutable_owner(info: os.stat_result) -> bool:
    return info.st_uid == 0 and not info.st_mode & 0o022


def is_designated_browser_server(server: Any) -> bool:
    return (server.name in {'browser', 'browser-mcp'} and server.command == BROWSER_MCP_COMMAND
            and tuple(server.args) == BROWSER_MCP_ARGS and not server.env)


def is_designated_browser_local(server: Any) -> bool:
    return (server is not None and server.name == 'browser' and server.command == BROWSER_MCP_COMMAND
            and tuple(server.args) == BROWSER_LOCAL_ARGS and not server.env)


def verify_browser_local_deployment(checkpoint=lambda: None) -> None:
    from src.permission.runtime.execution import ExecutionBlocked
    if sys.platform != 'linux':
        raise ExecutionBlocked('blocked: Browser trusted-local requires Linux/WSL2')
    _verify_tree(BROWSER_LOCAL_ROOT, BROWSER_LOCAL_MANIFEST_SHA256, BROWSER_LOCAL_PATCH, checkpoint)
    for executable, digest in ((Path(BROWSER_MCP_COMMAND), BROWSER_NODE_SHA256),
                               (Path(BROWSER_LIMITER), BROWSER_LIMITER_SHA256)):
        checkpoint()
        try:
            info = executable.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _has_immutable_owner(info)
                    or executable.resolve(strict=True) != executable
                    or hashlib.sha256(executable.read_bytes()).hexdigest() != digest):
                raise ValueError('executable identity changed')
            for parent in executable.parents:
                if not _has_immutable_owner(parent.lstat()):
                    raise ValueError('executable directory mutable')
        except (OSError, ValueError) as exc:
            raise ExecutionBlocked('blocked: unverified Browser Node/resource limiter; external review required') from exc


def verify_browser_deployment(checkpoint=lambda: None) -> None:
    """Verify the complete pinned closure before *every* isolated server launch.

No symlinks, hardlinks, host IPC, extra files, mutable directories or self-signed
inventory. Root ownership closes the verify/launch mutation window against
unprivileged controller/tools; OS administrator changes are outside that trust
boundary, as for the existing /usr executables.
"""
    _verify_tree(BROWSER_MCP_ROOT, BROWSER_MCP_MANIFEST_SHA256, None, checkpoint)


def _verify_tree(root: Path, anchor: str, patch: str | None, checkpoint) -> None:
    from src.permission.runtime.execution import ExecutionBlocked

    def trusted(path: Path) -> os.stat_result:
        info = path.lstat()
        if (not _has_immutable_owner(info)
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise ValueError('mutable/linked/special deployment entry')
        return info

    def fingerprint(path: Path, cap: int) -> tuple[bytes, str]:
        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        before = trusted(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise ValueError('deployment file size/type')
        digest = hashlib.sha256()
        data = bytearray()
        size = 0
        with path.open('rb') as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError('deployment changed during open')
            while chunk := stream.read(1024 * 1024):
                checkpoint()
                size += len(chunk)
                if size > cap:
                    raise ValueError('deployment file grew beyond size cap')
                digest.update(chunk)
                if cap <= 1024 * 1024:
                    data.extend(chunk)
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError('deployment changed during inspection')
        return bytes(data), digest.hexdigest()

    try:
        checkpoint()
        if root.resolve(strict=True) != root:
            raise ValueError('noncanonical deployment root')
        for ancestor in (root, *root.parents):
            trusted(ancestor)
        manifest_bytes, digest = fingerprint(root / 'manifest.json', 1024 * 1024)
        if digest != anchor:
            raise ValueError('unreviewed deployment manifest')
        manifest = json.loads(manifest_bytes)
        if (set(manifest) != ({'schema', 'package', 'version', 'entries', 'patch'} if patch else {'schema', 'package', 'version', 'entries'})
                or manifest['schema'] != (2 if patch else 1) or manifest.get('patch') != patch
                or manifest['package'] != '@browsermcp/mcp'
                or manifest['version'] != BROWSER_MCP_VERSION
                or not isinstance(manifest['entries'], dict) or len(manifest['entries']) > 20000):
            raise ValueError('invalid deployment inventory')
        entries = manifest['entries']
        seen = set()
        total = 0

        def walk_error(error: OSError) -> None:
            raise error

        for directory, folders, files in os.walk(root, followlinks=False, onerror=walk_error):
            checkpoint()
            for name in [*folders, *files]:
                item = Path(directory) / name
                key = item.relative_to(root).as_posix()
                if key == 'manifest.json':
                    continue
                if key not in entries:
                    raise ValueError('unexpected dependency entry')
                seen.add(key)
                info = trusted(item)
                if stat.S_ISDIR(info.st_mode):
                    if entries[key] is not None:
                        raise ValueError('dependency directory changed')
                else:
                    total += info.st_size
                    if total > 256 * 1024**2:
                        raise ValueError('deployment total size')
                    if fingerprint(item, 64 * 1024**2)[1] != entries[key]:
                        raise ValueError('dependency modified')
        if seen != set(entries):
            raise ValueError('missing dependency')
    except ExecutionBlocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise ExecutionBlocked('blocked: missing/stale/unsafe pinned Browser MCP deployment; '
                               'explicit external preparation required') from error
