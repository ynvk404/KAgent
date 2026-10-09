"""Explicit offline deployment maintenance; never called by discovery/dispatch.

First run npm ci --ignore-scripts --no-audit --no-fund outside the worker using
the reviewed package-lock.json, with a clean HOME/cache/npm configuration.
Then run this script with the installed tree and a new destination. It copies
only package.json, the lock and dependencies (no npm cache, HOME or .bin links).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat


def prepare(source: Path, destination: Path) -> str:
    source = source.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination already exists; explicit maintenance required')
    reviewed = Path(__file__).parent
    for name in ('package.json', 'package-lock.json'):
        if (source / name).read_bytes() != (reviewed / name).read_bytes():
            raise ValueError('installed tree must use the reviewed package and lock')
    package = json.loads((source / 'node_modules/@browsermcp/mcp/package.json').read_bytes())
    if (package['name'] != '@browsermcp/mcp' or package['version'] != '0.1.3'
            or package['bin'] != {'mcp-server-browsermcp': 'dist/index.js'}):
        raise ValueError('unexpected Browser MCP package identity')
    destination.mkdir(parents=True)
    for name in ('package.json', 'package-lock.json'):
        shutil.copyfile(source / name, destination / name)
    shutil.copytree(source / 'node_modules', destination / 'node_modules',
                    ignore=shutil.ignore_patterns('.bin', '.package-lock.json'), symlinks=True)
    entries: dict[str, str | None] = {}
    for path in sorted(destination.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[path.relative_to(destination).as_posix()] = None
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entries[path.relative_to(destination).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            raise ValueError('only regular files and directories are supported')
    manifest = json.dumps({'schema': 1, 'package': '@browsermcp/mcp', 'version': '0.1.3',
                           'entries': entries}, sort_keys=True, separators=(',', ':')).encode()
    (destination / 'manifest.json').write_bytes(manifest)
    return hashlib.sha256(manifest).hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(prepare(args.source, args.destination))
