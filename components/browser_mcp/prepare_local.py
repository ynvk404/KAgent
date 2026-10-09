"""External maintenance: copy verified upstream closure into a NEW patched tree."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path

from patch_local import PATCH_ID, UPSTREAM_BUNDLE_SHA256, patch_bundle
from prepare import prepare

UPSTREAM_MANIFEST = '19bd4d4fa3b8454b54c4ebb8fa571f4ce23bdf31a94f8439ecb43f9916bb3a8b'


def prepare_local(source: Path, destination: Path) -> str:
    raw = (source / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != UPSTREAM_MANIFEST:
        raise ValueError('upstream inventory is not reviewed')
    inventory = json.loads(raw)['entries']
    actual = {p.relative_to(source).as_posix(): (
        None if p.is_dir() and not p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest()
    ) for p in source.rglob('*') if p.name != 'manifest.json'}
    if actual != inventory:
        raise ValueError('upstream tree changed')
    bundle_path = 'node_modules/@browsermcp/mcp/dist/index.js'
    upstream = (source / bundle_path).read_bytes()
    patched = patch_bundle(upstream)
    prepare(source, destination)
    (destination / bundle_path).write_bytes(patched)
    diff = ''.join(difflib.unified_diff(upstream.decode().splitlines(True), patched.decode().splitlines(True),
                                      fromfile='upstream/' + bundle_path, tofile=PATCH_ID + '/' + bundle_path))
    (destination / 'patch.diff').write_text(diff, encoding='utf-8')
    (destination / 'patch.json').write_text(json.dumps({
        'patch': PATCH_ID, 'upstream_version': '0.1.3', 'upstream_bundle_sha256': UPSTREAM_BUNDLE_SHA256,
        'patched_bundle_sha256': hashlib.sha256(patched).hexdigest(), 'changed_upstream_files': [bundle_path],
    }, sort_keys=True, separators=(',', ':')), encoding='utf-8')
    entries = {p.relative_to(destination).as_posix(): (
        None if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest()
    ) for p in sorted(destination.rglob('*')) if p.name != 'manifest.json'}
    manifest = json.dumps({'schema': 2, 'package': '@browsermcp/mcp', 'version': '0.1.3',
                           'patch': PATCH_ID, 'entries': entries}, sort_keys=True, separators=(',', ':')).encode()
    (destination / 'manifest.json').write_bytes(manifest)
    return hashlib.sha256(manifest).hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(prepare_local(args.source, args.destination))
