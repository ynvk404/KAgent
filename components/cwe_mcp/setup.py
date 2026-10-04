"""Explicit setup-time acquisition/package build; never called by runtime."""
from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from .contract import ZIP_SHA256, XML_SHA256, XML_BYTES

ZIP_URL = 'https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip'
XSD_URL = 'https://cwe.mitre.org/data/xsd/cwe_schema_v7.3.xsd'
TERMS_URL = 'https://cwe.mitre.org/about/termsofuse.html'

def acquire(url, bound):
    with urllib.request.urlopen(url, timeout=60) as stream:
        data = stream.read(bound + 1)
    if len(data) > bound:
        raise ValueError('acquisition size bound exceeded')
    return data

def build(destination: Path, *, acquisition: Path | None = None):
    if destination.exists():
        raise ValueError('destination already exists; never overwrite deployment')
    archive = (acquisition / 'cwec_v4.20.xml.zip').read_bytes() if acquisition else acquire(ZIP_URL, XML_BYTES)
    if hashlib.sha256(archive).hexdigest() != ZIP_SHA256:
        raise ValueError('ZIP fingerprint mismatch; expected hash unchanged')
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        if zipped.namelist() != ['cwec_v4.20.xml'] or zipped.getinfo('cwec_v4.20.xml').file_size > XML_BYTES:
            raise ValueError('unexpected ZIP member')
        xml = zipped.read('cwec_v4.20.xml')
    if hashlib.sha256(xml).hexdigest() != XML_SHA256:
        raise ValueError('XML fingerprint mismatch; expected hash unchanged')
    xsd = (acquisition / 'cwe_schema_v7.3.xsd').read_bytes() if acquisition else acquire(XSD_URL, 1024 * 1024)
    terms = ((acquisition / 'CWE-TERMS-OF-USE.html').read_bytes()
             if acquisition and (acquisition / 'CWE-TERMS-OF-USE.html').exists()
             else acquire(TERMS_URL, 1024 * 1024))
    source = Path(__file__).parent
    destination.mkdir(parents=True)
    (destination / 'corpus').mkdir()
    (destination / 'corpus/cwec_v4.20.xml').write_bytes(xml)
    (destination / 'corpus/cwe_schema_v7.3.xsd').write_bytes(xsd)
    # Keep MITRE's copyright designation and complete license with this copy.
    # The adapter never reads this file or visits its links at runtime.
    (destination / 'corpus/CWE-TERMS-OF-USE.html').write_bytes(terms)
    shutil.copy2(source / 'launch.py', destination / 'launch.py')
    shutil.copy2(source / 'manifest.json', destination / 'manifest.json')
    package = destination / 'server/cwe_mcp'
    package.mkdir(parents=True)
    for name in ('__init__.py', 'contract.py', 'catalog.py', 'server.py'):
        shutil.copy2(source / name, package / name)
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-compile', '--only-binary=:all:',
                    '--target', str(destination / 'runtime'), 'mcp==1.28.1'], check=True)
    # Target installs may create launcher scripts referring to the host env;
    # runtime uses only imports through launch.py and /usr/bin/python3.
    print(f'Built {destination}; mcp==1.28.1; XML SHA-256={XML_SHA256}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    parser.add_argument('--acquisition', type=Path)
    options = parser.parse_args()
    build(options.destination, acquisition=options.acquisition)
