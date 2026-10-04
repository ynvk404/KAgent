import hashlib
import json
from pathlib import Path

import pytest

from components.cwe_mcp import catalog as module
from components.cwe_mcp.contract import EXPECTED_MANIFEST, NAMESPACE, SCHEMA_IDENTITY


def entry(ident, name='Missing Authorization', *, kind='Weakness', usage='Allowed', status='Stable',
          abstraction='Base', structure='Simple', description='Product misses authorization for a resource.',
          alternate='', notes=True):
    attributes = f'Abstraction="{abstraction}" Structure="{structure}"' if kind == 'Weakness' else ('Type="Graph"' if kind == 'View' else '')
    desc = {'Weakness': 'Description', 'Category': 'Summary', 'View': 'Objective'}[kind]
    guidance = (f'<Mapping_Notes><Usage>{usage}</Usage><Rationale>Suitable mechanism.</Rationale>'
                '<Comments>Review evidenced mechanism.</Comments><Reasons><Reason Type="Acceptable-Use"/>'
                '</Reasons><Suggestions><Suggestion CWE_ID="863" Comment="Review boundary"/></Suggestions></Mapping_Notes>') if notes else ''
    return (f'<{kind} ID="{ident}" Name="{name}" Status="{status}" {attributes}>'
            f'<{desc}>{description}</{desc}>'
            f'<Alternate_Terms><Alternate_Term><Term>{alternate}</Term></Alternate_Term></Alternate_Terms>'
            f'{guidance}</{kind}>')


def xml_document(weaknesses, categories='', views=''):
    return (f'<Weakness_Catalog xmlns="{NAMESPACE}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'Name="CWE" Version="4.20" Date="2026-04-30" xsi:schemaLocation="{NAMESPACE} {SCHEMA_IDENTITY}">'
            f'<Weaknesses>{weaknesses}</Weaknesses><Categories>{categories}</Categories><Views>{views}</Views>'
            '<External_References/></Weakness_Catalog>').encode()


@pytest.fixture
def make_catalog(tmp_path, monkeypatch):
    def build(raw=None):
        raw = raw or xml_document(entry(862), entry(1, kind='Category', usage='Prohibited'),
                                  entry(1000, kind='View', usage='Prohibited'))
        xml = tmp_path / 'corpus.xml'
        manifest = tmp_path / 'manifest.json'
        identity = EXPECTED_MANIFEST.corpus.model_copy(update={'xml_sha256': hashlib.sha256(raw).hexdigest()})
        pin = EXPECTED_MANIFEST.model_copy(update={'corpus': identity})
        monkeypatch.setattr(module, 'EXPECTED_MANIFEST', pin)
        xml.write_bytes(raw)
        manifest.write_text(json.dumps(pin.model_dump()))
        return module.Catalog(xml, manifest)
    return build
