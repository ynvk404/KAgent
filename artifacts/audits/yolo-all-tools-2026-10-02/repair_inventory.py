"""Checkpoint/current skill contracts, not an assertion of end-to-end support."""
from pathlib import Path
import subprocess
import sys
import json
import re

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
import yaml
from src.skills.registry import normalize_candidate_class

HEAD = 'b1057dcf7de9478c1649a35612d3bebeb3824303'
names = subprocess.check_output(['git','ls-tree','-r','--name-only',HEAD],cwd=ROOT).decode().splitlines()
rows=[]
for name in names:
    if not name.startswith('skills/') or not name.endswith('/SKILL.md'):
        continue
    before = subprocess.check_output(['git','show',f'{HEAD}:{name}'],cwd=ROOT).decode()
    after = (ROOT/name).read_text()
    front = before.split('---',2)[1]
    meta = yaml.safe_load(front)
    classes = [normalize_candidate_class(x) for x in meta.get('candidate-classes',[])]
    # Read the proof, impact, stop and allowed-tools contract in each full body.
    contracts = [line for line in before.splitlines() if re.search(r'confirmed|evidence|proof|stop|bounded|allowed-tools|ask_user',line,re.I)]
    rows.append({'skill':meta.get('name'), 'path':name, 'classes':classes,
        'allowed_tools':meta.get('allowed-tools',[]), 'stage':meta.get('stage'),
        'unchanged_body':before==after, 'proof_contract_lines':contracts,
        'checkpoint_e2e_claim':'playbook/record-result contract only; no historical per-class live acceptance asserted'})
out = Path(__file__).parent/'repair-2026-10-02/skill-inventory.json'
out.write_text(json.dumps(rows,indent=2,ensure_ascii=False))
print(json.dumps({'skills':len(rows),'validation_classes':sorted({x for row in rows for x in row['classes']}),
                  'bodies_preserved':all(row['unchanged_body'] for row in rows)},indent=2))
