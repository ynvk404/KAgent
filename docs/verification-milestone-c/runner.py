from pathlib import Path
import hashlib,json,subprocess,sys,time,os
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[2]
OUT=Path(os.environ.get('KAGENT_VERIFY_OUT', str(ROOT / '.kagent/verification'))).resolve()
OUT.mkdir(parents=True, exist_ok=True)
def manifest():
 files=[]
 for root in ('src','tests','benchmarks','skills','scripts'):
  files += [p for p in (ROOT/root).rglob('*') if p.is_file() and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts]
 files += [ROOT/n for n in ('AGENTS.md','pyproject.toml','pytest.ini','pyrightconfig.json','requirements.txt')]
 rows={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
 return {'files':rows,'count':len(rows),'aggregate':hashlib.sha256(''.join(f'{h}  {p}\n' for p,h in rows.items()).encode()).hexdigest()}
def save(name,data): (OUT/name).write_text(json.dumps(data,indent=2))
name=sys.argv[1]
if name in ('freeze','check'):
 current=manifest(); save(name+'.json',current)
 print(json.dumps({k:v for k,v in current.items() if k!='files'}))
 if name=='check':
  frozen=json.loads((OUT/'freeze.json').read_text()); print('MATCH:',current==frozen);sys.exit(0 if current==frozen else 1)
 sys.exit()
if name=='pyright': cmd=['venv-linux/bin/pyright']
else:
 cmd=['venv-linux/bin/pytest','-q','--tb=short','-ra',f'--junitxml={OUT/name}.xml',*sys.argv[2:]]
xml_path=OUT/(name+'.xml')
if name!='pyright' and xml_path.exists(): xml_path.unlink()
save(name+'-before.json',manifest());started=time.monotonic()
started_utc=datetime.now(timezone.utc).isoformat()
with (OUT/(name+'.log')).open('w') as log:
 result=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
after=manifest();save(name+'-after.json',after)
record={'command':cmd,'exit_code':result.returncode,'elapsed_seconds':round(time.monotonic()-started,3),
 'started_utc':started_utc, 'finished_utc':datetime.now(timezone.utc).isoformat(),
 'cwd':str(ROOT), 'python':sys.version,
 'source_unchanged':json.loads((OUT/(name+'-before.json')).read_text())==after,
 'environment':{'TERM':os.environ.get('TERM'),'COLORTERM':os.environ.get('COLORTERM')}}
record['junit_valid']=name=='pyright' or xml_path.exists()
record['log_sha256']=hashlib.sha256((OUT/(name+'.log')).read_bytes()).hexdigest()
if name!='pyright' and xml_path.exists():
 import xml.etree.ElementTree as ET
 suites=ET.parse(OUT/(name+'.xml')).getroot().findall('testsuite')
 record['junit_valid']=bool(suites)
 record['junit_sha256']=hashlib.sha256(xml_path.read_bytes()).hexdigest()
 record['junit']={key:sum(int(s.get(key,'0')) for s in suites) for key in ('tests','failures','errors','skipped')}
 record['skipped']=[{'id':c.get('classname','')+'::'+c.get('name',''),'reason':c.find('skipped').get('message')} for s in suites for c in s.findall('testcase') if c.find('skipped') is not None]
 import re
 summary=(OUT/(name+'.log')).read_text().splitlines()
 record['pytest_summary']=next((line for line in reversed(summary) if re.search(r'\d+ (?:passed|failed|skipped|error)',line)),None)
save(name+'-result.json',record);print(json.dumps(record,indent=2))
print('\n'.join((OUT/(name+'.log')).read_text().splitlines()[-16:]))
sys.exit(result.returncode)
