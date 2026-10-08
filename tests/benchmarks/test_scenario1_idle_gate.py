"""Production Java gate, local HTTP/TUI adapter and parent fail-closed regressions.

Set KAGENT_S1_RESET_TEST_WAR and KAGENT_S1_RESET_TEST_TOMCAT to cached offline
artifacts. Compilation/testing occurs only in pytest's temporary directories.
No Docker lifecycle operations, model calls or deployed-app modifications.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

import pytest

from benchmarks.scenario1.reset.install import JAVA


@pytest.fixture(scope='module')
def gate_java(tmp_path_factory):
    war = os.environ.get('KAGENT_S1_RESET_TEST_WAR')
    tomcat = os.environ.get('KAGENT_S1_RESET_TEST_TOMCAT')
    if not war or not tomcat:
        pytest.skip('requires cached offline WAR and Tomcat archive for production Java gate tests')
    assert shutil.which('java') and shutil.which('javac'), 'Java 17 JDK required'
    root = tmp_path_factory.mktemp('idle-java')
    deps = root / 'deps'
    deps.mkdir()
    with zipfile.ZipFile(war) as archive:
        for ref in archive.namelist():
            if ref.startswith('WEB-INF/lib/') and ref.endswith('.jar'):
                (deps / Path(ref).name).write_bytes(archive.read(ref))
        classes = root / 'original-classes'
        for ref in archive.namelist():
            if ref.startswith('WEB-INF/classes/') and not ref.endswith('/'):
                dest = classes / ref.removeprefix('WEB-INF/classes/')
                assert dest.resolve().is_relative_to(classes.resolve())
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(archive.read(ref))
    with tarfile.open(tomcat) as archive:
        for item in archive.getmembers():
            if '/lib/' in item.name and item.name.endswith('.jar'):
                (deps / Path(item.name).name).write_bytes(archive.extractfile(item).read())
    classpath = os.pathsep.join((str(classes), str(deps / '*')))
    production = root / 'production'
    production.mkdir()
    subprocess.run(['javac', '--release', '17', '-cp', classpath, '-d', str(production),
                    *map(str, sorted(JAVA.glob('*.java')))], check=True, capture_output=True, timeout=45)
    harness = root / 'harness'
    harness.mkdir()
    subprocess.run(['javac', '--release', '17', '-cp', classpath, '-d', str(harness),
                    str(JAVA / 'ResetGate.java'), str(Path(__file__).with_name('java') / 'ResetGateIdleTest.java')],
                   check=True, capture_output=True, timeout=45)
    env = {**os.environ, 'KAGENT_RESET_TOKEN': 'test-only-' + 'a' * 64,
           'KAGENT_RESET_TEST_PROBES': '0', 'KAGENT_BASE_WAR_SHA256': 'c' * 64,
           'KAGENT_RESET_SOURCE_SHA256': 'd' * 64}
    return ['java', '-cp', os.pathsep.join((str(harness), str(deps / '*'))),
            'org.kagent.scenario1.reset.ResetGateIdleTest'], env


@pytest.mark.parametrize('scenario', ['idle', 'transition', 'session', 'reset-failure', 'drain-timeout',
                                     'idle-failure', 'premature', 'crash'])
def test_production_gate_idle_and_benchmark_lifecycle(gate_java, scenario):
    command, env = gate_java
    result = subprocess.run([*command, scenario], env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert f'PASS {scenario}' in result.stdout


@pytest.mark.asyncio
async def test_normal_tui_http_adapter_through_idle_java_gate(gate_java):
    from src.engagement.state import EngagementState
    from src.permission.permission import Decision
    from src.target.target import Target
    from src.tools.common.registry import Registry
    from src.tools.http.http_tool import HTTPTool

    class Allow:
        async def ask(self, request, signal=None):
            return Decision.ALLOW_ONCE

    command, env = gate_java
    process = subprocess.Popen([*command, 'http'], env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(process.stdout.readline())
        url = f'http://127.0.0.1:{port}/benchmark/'
        engagement = EngagementState()
        engagement.initialize_target(url)
        registry = Registry()
        registry.register(HTTPTool(Target(url), engagement))
        for method in ('GET', 'POST'):
            result = await registry.execute('http', {'url': url, 'method': method, 'phase': 'recon'}, None, Allow())
            assert result.http_status == 200 and 'normal access' in result
    finally:
        process.communicate('\n', timeout=10)
        assert process.returncode == 0
