"""Instrument a copy of the pinned offline WAR. Original dataset remains read-only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

COMMIT = '8b67a88d73b2594570fc21150705283de884620b'
JAVA = Path(__file__).parent / 'java'
NS = 'http://xmlns.jcp.org/xml/ns/javaee'


def source_hash() -> str:
    hashed = hashlib.sha256()
    for path in sorted(JAVA.glob('*.java')):
        hashed.update(path.name.encode() + b'\0' + path.read_bytes())
    return hashed.hexdigest()


def install(war: Path, tomcat: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError('installation destination already exists')
    output.mkdir(parents=True)
    app = output / 'webapps' / 'benchmark'
    with zipfile.ZipFile(war) as archive:
        for name in archive.namelist():
            resolved = (app / name).resolve()
            if not resolved.is_relative_to(app.resolve()):
                raise ValueError('unsafe WAR entry')
        archive.extractall(app)
    required = ['hsqldb-2.7.4.jar', 'hibernate-core-3.6.10.Final.jar', 'spring-core-5.3.39.jar', 'commons-dbcp-1.4.jar']
    if any(not (app / 'WEB-INF/lib' / name).is_file() for name in required):
        raise ValueError('offline WAR dependency identity mismatch')
    classes = app / 'WEB-INF/classes'
    classpath = f'{classes}:{app / "WEB-INF/lib/*"}:{tomcat / "lib/*"}'
    subprocess.run(['javac', '--release', '17', '-cp', classpath, '-d', str(classes),
                    *map(str, sorted(JAVA.glob('*.java')))], check=True)
    ET.register_namespace('', NS)
    web = app / 'WEB-INF/web.xml'
    tree = ET.parse(web)
    root = tree.getroot()
    tag = lambda name: f'{{{NS}}}{name}'
    for entry in root.findall(tag('filter')):
        if entry.findtext(tag('filter-name')) == 'KAgentResetGate':
            raise ValueError('WAR already instrumented')
    original_filters = [entry.findtext(tag('filter-class')) for entry in root.findall(tag('filter'))]
    if 'org.owasp.benchmark.helpers.filters.DataBaseFilter' not in original_filters:
        raise ValueError('original database rollback filter missing')
    listener = ET.Element(tag('listener'))
    ET.SubElement(listener, tag('listener-class')).text = 'org.kagent.scenario1.reset.ResetGate'
    root.insert(0, listener)
    gate = ET.Element(tag('filter'))
    ET.SubElement(gate, tag('filter-name')).text = 'KAgentResetGate'
    ET.SubElement(gate, tag('filter-class')).text = 'org.kagent.scenario1.reset.ResetGate'
    ET.SubElement(gate, tag('async-supported')).text = 'false'
    root.insert(1, gate)
    mapping = ET.Element(tag('filter-mapping'))
    ET.SubElement(mapping, tag('filter-name')).text = 'KAgentResetGate'
    ET.SubElement(mapping, tag('url-pattern')).text = '/*'
    root.insert(2, mapping)
    import os
    if os.environ.get('KAGENT_RESET_REFERENCE') == '1':
        for entry in (listener, gate, mapping):
            root.remove(entry)
    if os.environ.get('KAGENT_RESET_TEST_PROBES') == '1':
        subprocess.run(['javac', '--release', '17', '-cp', classpath, '-d', str(classes),
                        str(JAVA.parent / 'tests/ResetProbe.java')], check=True)
        servlet = ET.SubElement(root, tag('servlet'))
        ET.SubElement(servlet, tag('servlet-name')).text = 'KAgentTestProbe'
        ET.SubElement(servlet, tag('servlet-class')).text = 'org.kagent.scenario1.reset.ResetProbe'
        binding = ET.SubElement(root, tag('servlet-mapping'))
        ET.SubElement(binding, tag('servlet-name')).text = 'KAgentTestProbe'
        ET.SubElement(binding, tag('url-pattern')).text = '/__kagent_probe'
    # No replacement initializer and no filter reinitialization. Tomcat loads the
    # original @WebListener Startup; baseline is captured later in filter.init.
    tree.write(web, encoding='UTF-8', xml_declaration=True)
    for directory in ('conf', 'logs', 'temp', 'work', 'lib'):
        (output / directory).mkdir(exist_ok=True)
    shutil.copytree(tomcat / 'conf', output / 'conf', dirs_exist_ok=True)
    server = output / 'conf/server.xml'
    configuration = ET.parse(server)
    resources = configuration.getroot().find('GlobalNamingResources')
    if resources is None:
        raise ValueError('Tomcat global resource hierarchy missing')
    ET.SubElement(resources, 'Resource', {
        'name': 'jdbc/ApplicationContext_BenchmarkDB', 'auth': 'Container', 'type': 'javax.sql.DataSource',
        'username': 'sa', 'password': '', 'driverClassName': 'org.hsqldb.jdbc.JDBCDriver',
        'url': 'jdbc:hsqldb:hsql://localhost/benchmarkDataBase;file:benchmark.db;sql.enforce_size=false;shutdown=false;',
        'maxTotal': '12', 'maxIdle': '2', 'maxWaitMillis': '5000', 'removeAbandonedOnBorrow': 'true'})
    configuration.getroot().set('port', '-1')
    configuration.write(server, encoding='UTF-8', xml_declaration=True)
    shutil.copy2(app / 'WEB-INF/lib/hsqldb-2.7.4.jar', output / 'lib')
    report = {'source_commit': COMMIT, 'base_war_sha256': hashlib.sha256(war.read_bytes()).hexdigest(),
              'reset_source_sha256': source_hash(), 'original_filters': original_filters,
              'installation_mode': 'predeployment-descriptor; original initializer and filters retained',
              'reference': os.environ.get('KAGENT_RESET_REFERENCE') == '1'}
    (output / 'installation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--war', required=True, type=Path)
    parser.add_argument('--tomcat', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    install(args.war, args.tomcat, args.output)
