#!/bin/bash
# Invoked only inside an owned disposable container by owned_target.py.
set -euo pipefail
test "${KAGENT_RESET_OWNER:-}" != ""
cd /runtime
tomcat=/owasp/BenchmarkJava/target/cargo/installs/apache-tomcat-9.0.122/apache-tomcat-9.0.122
python3 /reset-source/install.py --war /owasp/BenchmarkJava/target/benchmark.war --tomcat "$tomcat" --output /runtime/tomcat
export KAGENT_BASE_WAR_SHA256
export KAGENT_RESET_SOURCE_SHA256
KAGENT_BASE_WAR_SHA256=$(python3 -c 'import json; print(json.load(open("/runtime/tomcat/installation.json"))["base_war_sha256"])')
KAGENT_RESET_SOURCE_SHA256=$(python3 -c 'import json; print(json.load(open("/runtime/tomcat/installation.json"))["reset_source_sha256"])')
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export JAVA_TOOL_OPTIONS='--add-opens=java.base/java.lang=ALL-UNNAMED'
export CATALINA_HOME="$tomcat"
export CATALINA_BASE=/runtime/tomcat
mkdir -p /runtime/target/db
java -cp /runtime/tomcat/lib/hsqldb-2.7.4.jar org.hsqldb.Server \
  --address 127.0.0.1 --database.0 file:/runtime/target/db/benchmark.db --dbname.0 benchmarkDataBase > /runtime/hsqldb.log 2>&1 &
database_pid=$!
trap 'kill "$database_pid" 2>/dev/null || true' EXIT
for attempt in {1..50}; do
  if (echo > /dev/tcp/127.0.0.1/9001) 2>/dev/null; then break; fi
  sleep 0.1
done
bash "$tomcat/bin/catalina.sh" run
