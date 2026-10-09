# Operator-managed Scenario 1 target

The runner connects to existing containers. It does not create, start, stop,
restart, delete or replace Docker resources. Start prepared containers in Docker
Desktop, then pass their names or IDs and the published URL. No ownership labels
or generated private owned-state file are required.

Admission still requires the existing security bounds: one internal target
network without egress, read-only root and bind mounts, dropped capabilities,
no new privileges, and a sole loopback HTTP binding. Docker Desktop's internal
network publishing limitations normally require a fixed nginx ingress container.
`--ingress-container` selects that existing ingress explicitly. A direct binding
is accepted only if Docker actually publishes it on an isolated internal target.
Arbitrary bridge-network targets and reverse proxy configurations are rejected.

`--reset-war` is a trusted local copy of the exact compatible offline WAR.
The runner compares its hash with the selected container's WAR and installation
report, verifies selected dataset artifacts and every reset bootstrap source,
and reads authenticated reset status inside that container. HTTP reset receipts
must match that JVM's boot ID, baseline and generation. A name, URL or HTTP 200
does not establish identity. The private control credential is read through
Docker inspection, stays in the parent, and never enters worker inputs or evidence.

## Current container prerequisite

Read-only inspection of `owasp-benchmark` during this implementation found no
`KAGENT_RESET_TOKEN`, no `/runtime/tomcat/installation.json` or installed gate at
the supported deployment path, no compatible source image label, a writable
root, and the default bridge network. It publishes 8443 rather than this reset
deployment's HTTP connector. Its exact source/build compatibility was not
established. It was not modified or reset. It cannot be admitted as configured.

Do not point the runner at that container to work around setup. Prepare a separate
compatible deployment yourself; keep the existing container untouched. The cached
offline WAR and build image can be reused when their identities match. The required
source commit is `8b67a88d73b2594570fc21150705283de884620b`, with HSQLDB 2.7.4,
Tomcat 9.0.122, JDK 17, Hibernate 3.6.10.Final and Spring 5.3.39.

## Separate preparation, performed by the operator

The following is an explicit one-time deployment recipe, not a runner action.
Use a fresh local directory outside the repository, for example
`/home/khainguyen/.local/share/kagent-s1-operator`. Copy `install.py`,
`run-target.sh`, and `java/` from this reset directory into its `reset-source/`
subdirectory. Keep those copies synchronized with the current reset sources.
Make a separate `reset-config/` directory containing `proxy.conf` with exactly
this configuration (a final newline is accepted):

```nginx
pid /tmp/nginx.pid;
error_log stderr;
events {}
http { access_log off; client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; server { listen 8080; location / { proxy_pass http://operator-benchmark:8080; proxy_read_timeout 45s; } } }
```

Place this `compose.yaml` in the preparation directory. The target image must
already exist locally and contain the pinned source, cached Tomcat and compatible
`/owasp/BenchmarkJava/target/benchmark.war`. The nginx image must also be available
locally. Use `pull_policy: never` to avoid implicit image replacement.

```yaml
services:
  benchmark:
    image: kagent-experiment:kagent-s1-build-62da4de4df96
    pull_policy: never
    container_name: operator-benchmark
    entrypoint: ["/bin/bash"]
    command: ["/reset-source/run-target.sh"]
    environment:
      KAGENT_RESET_OWNER: operator-managed
      KAGENT_RESET_TOKEN: ${KAGENT_RESET_TOKEN:?private reset credential required}
      KAGENT_RESET_TEST_PROBES: "0"
      KAGENT_RESET_REFERENCE: "0"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges]
    pids_limit: 256
    mem_limit: 2g
    cpus: 2
    tmpfs:
      - /runtime:rw,nosuid,nodev,size=1g
      - /tmp:rw,nosuid,nodev,size=128m
    volumes:
      - ./reset-source:/reset-source:ro
    networks: [target]
  ingress:
    image: nginx:alpine
    pull_policy: never
    container_name: operator-ingress
    entrypoint: [nginx]
    command: ["-c", "/reset-config/proxy.conf", "-g", "daemon off;"]
    user: "101:101"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges]
    pids_limit: 64
    mem_limit: 128m
    tmpfs:
      - /tmp:rw,nosuid,nodev,size=16m
      - /var/cache/nginx:rw,nosuid,nodev,mode=1777,size=16m
    volumes:
      - ./reset-config:/reset-config:ro
    ports: ["127.0.0.1:18080:8080"]
    networks: [target, ingress]
networks:
  target:
    internal: true
  ingress: {}
```

`KAGENT_RESET_OWNER` is only the existing bootstrap's required nonempty marker;
it grants no admission authority. Generate a random credential of at least 32
characters in a private `.env` file in the preparation directory, for example:

```bash
python3 - <<'PY'
import os, secrets
fd = os.open('.env', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('KAGENT_RESET_TOKEN=' + secrets.token_hex(32) + '\n')
PY
```

Provision this separate Compose project yourself, then use Docker Desktop to
start/manage it. This recipe was not executed during implementation. The reused
bootstrap installs instrumentation in the new target's private tmpfs before
Tomcat starts and captures both pristine baselines while admission is closed.
It never patches the existing `owasp-benchmark` deployment. Wait for application
startup to finish; an unavailable endpoint or failed baseline capture blocks the
runner. There is no readiness retry that bypasses verification.

## Locked smoke, after Docker Desktop startup

From the repository root, use a fresh selection/output path. Seed and 12-case
selection are unchanged. If a locked manifest already exists, reuse it directly
instead of overwriting it. These commands launch an LLM run only when the final
`run` command is explicitly executed by the operator; they were not run here.

```bash
venv-linux/bin/python -m benchmarks.scenario1 select \
  --dataset /mnt/d/DOANTOTNGHIEP/benchmark-targets/BenchmarkJava \
  --mode smoke --seed 1729 \
  --output artifacts/benchmarks/scenario1-smoke-1729/manifest.json

venv-linux/bin/python -m benchmarks.scenario1 run \
  --mode smoke \
  --dataset /mnt/d/DOANTOTNGHIEP/benchmark-targets/BenchmarkJava \
  --manifest artifacts/benchmarks/scenario1-smoke-1729/manifest.json \
  --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab \
  --target-state external-reset \
  --container operator-benchmark --ingress-container operator-ingress \
  --reset-war /home/khainguyen/.cache/kagent-s1-build-62da4de4df96/benchmark-offline.war \
  --output artifacts/benchmarks/scenario1-locked-smoke-NEW
```

The parent persists identity and before/authorize/after reset receipts, along with
separate durations. Every case gets the existing isolated worker, workspace,
session and permission context. Failures and unknown state block further workers.
Locks under `~/.kagent/benchmark-target-locks/` serialize local runners by full
container ID, including the optional legacy `--reset-state` path. Operators must
also prevent independent clients or runners on other machines from controlling
the same lab; these are local advisory locks.

Scope remains **PARTIAL**: SQL/DDL and application lifecycle restoration do not
certify filesystem/process/LDAP effects or full Hibernate cache parity. No
performance measurement was made on a prepared operator target in this task.

## Optional real, model-free regression

The focused suite runs admission tests offline. The real integration test is
skipped unless the operator explicitly selects an already prepared lab through
`KAGENT_S1_EXISTING_CONTAINER`, `KAGENT_S1_EXISTING_INGRESS` (when needed),
`KAGENT_S1_EXISTING_TARGET`, `KAGENT_S1_EXISTING_DATASET`, and
`KAGENT_S1_EXISTING_WAR`. It sends fixed benign insert requests, verifies real
logical reset receipts between requests, and checks the container did not restart.
It creates no Docker resources and calls no model.

```bash
venv-linux/bin/python -m pytest \
  tests/benchmarks/test_scenario1_operator_target.py \
  tests/benchmarks/test_scenario1_reset.py -q
```

## Deploying the idle-access update

The Java gate is compiled by `run-target.sh` before Tomcat starts. The idle
update changes only the gate source; the existing image, pinned offline WAR,
Tomcat archive, database adapter and nginx configuration can be reused.
Do not deploy until the operator approves the exact stop/copy/start operation.
The existing `owasp-benchmark` container is outside this operation.

For the currently prepared lab at
`/home/khainguyen/.local/share/kagent-s1-operator`, hold the runner's existing
exclusive lock for `operator-benchmark` throughout deployment. Using
`OperatorResetController(...).ownership()` acquires that same lock; it must
succeed before stopping anything. Then execute these exact steps:

```bash
docker compose --project-name kagent-s1-operator --project-directory /home/khainguyen/.local/share/kagent-s1-operator -f /home/khainguyen/.local/share/kagent-s1-operator/compose.yaml stop benchmark
cp /mnt/d/DOANTOTNGHIEP/kagent/benchmarks/scenario1/reset/java/ResetGate.java /home/khainguyen/.local/share/kagent-s1-operator/reset-source/java/ResetGate.java
docker compose --project-name kagent-s1-operator --project-directory /home/khainguyen/.local/share/kagent-s1-operator -f /home/khainguyen/.local/share/kagent-s1-operator/compose.yaml start benchmark
```

This is one controlled restart of the existing `operator-benchmark`, with the
same image/container/network identity. Its private runtime tmpfs is initialized
by the existing bootstrap. Neither `operator-ingress` nor `owasp-benchmark` is
restarted, replaced or deleted. No image build/pull or new container is required.
Do not run these commands separately from the exclusive lock. If copying fails,
leave the benchmark stopped and report the error; do not start an uncertain build.

After startup, verify the authenticated control status has the updated reset
source hash, successful baseline capture, `IDLE`, and the expected pinned build.
Check `http://localhost:18080/benchmark/` returns HTTP 200. Once approved and
updated, the existing model-free real-container regression can verify idle
access, closure, per-case restrictions, reset/replay, boot identity and verified
return to idle:

```bash
KAGENT_S1_EXISTING_CONTAINER=operator-benchmark \
KAGENT_S1_EXISTING_INGRESS=operator-ingress \
KAGENT_S1_EXISTING_TARGET=http://127.0.0.1:18080 \
KAGENT_S1_EXISTING_DATASET=/home/khainguyen/.local/share/kagent-s1-operator/verification-dataset \
KAGENT_S1_EXISTING_WAR=/home/khainguyen/.cache/kagent-s1-build-62da4de4df96/benchmark-offline.war \
venv-linux/bin/python -m pytest tests/benchmarks/test_scenario1_operator_target.py -k real_existing_container -q
```

Source verification before deployment uses only cached artifacts in temporary
files. It does not alter a running app, start Docker resources or call a model:

```bash
KAGENT_S1_RESET_TEST_WAR=/home/khainguyen/.cache/kagent-s1-build-62da4de4df96/benchmark-offline.war \
KAGENT_S1_RESET_TEST_TOMCAT=/home/khainguyen/.local/share/kagent-s1-operator/build/apache-tomcat-9.0.122.tar.gz \
venv-linux/bin/python -m pytest tests/benchmarks/test_scenario1_idle_gate.py tests/benchmarks/test_scenario1_reset.py tests/benchmarks/test_scenario1_operator_target.py -q
```

The Java harness runs the production `ResetGate` with an injected lifecycle test
double and the original servlet/Jackson dependencies, exercises drain and failure
paths, and sends actual loopback HTTP through KAgent's normal HTTP registry/tool.
All production Java reset sources also compile against the cached original WAR
and Tomcat libraries. Actual catalog restoration in the updated deployed JVM
remains a post-approval verification step; the harness does not claim SQL parity.
