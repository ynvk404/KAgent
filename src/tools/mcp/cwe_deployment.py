"""Fixed controller contract for the optional pinned CWE MCP deployment."""
from __future__ import annotations

from typing import Any
from pathlib import Path

CWE_MCP_SERVER_NAME = "cwe_catalog"
CWE_MCP_COMMAND = "/usr/bin/python3"
CWE_MCP_MOUNT_PATH = "/opt/kagent-cwe-mcp"
CWE_MCP_LAUNCH_PATH = f"{CWE_MCP_MOUNT_PATH}/launch.py"
CWE_MCP_ARGS = ("-I", "-B", CWE_MCP_LAUNCH_PATH)


def is_designated_cwe_server(server: Any) -> bool:
    """Return whether this is the one supported, non-generic CWE launch."""
    return (server.name == CWE_MCP_SERVER_NAME
            and server.command == CWE_MCP_COMMAND
            and tuple(server.args) == CWE_MCP_ARGS
            and not server.env)


def require_matching_cwe_deployment(policy: Any, worker: Any) -> Path:
    """Bind verification and launch to the same explicit controller setting."""
    from src.permission.runtime.execution import ExecutionBlocked

    deployment = policy.cwe_mcp_deployment_path
    mounted = getattr(worker, "cwe_mcp_deployment_path", None)
    if deployment is None or mounted != deployment:
        raise ExecutionBlocked("blocked: CWE-deployment-policy-worker-mismatch")
    return deployment


def verify_cwe_runtime_archive(deployment: Path, entries: dict[str, Path | None], checkpoint) -> None:
    """Fail closed on stale prepared dependencies, before the handshake clock.

    Entries come from the worker's no-follow, regular-file-only tree inspection;
    archive names are compared with them, never interpreted as host paths.
    Unprepared legacy deployments retain their existing source import behavior.
    """
    import hashlib
    import json
    import zipfile
    from src.permission.runtime.execution import ExecutionBlocked

    archive = deployment / 'runtime.zip'
    if not archive.exists():
        return
    try:
        if not 0 < archive.stat().st_size <= 16 * 1024 * 1024:
            raise ValueError('archive size')
        with zipfile.ZipFile(archive) as bundle:
            name = 'kagent-runtime-manifest.json'
            if bundle.namelist().count(name) != 1 or bundle.getinfo(name).file_size > 512 * 1024:
                raise ValueError('inventory size/identity')
            inventory = json.loads(bundle.read(name))
        if (not isinstance(inventory, dict) or set(inventory) != {'schema_version', 'entries'}
                or type(inventory['schema_version']) is not int or inventory['schema_version'] != 1
                or not isinstance(inventory['entries'], dict) or set(inventory['entries']) != set(entries)):
            raise ValueError('inventory identity')
        for name, path in entries.items():
            checkpoint()
            expected = inventory['entries'][name]
            if path is None:
                if expected is not None:
                    raise ValueError('directory changed')
                continue
            if not isinstance(expected, str) or len(expected) != 64:
                raise ValueError('file identity')
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                while chunk := stream.read(1024 * 1024):
                    checkpoint()
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError('dependency changed')
    except ExecutionBlocked:
        raise
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RecursionError) as error:
        raise ExecutionBlocked('blocked: stale-or-invalid-CWE-runtime-archive; run explicit pack_runtime maintenance') from error
