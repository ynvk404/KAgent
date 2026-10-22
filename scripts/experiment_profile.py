"""Prepare a fresh KAgent experiment profile; never delete existing data.

Default/--dry-run is read-only. --apply only creates a new, exclusive directory.
The optional launcher adapts store constructor paths in its own process, then
uses the official CLI. It does not replace Agent/tool/policy implementations.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from unittest.mock import patch
from urllib.parse import urlsplit


REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def regular(path: Path) -> bytes:
    """Reject links/special files, including symlinked ancestors."""
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlinked path is not supported")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("expected an unlinked regular file")
        return stream.read()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree(root: Path, *, exclude_caches: bool = True) -> dict[str, str]:
    if root.is_symlink():
        raise ValueError("linked tree root is not supported")
    rows = {}
    for path in sorted(root.rglob("*")):
        if exclude_caches and ("__pycache__" in path.parts or ".pytest_cache" in path.parts):
            continue
        if path.is_symlink():
            raise ValueError("linked source/skill is not supported")
        if path.is_file():
            rows[str(path.relative_to(root))] = digest(regular(path))
    return rows


def normalized_origin(value: str) -> str:
    from src.target.origin import HTTPOrigin
    parsed = urlsplit(value)
    if (parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.username or parsed.password):
        raise ValueError("an exact HTTP(S) origin is required")
    return HTTPOrigin.from_url(value).as_url()


def reviewed_prompt(path: Path) -> bytes:
    """Use the CLI loader's safety contract, retaining the exact reviewed bytes."""
    from src.cli.prompt_file import MAX_PROMPT_BYTES, read_prompt_file
    text = read_prompt_file(path)
    raw = regular(path)
    if len(raw) > MAX_PROMPT_BYTES or raw.decode("utf-8-sig").replace("\r\n", "\n") != text:
        raise ValueError("reviewed request changed while reading")
    return raw


def request_bytes(value: dict) -> bytes:
    """Resolve a pinned request, or preserve the legacy v2 generated request."""
    if value.get("version") == 4 and "reviewed_request" not in value:
        return b""
    if value.get("version") == 2 and "reviewed_request" not in value:
        return whole_target_request(value).encode()
    if value.get("version") not in (3, 4):
        raise ValueError("invalid request profile version")
    request = value.get("reviewed_request")
    if not isinstance(request, dict) or set(request) != {"source", "sha256", "bytes"}:
        raise ValueError("invalid reviewed request metadata")
    source = request["source"]
    if not isinstance(source, str) or not Path(source).is_absolute() or ".." in Path(source).parts:
        raise ValueError("invalid reviewed request source")
    raw = reviewed_prompt(Path(source))
    if digest(raw) != request["sha256"] or type(request["bytes"]) is not int or len(raw) != request["bytes"]:
        raise ValueError("reviewed request hash or size changed")
    return raw


def plan(repo: Path, home: Path, config: Path, run: Path, origin: str, max_steps: int | None = None,
         *, prompt_file: Path | None = None, enable_headless_shell: bool = False,
         legacy_bounded: bool = False) -> dict:
    from src.config.config import config_from_dict, resolve_custom_provider
    repo, home, config, run = (p.absolute() for p in (repo, home, config, run))
    if any(".." in p.parts for p in (repo, home, config, run)):
        raise ValueError("parent traversal is not supported")
    if run.exists() or run.is_symlink():
        raise ValueError("run directory must not exist; use a new run ID")
    if any(p.is_symlink() for p in run.parents):
        raise ValueError("symlinked run parent is not supported")
    profile_root = run.parent.parent / "profiles" if run.parent.name == "runs" else run.parent / "profiles"
    profile = profile_root / run.name
    if profile.exists() or any(p.is_symlink() for p in (profile, *profile.parents)):
        raise ValueError("profile directory must be new and not symlinked")
    # A run may live under the project's ignored .kagent, never in source/Git.
    if repo.is_relative_to(run) or home.is_relative_to(run) or any(run.is_relative_to(repo / name) for name in (
        "src", "skills", "tests", "scripts", "docs", "artifacts", ".git",
    )) or run.is_relative_to(home / ".kagent"):
        raise ValueError("run directory overlaps protected or existing user data")
    raw = regular(config)
    cfg = config_from_dict(json.loads(raw))
    if legacy_bounded and cfg.active_custom_provider_id:
        raise ValueError("Scenario 3 requires the reviewed official provider, not an active Custom profile")
    effective = cfg
    if not legacy_bounded and cfg.active_custom_provider_id:
        effective, _ = resolve_custom_provider(cfg, cfg.active_custom_provider_id)
    if effective.base_url:
        from src.llm.providers import validate_base_url
        validate_base_url(effective.base_url)
    if max_steps is not None and (type(max_steps) is not int or max_steps <= 0):
        raise ValueError("max steps must be positive")
    if legacy_bounded and (cfg.skills_dirs or cfg.plugins):
        raise ValueError("extra skill/plugin paths require a separate reviewed profile")
    # Legacy experiments admitted only the pinned, generic CWE catalog. Normal
    # isolation profiles retain the operator's configured integrations.
    from src.tools.mcp.cwe_deployment import is_designated_cwe_server
    if legacy_bounded and any(not is_designated_cwe_server(s) for s in cfg.mcp_servers):
        raise ValueError("unreviewed MCP data source in configuration")
    if enable_headless_shell and not legacy_bounded:
        raise ValueError("shell preset requires --legacy-bounded; normal headless policy is unchanged")
    backups = []
    for label, path in (
        ("project-intelligence", repo / ".kagent/intelligence/scenarios.jsonl"),
        ("personal-intelligence", home / ".kagent/intelligence/scenarios.jsonl"),
    ):
        if path.exists() or path.is_symlink():
            data = regular(path)
            backups.append({"label": label, "path": str(path), "sha256": digest(data),
                            "bytes": len(data)})
    value = {"version": 2 if legacy_bounded else 4, "operation": "fresh-profile-no-deletion", "repo": str(repo),
            "original_home": str(home), "config": str(config), "config_sha256": digest(raw),
            "run": str(run), "profile": str(profile), "origin": normalized_origin(origin), "backup_sources": backups,
            "runtime_files": tree(repo / "src"), "skill_files": tree(repo / "skills"),
            "script_sha256": digest(regular(Path(__file__))),
            "launcher_sha256": digest(regular(Path(__file__).with_name("run_experiment.sh"))),
            "provider": {"backend": str(cfg.backend), "model": cfg.model,
                         "base_url": cfg.base_url, "thinking_enabled": cfg.thinking_enabled,
                         "streaming_enabled": cfg.streaming_enabled},
            "limits": {"max_steps": max_steps, "wall_seconds_foreground_int": 1200,
                       "wall_clock_start": "frontend process start; includes startup, operator wait and reviews",
                       "native_http": {"seconds": 1200, "requests": 500, "rate": 3,
                                       "burst": 3, "concurrency": 2,
                                       "request_bytes": 131072, "response_bytes": 65536},
                       "scanner_jobs_authorized": 0,
                       "token_budget_proposal": 2000000, "usd_budget_proposal": 1,
                       "token_cost_hard_cap_available_in_cli": False},
            "deletions": [], "existing_files_to_modify": [],
            "new_paths": [str(profile), *[str(run / p) for p in ("backup", "project", "profile-home", "logs")]],
            "startup_adapter": ["IntelligenceStore(cwd, home)", "MemoryStore(cwd, home)",
                                "EngagementStore(cwd, home)", "skill_search_dirs(cwd, home)",
                                "session.store.dir_from_path", "KAGENT_PROJECT_ROOT + cwd"]}
    if legacy_bounded:
        value["limits"]["max_steps"] = max_steps if max_steps is not None else 60
    else:
        del value["limits"]
        value["runtime_options"] = {"max_steps": max_steps}
        value["provider"] = {"backend": str(effective.backend), "model": effective.model,
                             "base_url": effective.base_url,
                             "active_custom_provider_id": cfg.active_custom_provider_id,
                             "thinking_enabled": effective.thinking_enabled,
                             "streaming_enabled": effective.streaming_enabled}
    if prompt_file is not None:
        source = prompt_file.expanduser().absolute()
        if ".." in source.parts or source.is_relative_to(run) or source.is_relative_to(profile):
            raise ValueError("reviewed request source must be outside the new run and profile")
        raw_request = reviewed_prompt(source)
        value["version"] = 3 if legacy_bounded else 4
        value["reviewed_request"] = {"source": str(source), "sha256": digest(raw_request),
                                     "bytes": len(raw_request)}
    if enable_headless_shell:
        if prompt_file is None:
            raise ValueError("shell preset requires an explicitly reviewed request")
        value["execution_preset"] = "headless-shell"
        # This existing runtime has one active scanner slot, but no aggregate
        # scanner-job quota. Do not misrepresent permission as an enforced cap.
        value["limits"]["scanner_jobs_authorized"] = None
    return value


def encode(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if regular(path) != data:
        raise ValueError("written file did not verify")


def validate_plan(value: dict) -> None:
    request_bytes(value)  # Reject malformed metadata or a stale prompt before any writes.
    expected = plan(Path(value["repo"]), Path(value["original_home"]), Path(value["config"]),
                    Path(value["run"]), value["origin"],
                    value["runtime_options"]["max_steps"] if value["version"] == 4 else value["limits"]["max_steps"],
                    prompt_file=Path(value["reviewed_request"]["source"]) if "reviewed_request" in value else None,
                    enable_headless_shell=value.get("execution_preset") == "headless-shell",
                    legacy_bounded=value["version"] in (2, 3))
    if expected != value:
        raise ValueError("plan is stale or modified; review a new dry-run")


def apply(value: dict) -> Path:
    """Create only new files. A failed prepare remains unlaunchable; never clean it."""
    validate_plan(value)
    run, repo = Path(value["run"]), Path(value["repo"])
    # Exclusive creation prevents reusing a dirty run or overwriting evidence.
    run.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    run.mkdir(mode=0o700)
    for row in value["backup_sources"]:
        data = regular(Path(row["path"]))
        if digest(data) != row["sha256"]:
            raise ValueError("backup source changed")
        private_write(run / "backup" / (row["label"] + ".jsonl"), data)
    # Verify every backup and original again before publishing a usable profile.
    for row in value["backup_sources"]:
        for path in (Path(row["path"]), run / "backup" / (row["label"] + ".jsonl")):
            if digest(regular(path)) != row["sha256"]:
                raise ValueError("backup/original verification failed")
    for name in ("project", "profile-home", "logs"):
        (run / name).mkdir(mode=0o700)
    for relative, sha in value["skill_files"].items():
        data = regular(repo / "skills" / relative)
        if digest(data) != sha:
            raise ValueError("skill changed during preparation")
        private_write(run / "project/skills" / relative, data)
        (run / "project/skills" / relative).chmod(0o400)
    if tree(repo / "src") != value["runtime_files"] or digest(regular(Path(value["config"]))) != value["config_sha256"]:
        raise ValueError("runtime/config changed during preparation")
    profile = Path(value["profile"])
    profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile.mkdir(mode=0o700)
    receipt = profile / "profile.json"
    request = request_bytes(value)
    if request:
        private_write(profile / "whole-target-request.txt", request)
    private_write(receipt, encode(value))
    return receipt


def verify(receipt: Path) -> dict:
    """Read-only pre-launch checks; no canary is inserted into a real run."""
    value = json.loads(regular(receipt))
    run, repo = Path(value["run"]), Path(value["repo"])
    if any(path.is_symlink() for path in run.rglob("*")):
        raise ValueError("run contains a linked path")
    if tree(run / "logs", exclude_caches=False):
        raise ValueError("run contains pre-existing logs")
    if receipt.absolute() != Path(value["profile"]) / "profile.json" or value.get("version") not in (2, 3, 4):
        raise ValueError("invalid profile receipt")
    if "execution_preset" in value and (
        value["execution_preset"] != "headless-shell" or value["version"] != 3
        or value["limits"]["scanner_jobs_authorized"] is not None
    ):
        raise ValueError("invalid shell execution preset")
    if digest(regular(Path(__file__))) != value["script_sha256"]:
        raise ValueError("profile launcher changed")
    if digest(regular(Path(__file__).with_name("run_experiment.sh"))) != value["launcher_sha256"]:
        raise ValueError("shell launcher changed")
    if tree(repo / "src") != value["runtime_files"]:
        raise ValueError("runtime changed since preparation")
    if tree(run / "project/skills") != value["skill_files"]:
        raise ValueError("profile skills changed")
    expected_project = {"skills/" + path: sha for path, sha in value["skill_files"].items()}
    if tree(run / "project", exclude_caches=False) != expected_project or tree(run / "profile-home", exclude_caches=False):
        raise ValueError("profile contains unexpected files")
    if digest(regular(Path(value["config"]))) != value["config_sha256"]:
        raise ValueError("provider configuration changed")
    request = request_bytes(value)
    request_path = Path(value["profile"]) / "whole-target-request.txt"
    if (request and regular(request_path) != request) or (not request and request_path.exists()):
        raise ValueError("reviewed request changed")
    if value["version"] == 4:
        options = value.get("runtime_options")
        if not isinstance(options, dict) or set(options) != {"max_steps"} or "limits" in value:
            raise ValueError("invalid isolation runtime options")
        steps = options["max_steps"]
        if steps is not None and (type(steps) is not int or steps <= 0):
            raise ValueError("max steps must be positive")
    for row in value["backup_sources"]:
        if digest(regular(run / "backup" / (row["label"] + ".jsonl"))) != row["sha256"]:
            raise ValueError("backup changed")
    if (run / "launch-started.json").exists():
        raise ValueError("this profile has already been launched")
    # Even an unrelated learned fact would make this a non-fresh experiment.
    for base in (run / "project/.kagent", run / "profile-home/.kagent"):
        if any(p.is_symlink() for p in (base, *base.parents)):
            raise ValueError("profile directory was replaced by a link")
        if base.exists() and any(base.iterdir()):
            raise ValueError("profile has pre-existing runtime data")
    if not (run / "project").is_dir() or not (run / "profile-home").is_dir():
        raise ValueError("profile directories are missing")
    return value


@contextmanager
def bound_runtime(value: dict):
    """Process-local wiring only. All implementations and permission gates stay intact."""
    from src.cli import runtime
    from src.engagement.store import EngagementStore
    from src.intelligence.store import IntelligenceStore
    from src.memory.store import MemoryStore
    from src.session import store as sessions
    from src.skills.discovery import skill_search_dirs
    run = Path(value["run"])
    project, home = run / "project", run / "profile-home"
    previous_cwd = Path.cwd()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"KAGENT_PROJECT_ROOT": str(project),
                                                   "kagent_CONFIG": value["config"]}))
        stack.enter_context(patch.object(runtime, "IntelligenceStore", partial(IntelligenceStore, cwd=project, home=home)))
        stack.enter_context(patch.object(runtime, "MemoryStore", partial(MemoryStore, cwd=str(project), home=str(home))))
        stack.enter_context(patch.object(runtime, "EngagementStore", partial(EngagementStore, cwd=project, home=home)))
        if value.get("version") == 4:
            def isolated_skill_dirs(configured):
                # Keep normal playbooks/configured paths; replace only the builtin
                # project snapshot. Learned memory and engagement use fresh stores.
                original = skill_search_dirs(configured, cwd=value["repo"], home=value["original_home"])
                return [str(project / "skills"), *original[1:]]
            stack.enter_context(patch.object(runtime, "skill_search_dirs", isolated_skill_dirs))
        else:
            stack.enter_context(patch.object(runtime, "skill_search_dirs", partial(skill_search_dirs, cwd=str(project), home=str(home))))
        stack.enter_context(patch.object(sessions, "dir_from_path", lambda path=None: (
            Path(path).parent if path else home / ".kagent/sessions")))
        try:
            os.chdir(project)  # Prevent the legacy CWD fallback from importing old state.
            yield runtime
        finally:
            os.chdir(previous_cwd)


def whole_target_request(value: dict) -> str:
    return (
        f"Thực hiện một phiên Whole-target trên lab được phép tại {value['origin']}.\n"
        f"Scope duy nhất: {value['origin']}; không mở rộng origin hoặc port.\n"
        "Tự khám phá endpoint/input, phân tích và xác thực SQL Injection/XSS có giới hạn, "
        "không phá hoại; ghi evidence và Finding chỉ khi đủ điều kiện.\n"
        "Không DoS, brute-force không giới hạn, phá hủy dữ liệu, trích xuất hàng loạt "
        "hoặc sử dụng tài khoản ngoài tài khoản test được cung cấp. Không chạy scanner jobs.\n"
        "Tuân thủ scope, permission và workflow; dừng khi bị chặn hoặc hết budget. "
        "Không đọc kết quả thực nghiệm cũ. Không có endpoint, payload hay ground truth cung cấp sẵn.\n"
        f"Giới hạn: {value['limits']['max_steps']} outer steps; hạn 20 phút từ lúc khởi động frontend. "
        "HTTP governed envelope: 500 requests, 3/s, burst 3, concurrency 2; "
        "không renew hoặc mở rộng quyền khi hết hạn.\n"
    )


@contextmanager
def headless_shell_runtime(value: dict):
    """One launch only: restore existing session rights at the frontend boundary.

    CLI startup installs its fixed Headless revocations before calling this
    runner. Use the existing controller API once, then delegate to the official
    runner; later revocations, receipts, worker and scanner gates stay intact.
    No Agent, Registry, ExecutionPolicy or tool implementation is replaced.
    """
    from src.cli import headless
    from src.permission.runtime.execution import policy_for
    from src.target.origin import HTTPOrigin
    original = headless.run_headless

    async def run(agent, *args, **kwargs):
        policy = policy_for(agent.prompter)
        if (policy is None or policy.worker is None or "*" in policy.revoked
                or "BashTool" in policy.revoked
                or policy.root != (Path(value["run"]) / "project").resolve()
                or agent.target.origin() != HTTPOrigin.from_url(value["origin"])
                or policy.engagement.allowed_origins != {HTTPOrigin.from_url(value["origin"])}
                or policy.engagement.allowed_tcp):
            raise ValueError("shell preset requires its fresh scoped runtime and enforcing worker")
        for name in ("shell", "bash"):
            policy.restore_tool(name)
        return await original(agent, *args, **kwargs)

    with patch.object(headless, "run_headless", run):
        yield


def launch_isolated(value: dict, receipt: Path, max_steps: int | None, *, headless: bool,
                    interactive: bool, non_interactive: bool, execute_prompt: bool,
                    yolo: bool, accept_unknown_http_effects: bool, cli_args: list[str]) -> int:
    """Change storage paths and delegate behavior/validation to the normal CLI."""
    managed = {"--target", "--resume", "--prompt-file", "--log", "--debug-session-path",
               "--headless-output", "--headless", "--interactive", "--non-interactive",
               "--execute-prompt", "--max-steps", "--yolo", "--accept-unknown-http-effects"}
    if any(arg.split("=", 1)[0] in managed for arg in cli_args):
        raise ValueError("use launcher options for target, input modes and isolated output paths")
    run = Path(value["run"])
    steps = max_steps if max_steps is not None else value["runtime_options"]["max_steps"]
    argv = ["kagent", "--target", value["origin"],
            "--log", str(run / "logs/kagent.log"),
            "--debug-session-path", str(run / "logs/session.jsonl")]
    if steps is not None:
        argv.extend(["--max-steps", str(steps)])
    if "reviewed_request" in value:
        argv.extend(["--prompt-file", str(Path(value["profile"]) / "whole-target-request.txt")])
    if yolo:
        argv.append("--yolo")
    if accept_unknown_http_effects:
        argv.append("--accept-unknown-http-effects")
    if headless:
        argv.extend(["--headless", "--headless-output", str(run / "logs/headless")])
    if execute_prompt:
        argv.append("--execute-prompt")
    if interactive:
        argv.append("--interactive")
    if non_interactive:
        argv.append("--non-interactive")
    argv.extend(cli_args)
    with bound_runtime(value) as runtime, patch.object(sys, "argv", argv):
        # Reuse all normal CLI checks, including headless YOLO's explicit finite
        # grant requirement. Invalid flags must not consume a fresh profile.
        flags = runtime.parse_flags(argv[1:])
        private_write(run / "launch-started.json", encode({
            "profile_sha256": digest(regular(receipt)), "max_steps": steps,
            "headless": flags.headless, "interactive": flags.interactive, "yolo": flags.yolo,
            "execute_prompt": flags.execute_prompt, "mode": "isolation",
        }))
        if not headless:
            print("Opening the official KAgent TUI with isolated experiment data.")
        return runtime.cli_main()


def launch(receipt: Path, max_steps: int | None = None, *, headless: bool = False,
           interactive: bool = False, non_interactive: bool = False,
           execute_prompt: bool = False, yolo: bool = False,
           accept_unknown_http_effects: bool = False, enable_headless_shell: bool = False,
           cli_args: list[str] | None = None) -> int:
    if interactive and non_interactive:
        raise ValueError("input modes are mutually exclusive")
    if (interactive or non_interactive or execute_prompt) and not headless:
        raise ValueError("headless input/execution flags require --headless")
    if headless and not execute_prompt:
        raise ValueError("headless requires explicit --execute-prompt")
    if (not headless or interactive) and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("run requires the current interactive WSL terminal")
    if headless and interactive and not sys.stderr.isatty():
        raise ValueError("interactive headless requires stderr TTY")
    value = verify(receipt)
    if value["version"] == 4:
        if enable_headless_shell:
            raise ValueError("shell preset requires a legacy bounded profile")
        return launch_isolated(value, receipt, max_steps, headless=headless,
                               interactive=interactive, non_interactive=non_interactive,
                               execute_prompt=execute_prompt, yolo=yolo,
                               accept_unknown_http_effects=accept_unknown_http_effects,
                               cli_args=cli_args or [])
    if cli_args:
        raise ValueError("native CLI arguments require an isolation profile")
    if yolo and not accept_unknown_http_effects:
        raise ValueError("YOLO requires explicit acceptance of bounded HTTP effects")
    shell_preset = value.get("execution_preset") == "headless-shell"
    if enable_headless_shell != shell_preset or (shell_preset and not headless):
        raise ValueError("shell preset requires matching explicit --headless and --enable-headless-shell")
    if value["provider"]["backend"] != "deepseek" or value["provider"]["model"] != "deepseek-flash":
        raise ValueError("Scenario 3 requires the reviewed DeepSeek model identity")
    approved_steps = value["limits"]["max_steps"]
    if max_steps is not None and max_steps != approved_steps:
        raise ValueError("max steps differs from the approved profile")
    max_steps = approved_steps
    run = Path(value["run"])
    # Exclusive marker forbids silently repeating a run using the same profile.
    private_write(run / "launch-started.json", encode({"profile_sha256": digest(regular(receipt)),
        "max_steps": max_steps, "headless": headless, "interactive": interactive,
        "yolo": yolo, "execute_prompt": execute_prompt, "enable_headless_shell": shell_preset}))
    argv = ["kagent", "--target", value["origin"], "--max-steps", str(max_steps),
            "--prompt-file", str(Path(value["profile"]) / "whole-target-request.txt"),
            "--log", str(run / "logs/kagent.log"), "--debug-session-path", str(run / "logs/session.jsonl")]
    if yolo:
        argv.append("--yolo")
    if accept_unknown_http_effects:
        limits = value["limits"]["native_http"]
        spec = ",".join(str(part) for part in (value["origin"], "autonomous", *(
            limits[key] for key in ("seconds", "requests", "rate", "burst", "concurrency", "request_bytes", "response_bytes"))))
        argv.extend(["--http-lab-grant", spec, "--accept-unknown-http-effects"])
    if headless:
        argv.extend(["--headless", "--execute-prompt", "--interactive" if interactive else "--non-interactive",
                     "--headless-output", str(run / "logs/headless")])
    else:
        print("Opening the official KAgent TUI; review the prefilled user draft and press Enter to start.")
        print("Provider startup probes may consume API tokens before a workflow is submitted.")
    with bound_runtime(value) as runtime, patch.object(sys, "argv", argv):
        with ExitStack() as stack:
            if shell_preset:
                stack.enter_context(headless_shell_runtime(value))
            return runtime.cli_main()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify", type=Path, metavar="PROFILE_JSON")
    mode.add_argument("--launch", type=Path, metavar="PROFILE_JSON")
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--origin", default="http://127.0.0.1:8081")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approve-plan-sha256")
    parser.add_argument("--prompt-file", type=Path, help="Dry-run only: pin this reviewed request's exact bytes and SHA-256")
    parser.add_argument("--enable-headless-shell", action="store_true",
                        help="Legacy bounded profiles only: opt into the existing headless shell preset")
    parser.add_argument("--legacy-bounded", action="store_true",
                        help="Dry-run only: select the old Scenario 3 limits and generated request")
    parser.add_argument("--max-steps", type=int, help="Optional native CLI override; otherwise use normal KAgent defaults/config")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--execute-prompt", action="store_true")
    parser.add_argument("--yolo", action="store_true")
    parser.add_argument("--accept-unknown-http-effects", action="store_true")
    parser.add_argument("cli_args", nargs=argparse.REMAINDER, help="Native CLI options after --, on isolation-profile launch only")
    args = parser.parse_args(argv)
    try:
        native_args = args.cli_args[1:] if args.cli_args[:1] == ["--"] else args.cli_args
        if native_args and (not args.launch or args.cli_args[:1] != ["--"]):
            raise ValueError("native CLI options require --launch PROFILE -- ...")
        if args.legacy_bounded and (args.apply or args.verify or args.launch):
            raise ValueError("select legacy bounded behavior at dry-run")
        if args.prompt_file is not None and (args.apply or args.verify or args.launch):
            raise ValueError("select the request at dry-run; prepare/verify/run use only the reviewed plan")
        if args.enable_headless_shell and (args.apply or args.verify):
            raise ValueError("select shell preset at dry-run and explicitly enable it again at launch")
        if args.verify:
            verify(args.verify)
            print(json.dumps({"fresh_profile_verified": True, "model_called": False}))
        elif args.launch:
            return launch(args.launch, args.max_steps, headless=args.headless,
                          interactive=args.interactive, non_interactive=args.non_interactive,
                          execute_prompt=args.execute_prompt, yolo=args.yolo,
                          accept_unknown_http_effects=args.accept_unknown_http_effects,
                          enable_headless_shell=args.enable_headless_shell, cli_args=native_args)
        elif args.apply:
            if not args.plan or not args.approve_plan_sha256:
                raise ValueError("apply requires the reviewed --plan and --approve-plan-sha256")
            raw = regular(args.plan)
            if digest(raw) != args.approve_plan_sha256:
                raise ValueError("approved plan hash does not match")
            print(json.dumps({"profile": str(apply(json.loads(raw))), "launched": False}))
        else:
            from src.config.config import config_path
            if args.run_dir is None:
                raise ValueError("dry-run requires an explicit --run-dir for review")
            value = plan(args.repo, Path.home(), config_path(), args.run_dir, args.origin, args.max_steps,
                         prompt_file=args.prompt_file, enable_headless_shell=args.enable_headless_shell,
                         legacy_bounded=args.legacy_bounded)
            sys.stdout.write(encode(value).decode())
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        # No exception repr: path/decoder/config errors may contain credentials.
        message = "experiment profile refused: " + type(error).__name__
        if args.launch and (not args.headless or args.interactive) and (not sys.stdin.isatty() or not sys.stdout.isatty()):
            message += "; --run requires an interactive terminal (TTY); no headless fallback"
        print(message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
