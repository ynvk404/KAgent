#!/usr/bin/env python3
"""Remove KAgent project outputs, historical docs/evidence and Python caches."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import stat
import sys


# Fixed project-local scope. Never discover deletion targets by vague file names.
OUTPUT_DIRECTORIES = (
    "docs", "artifacts", "logs", "htmlcov",
    "sessions", "findings", "recon", "captures", "web-enumeration",
    "web-input-analysis", "sql-injection", "cross-site-scripting",
    "access-control", "authentication", "csrf", "ssrf", "ssti",
    "audit", "audits", "report", "reports", "evidence",
)
RUNTIME_DIRECTORIES = (
    "coverage", "evidence", "observations", "permissions", "sessions",
    "context", "tool-results",
)
SKILL_OUTPUT_DIRECTORIES = (
    "access-control", "authentication", "command-injection", "cors-misconfiguration",
    "cross-site-scripting", "csrf", "file-upload", "findings", "jwt-misconfiguration",
    "nosql-injection", "open-redirect", "path-traversal", "recon", "sql-injection",
    "ssrf", "ssti", "web-enumeration", "web-input-analysis", "worker", "xxe",
)
BENCHMARK_PATTERNS = (
    "reasoning-*.jsonl", "*benchmark*.json", "*benchmark*.jsonl", "metrics*.jsonl",
)
CACHE_DIRECTORIES = (".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__")
CACHE_SCAN_DIRECTORIES = ("src", "tests", "benchmarks", "components", "scripts", "integrations")
BENCHMARK_EVIDENCE = Path("benchmarks/scenario1/reset/evidence")


class CleanupError(ValueError):
    pass


@dataclass(frozen=True)
class Deletion:
    path: Path
    files: int
    bytes: int


def validate_path(root: Path, path: Path) -> None:
    """Reject paths outside the root or reached through a symbolic-link parent."""
    relative = path.relative_to(root)
    if not relative.parts or ".." in relative.parts:
        raise CleanupError("invalid cleanup path")
    parent = root
    for part in relative.parts[:-1]:
        parent /= part
        if parent.is_symlink():
            raise CleanupError(f"symlink parent: {parent.relative_to(root)}")


def existing(root: Path, relative: str | Path) -> Path | None:
    path = root / relative
    validate_path(root, path)
    return path if path.exists() or path.is_symlink() else None


def walk_files(path: Path):
    if path.is_symlink() or not path.is_dir():
        yield path
        return
    for directory, subdirs, filenames in os.walk(path, followlinks=False):
        base = Path(directory)
        for name in subdirs[:]:
            child = base / name
            if child.is_symlink():
                subdirs.remove(name)
                yield child
        for name in filenames:
            yield base / name


def build_plan(root: Path, scope: str = "all", *, reset_intelligence: bool = False) -> list[Deletion]:
    candidates: set[Path] = set()

    def add_directory(relative: str | Path, *, contents: bool = False) -> None:
        path = existing(root, relative)
        if path is not None:
            if path.is_symlink() or not path.is_dir():
                raise CleanupError(f"cleanup directory must be a real directory (no symlink): {relative}")
            if contents:
                candidates.update(path.iterdir())
            else:
                candidates.add(path)

    for name in RUNTIME_DIRECTORIES:
        add_directory(f".kagent/{name}", contents=scope != "all")
    if scope == "all":
        for relative in (*OUTPUT_DIRECTORIES, *CACHE_DIRECTORIES):
            add_directory(relative)
        evidence = existing(root, BENCHMARK_EVIDENCE)
        if evidence is not None:
            if evidence.is_symlink() or not evidence.is_dir():
                raise CleanupError("benchmark evidence must be a real directory")
            # This ignore policy is configuration, not a historical receipt.
            candidates.update(p for p in evidence.iterdir() if p.name != ".gitignore")
    else:
        for name in SKILL_OUTPUT_DIRECTORIES:
            add_directory(f"artifacts/{name}", contents=True)
        if scope == "benchmark":
            add_directory("artifacts/benchmarks", contents=True)

    runtime = existing(root, ".kagent")
    if runtime is not None:
        if runtime.is_symlink() or not runtime.is_dir():
            raise CleanupError(".kagent must be a real directory")
        patterns = (".kagent.cfg.tmp.*",) + (BENCHMARK_PATTERNS if scope != "runtime" else ())
        for pattern in patterns:
            candidates.update(runtime.glob(pattern))
    candidates.update(root.glob(".kagent.cfg.tmp.*"))
    if reset_intelligence:
        for name in ("scenarios.jsonl", "scenarios.jsonl.lock"):
            path = existing(root, f".kagent/intelligence/{name}")
            if path is not None:
                if path.is_symlink() or not path.is_file():
                    raise CleanupError(f"intelligence output must be a real file: {name}")
                candidates.add(path)
    if scope == "all":
        coverage = existing(root, ".coverage")
        if coverage is not None:
            candidates.add(coverage)
        candidates.update(root.glob(".coverage.*"))

    for relative in CACHE_SCAN_DIRECTORIES if scope == "all" else ():
        path = existing(root, relative)
        if path is None:
            continue
        if path.is_symlink():
            raise CleanupError(f"symlink source directory: {relative}")
        for directory, subdirs, filenames in os.walk(path, followlinks=False):
            base = Path(directory)
            for name in subdirs[:]:
                child = base / name
                if name == "__pycache__":
                    candidates.add(child)
                    subdirs.remove(name)
                elif child.is_symlink() or child == root / BENCHMARK_EVIDENCE:
                    subdirs.remove(name)
            candidates.update(base / name for name in filenames if name.endswith((".pyc", ".pyo")))

    plan = []
    for path in sorted(candidates):
        validate_path(root, path)
        # A containing output directory already covers its descendants.
        if any(parent in candidates for parent in path.parents if parent != root):
            continue
        files = size = 0
        for file in walk_files(path):
            info = file.lstat()
            files += 1
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
        plan.append(Deletion(path, files, size))
    return plan


def hold_runner_locks(plan: list[Deletion], stack: ExitStack) -> None:
    """Do not remove control state while a benchmark owns its runner lock."""
    for deletion in plan:
        for path in walk_files(deletion.path):
            if path.name.endswith(".runner.lock"):
                if path.is_symlink() or not path.is_file():
                    raise CleanupError("invalid benchmark runner lock")
                if os.name != "posix":
                    raise CleanupError("runner lock verification requires POSIX")
                import fcntl
                handle = stack.enter_context(path.open("rb"))
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise CleanupError("benchmark is running; stop it before cleanup") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Clean project outputs. Default scope 'all' deletes ALL project docs, artifacts, "
                    "historical benchmark evidence, transient runtime state and caches.",
        epilog="Run from the repository root after stopping KAgent/benchmarks. "
               "Preserves source, tests, skills, config, virtualenvs, .git, "
               "project memory/custom skills and all ~/.kagent data. "
               "Project intelligence is retained unless --reset-intelligence is passed. "
               "This also deletes archived runs and findings under artifacts/.",
    )
    parser.add_argument("--scope", choices=("all", "runtime", "benchmark"), default="all",
                        help="all: full cleanup; runtime: transient state and skill outputs; "
                             "benchmark: runtime plus benchmark outputs. Narrow scopes retain "
                             "docs, audits, checkpoints, archives and caches")
    parser.add_argument("--reset-intelligence", "--fresh-intelligence", action="store_true",
                        help="also delete project scenarios.jsonl and its lock (all/benchmark only)")
    parser.add_argument("-n", "--dry-run", action="store_true", help="preview without deleting files")
    args = parser.parse_args(argv)
    if args.reset_intelligence and args.scope == "runtime":
        parser.error("--reset-intelligence requires --scope benchmark or all")
    root = Path.cwd().resolve()
    if (root != Path(__file__).resolve().parents[1]
            or not all((root / marker).is_file() for marker in ("pyproject.toml", "AGENTS.md", "src/paths.py"))):
        print("[ERROR] This script must be executed from the KAgent repository root.", file=sys.stderr)
        return 1
    try:
        # Finish path validation and lock checks before performing any deletion.
        plan = build_plan(root, args.scope, reset_intelligence=args.reset_intelligence)
        with ExitStack() as stack:
            if not args.dry_run:
                hold_runner_locks(plan, stack)
            label = "DRY-RUN" if args.dry_run else "DELETE"
            for deletion in plan:
                path = deletion.path
                print(f"[{label}] {path.relative_to(root)} ({deletion.files} files, {deletion.bytes} bytes)")
                if not args.dry_run:
                    validate_path(root, path)
                    if path.is_symlink() or not path.is_dir():
                        path.unlink(missing_ok=True)
                    else:
                        shutil.rmtree(path)
        total_files = sum(item.files for item in plan)
        total_size = sum(item.bytes for item in plan)
        verb = "Would remove" if args.dry_run else "Removed"
        print(f"[DONE] {verb} {total_files} files, {total_size / 1048576:.2f} MiB.")
        return 0
    except (CleanupError, OSError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
