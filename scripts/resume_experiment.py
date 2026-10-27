#!/usr/bin/env python3
"""Resume a numbered Scenario 3 experiment using its existing data.

Run without arguments to enter a number, or pass e.g. ``50``.
``--check 50`` reads the saved session without starting KAgent.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch
import uuid


REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


class ResumeError(ValueError):
    """A fixed, credential-free message suitable for the terminal."""


def run_name(number: str) -> str:
    if not re.fullmatch(r"[0-9]{1,6}", number) or int(number) < 1:
        raise ResumeError("Số run phải là số nguyên dương, ví dụ 50 hoặc 05.")
    return f"lan-{int(number):02d}"


def load_profile(name: str) -> dict:
    from scripts.experiment_profile import regular

    root = REPO / "experiments/scenario3"
    receipt = root / "profiles" / name / "profile.json"
    if not receipt.is_file():
        raise ResumeError(f"Không tìm thấy profile của {name}.")
    value = json.loads(regular(receipt))
    expected = {"repo": REPO, "run": root / "runs" / name, "profile": receipt.parent}
    if (not isinstance(value, dict) or value.get("version") not in (2, 3, 4)
            or any(value.get(key) != str(path) for key, path in expected.items())):
        raise ResumeError("Profile không khớp thư mục experiment trong repo hiện tại.")
    for key in ("config", "original_home"):
        path = Path(value[key])
        if not path.is_absolute() or ".." in path.parts:
            raise ResumeError("Profile chứa đường dẫn không hợp lệ.")
    run = expected["run"]
    for path in (run / "project", run / "profile-home", run / "logs"):
        if not path.is_dir() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ResumeError("Thư mục dữ liệu experiment bị thiếu hoặc chứa symlink.")
    return value


def select_session(value: dict, requested: str | None, *, check: bool) -> str:
    directory = Path(value["run"]) / "profile-home/.kagent/sessions"
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ResumeError("Thư mục session chứa symlink.")
    sessions = sorted(path.stem for path in directory.glob("*.json") if path.is_file())
    if not sessions:
        raise ResumeError("Experiment này chưa có session đã lưu để mở tiếp.")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in sessions):
        raise ResumeError("Experiment chứa tên session không hợp lệ.")
    if requested is not None:
        if requested not in sessions:
            raise ResumeError("Session được chọn không thuộc experiment này.")
        return requested
    if len(sessions) == 1:
        return sessions[0]
    if check:
        raise ResumeError("Run có nhiều session; dùng --session SESSION_ID để chọn rõ phiên.")
    print("Run có nhiều session:")
    for index, session_id in enumerate(sessions, 1):
        print(f"  {index}. {session_id}")
    choice = input("Nhập số thứ tự session: ").strip()
    if not re.fullmatch(r"[0-9]{1,6}", choice) or not 1 <= int(choice) <= len(sessions):
        raise ResumeError("Số thứ tự session không hợp lệ.")
    return sessions[int(choice) - 1]


def resume(value: dict, session_id: str, *, check: bool) -> int:
    from scripts.experiment_profile import bound_runtime, regular

    run = Path(value["run"])
    # Resume deliberately accepts existing logs/runtime data and the current
    # provider config. Fresh-profile verification belongs to run_experiment.sh.
    with bound_runtime(value) as runtime:
        store = runtime.require_existing_resume_session(session_id)
        regular(store.path)
        state = store.load()
        if state.id != session_id:
            raise ResumeError("ID trong session không khớp tên tệp đã chọn.")
        print(f"{run.name}: session {session_id}, {len(state.messages)} tin nhắn.")
        if check:
            print("Chỉ kiểm tra; chưa mở TUI hoặc gọi model.")
            return 0
        suffix = uuid.uuid4().hex[:12]
        argv = ["kagent", "--resume", session_id,
                "--log", str(run / "logs" / f"kagent-resume-{suffix}.log"),
                "--debug-session-path", str(run / "logs" / f"session-resume-{suffix}.jsonl")]
        # Let the native resume restore target/workflow. Never replay the old
        # prompt, override the target, or reinstate YOLO/HTTP grants here.
        with patch.object(sys, "argv", argv):
            runtime.parse_flags(argv[1:])
            print("Mở tiếp phiên cũ với cấu hình provider hiện tại.")
            return runtime.cli_main()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("number", nargs="?", help="Số experiment, ví dụ 50 hoặc 05")
    parser.add_argument("--check", action="store_true", help="Chỉ đọc kiểm tra, không mở phiên")
    parser.add_argument("--session", help="Chọn session ID khi run có nhiều phiên")
    args = parser.parse_args(argv)
    try:
        if not args.check and (not sys.stdin.isatty() or not sys.stdout.isatty()):
            raise ResumeError("Hãy chạy script trong terminal WSL tương tác (TTY).")
        if args.number is None and args.check:
            raise ResumeError("Hãy truyền số run, ví dụ --check 50.")
        number = args.number if args.number is not None else input("Nhập số run cần mở tiếp (ví dụ 50): ").strip()
        value = load_profile(run_name(number))
        session_id = select_session(value, args.session, check=args.check)
        return resume(value, session_id, check=args.check)
    except ResumeError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Đã hủy.", file=sys.stderr)
        return 130
    except Exception as error:
        # Config/session/provider exception text can contain credentials.
        print(f"Không thể mở experiment ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    task_python = REPO / "venv-linux/bin/python"
    if not os.access(task_python, os.X_OK):
        print("Không tìm thấy Python của venv-linux; chưa mở phiên.", file=sys.stderr)
        raise SystemExit(2)
    if Path(sys.executable).absolute() != task_python:
        os.execv(str(task_python), [str(task_python), "-B", str(Path(__file__).resolve()), *sys.argv[1:]])
    raise SystemExit(main())
