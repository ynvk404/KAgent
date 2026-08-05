"""
Test bổ sung cho các fix mới trong store.py — không có trong bản
test_store.py ported từ TS, vì các hành vi này KHÔNG tồn tại (hoặc
không đúng) trong bản Python trước khi fix.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path

import pytest

from src.llm.types import Message
from src.session.store import Store, SessionMemory, dir_from_path, list_dir, new_id

class TestEmptyPathGuards:
    @pytest.mark.asyncio
    async def test_save_is_noop_with_empty_path(self, tmp_path):
        store = Store("", "")
        # Trước fix: crash hoặc ghi nhầm vào cwd. Sau fix: no-op im lặng.
        await store.save([Message(role="user", content="x")], None)
        assert not any(Path(".").glob("*.tmp.*"))

    @pytest.mark.asyncio
    async def test_clear_is_noop_with_empty_path(self):
        store = Store("", "")
        # Trước fix: Path("") -> Path(".") -> unlink(".") raise IsADirectoryError.
        await store.clear()  # không được raise

    @pytest.mark.asyncio
    async def test_save_context_snapshot_is_noop_with_empty_path(self):
        store = Store("", "")
        out = await store.save_context_snapshot("hello")
        assert out == ""


class TestTmpFilePermissionRace:
    @pytest.mark.asyncio
    async def test_tmp_file_is_0600_at_creation_not_only_after_rename(
        self, tmp_path, monkeypatch
    ):
        """
        Bug bảo mật cũ: `open(tmp, "x")` tạo file theo umask tiến trình
        (thường 0644), rồi mới os.replace() + chmod(0600) SAU đó. Có
        một khoảng hở khi file .tmp.* chứa credentials nằm trên đĩa với
        quyền group/other-readable.

        Test này chặn ngay trước os.replace() để kiểm tra quyền của
        chính file .tmp lúc đó (không phải quyền của file đích sau khi
        rename+chmod), để bug cũ chắc chắn bị bắt.
        """
        store = Store.new_with_id(tmp_path, new_id())
        observed_modes = []

        real_replace = os.replace

        def spy_replace(src, dst):
            observed_modes.append(stat.S_IMODE(os.stat(src).st_mode))
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", spy_replace)

        memory = SessionMemory(credentials=["super-secret-token"])
        await store.save([Message(role="user", content="x")], None, memory)

        assert observed_modes, "os.replace was never called"
        assert observed_modes[0] == 0o600, (
            f"tmp file had mode {oct(observed_modes[0])} before rename; "
            "should be 0600 from creation, not only after chmod"
        )


class TestCrossFormatMemoryCompat:
    @pytest.mark.asyncio
    async def test_loads_memory_written_by_ts_store_camel_case(self, tmp_path):
        """
        Bug cũ: SessionMemory(**memory_data) raise TypeError trên key
        camelCase (updatedAt/lastCompactedAt/lastSummary) do TS CLI ghi,
        bị nuốt bởi `except Exception: memory = None` -> toàn bộ memory
        (kể cả credentials, findings...) biến mất im lặng khi Python
        load lại session do TS lưu.
        """
        store = Store.new_with_id(tmp_path, "ts-written")
        ts_style_file = {
            "updated_at": "2026-01-01T00:00:00",
            "id": "ts-written",
            "target": None,
            "memory": {
                "version": 1,
                "updatedAt": "2026-01-01T00:00:00",
                "compactions": 3,
                "lastCompactedAt": "2026-01-01T00:00:00",
                "lastSummary": "compacted once",
                "objectives": [],
                "plan": [],
                "completed": [],
                "findings": ["idor on /api/orders/1"],
                "tested": [],
                "files": [],
                "commands": [],
                "credentials": ["USER_A_TOKEN placeholder"],
                "todos": [],
            },
            "messages": [{"role": "user", "content": "hi"}],
        }
        store.path.write_text(json.dumps(ts_style_file), encoding="utf-8")

        loaded = store.load()

        assert loaded.memory is not None, (
            "memory bị drop khi load file do TS store ghi (camelCase keys)"
        )
        assert loaded.memory.compactions == 3
        assert loaded.memory.last_compacted_at == "2026-01-01T00:00:00"
        assert loaded.memory.last_summary == "compacted once"
        assert loaded.memory.credentials == ["USER_A_TOKEN placeholder"]

    @pytest.mark.asyncio
    async def test_still_loads_native_python_snake_case_memory(self, tmp_path):
        # Không được regress đường load bình thường khi tự Python ghi/đọc.
        store = Store.new_with_id(tmp_path, new_id())
        memory = SessionMemory(compactions=9, last_summary="native")
        await store.save([Message(role="user", content="hi")], None, memory)
        loaded = store.load()
        assert loaded.memory is not None
        assert loaded.memory.compactions == 9
        assert loaded.memory.last_summary == "native"


class TestListDir:
    def test_returns_empty_list_for_missing_dir(self, tmp_path):
        assert list_dir(tmp_path / "does-not-exist") == []

    @pytest.mark.asyncio
    async def test_lists_newest_first_and_skips_corrupt_files(self, tmp_path):
        store_old = Store.new_with_id(tmp_path, "old-session")
        store_new = Store.new_with_id(tmp_path, "new-session")

        await store_old.save([Message(role="user", content="first one")], None)
        # Ghi đè updated_at thủ công để đảm bảo thứ tự rõ ràng, không phụ
        # thuộc vào độ phân giải thời gian giữa 2 lần save liên tiếp.
        raw_old = json.loads(store_old.path.read_text())
        raw_old["updated_at"] = "2020-01-01T00:00:00"
        store_old.path.write_text(json.dumps(raw_old))

        await store_new.save([Message(role="user", content="second one")], None)
        raw_new = json.loads(store_new.path.read_text())
        raw_new["updated_at"] = "2026-01-01T00:00:00"
        store_new.path.write_text(json.dumps(raw_new))

        (tmp_path / "corrupt-session.json").write_text("{not valid json")

        entries = list_dir(tmp_path)
        ids = [e.id for e in entries]

        assert "corrupt-session.json" not in [Path(e.path).name for e in entries]
        assert ids.index("new-session") < ids.index("old-session")

    @pytest.mark.asyncio
    async def test_preview_strips_referenced_files_marker_and_first_line_only(
        self, tmp_path
    ):
        store = Store.new_with_id(tmp_path, new_id())
        content = "Investigate login bypass\nsecond line\n\n# Referenced files\n\napp.py"
        await store.save([Message(role="user", content=content)], None)

        entries = list_dir(tmp_path)
        assert entries[0].preview == "Investigate login bypass"

    @pytest.mark.asyncio
    async def test_preview_truncates_long_first_line_with_ellipsis(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        long_line = "x" * 100
        await store.save([Message(role="user", content=long_line)], None)

        entries = list_dir(tmp_path)
        assert len(entries[0].preview) == 80
        assert entries[0].preview.endswith("…")

    @pytest.mark.asyncio
    async def test_preview_falls_back_when_no_user_messages(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save([Message(role="assistant", content="hi")], None)

        entries = list_dir(tmp_path)
        assert entries[0].preview == "(no user messages)"