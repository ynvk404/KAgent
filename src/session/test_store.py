"""
Round-trip + crash-safety tests cho session store.
Port từ store.test.ts (TypeScript) sang pytest.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path

import pytest

from src.llm.types import Message
from src.session.store import (
    Store,
    SessionMemory,
    cleanup_stale_temps,
    new_id,
    validate_id,
)
from src.target.target import Target


# ============================================================
# new_id / validate_id
# ============================================================


class TestNewIdValidateId:
    def test_generates_uuidv4_shaped_ids(self):
        id_ = new_id()
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            id_,
        )

    def test_rejects_path_traversal_in_ids(self):
        with pytest.raises(ValueError):
            validate_id("../etc/passwd")
        with pytest.raises(ValueError):
            validate_id("a/b")
        with pytest.raises(ValueError):
            validate_id("")

    def test_accepts_a_normal_id(self):
        # Không raise.
        validate_id(new_id())


# ============================================================
# Store
# ============================================================


class TestStore:
    @pytest.mark.asyncio
    async def test_round_trips_messages_and_target(self, tmp_path: Path):
        id_ = new_id()
        store = Store.new_with_id(tmp_path, id_)
        target = Target()
        target.set_base_url("https://app.example.com")

        await store.save(
            [
                Message(role="system", content="sys"),
                Message(role="user", content="hi"),
            ],
            target,
        )

        loaded = store.load()
        assert len(loaded.messages) == 2
        assert loaded.messages[1].content == "hi"
        assert loaded.target is not None
        assert loaded.target.base_url() == "https://app.example.com"

    @pytest.mark.asyncio
    async def test_persists_target_as_null_when_empty(self, tmp_path: Path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save([Message(role="user", content="hi")], Target())
        loaded = store.load()
        # Lưu ý: khác với bản TS (nơi save() tự bỏ qua target rỗng),
        # bản Python hiện tại lưu target rỗng nguyên trạng nếu save()
        # không có logic check empty(). Nếu Target chưa có empty(),
        # test này sẽ cần điều chỉnh lại theo hành vi thực tế.
        assert loaded.target is None

    @pytest.mark.asyncio
    async def test_round_trips_optional_session_memory(self, tmp_path: Path):
        store = Store.new_with_id(tmp_path, new_id())
        memory = SessionMemory(
            version=1,
            updated_at="2026-06-02T00:00:00.000Z",
            compactions=1,
            last_compacted_at="2026-06-02T00:00:00.000Z",
            last_summary="summary",
            objectives=["test authz"],
            plan=["enumerate auth endpoints, then test IDOR"],
            completed=["mapped auth surface"],
            findings=["idor on /api/orders/1"],
            tested=["GET /api/orders/:id as user A/B"],
            files=["findings/idor.md"],
            commands=["curl https://app.example.com/api/orders/1"],
            credentials=["USER_A_TOKEN placeholder"],
            todos=["retest with admin role"],
        )
        await store.save([Message(role="user", content="hi")], None, memory)

        loaded = store.load()
        assert loaded.memory is not None
        assert loaded.memory.compactions == 1
        assert "idor on /api/orders/1" in loaded.memory.findings

    @pytest.mark.asyncio
    async def test_writes_compact_json_that_still_round_trips_across_many_saves(
        self, tmp_path: Path
    ):
        store = Store.new_with_id(tmp_path, new_id())
        # Nhiều lần save để test đường fsync định kỳ.
        for i in range(7):
            await store.save([Message(role="user", content=f"msg {i}")], None)

        raw = store.path.read_text(encoding="utf-8")
        # Compact: không có pretty-print indentation.
        assert '\n  "' not in raw
        assert len(raw.rstrip("\n").split("\n")) == 1

        loaded = store.load()
        assert loaded.messages[0].content == "msg 6"

    @pytest.mark.asyncio
    async def test_saved_file_leaves_no_orphan_tmp(self, tmp_path: Path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save([Message(role="user", content="x")], None)
        orphans = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
        assert orphans == []

    @pytest.mark.asyncio
    async def test_saved_file_has_0o600_perms(self, tmp_path: Path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save([Message(role="user", content="x")], None)
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        assert mode == 0o600

    @pytest.mark.asyncio
    async def test_writes_context_snapshots_under_context_directory(
        self, tmp_path: Path
    ):
        sessions_dir = tmp_path / "sessions"
        store = Store.new_with_id(sessions_dir, "abc123")
        out_path = await store.save_context_snapshot("# Context\n\nredacted history")

        assert out_path == str(tmp_path / "context" / "abc123.md")
        assert "redacted history" in Path(out_path).read_text(encoding="utf-8")

        mode = stat.S_IMODE(os.stat(out_path).st_mode)
        assert mode == 0o600


# ============================================================
# cleanup_stale_temps
# ============================================================


class TestCleanupStaleTemps:
    def test_removes_old_tmp_files_but_keeps_fresh_ones(self, tmp_path: Path):
        stale = tmp_path / "a.json.tmp.deadbeef"
        fresh = tmp_path / "b.json.tmp.cafebabe"
        stale.write_text("old")
        fresh.write_text("new")

        # Backdate file cũ đi 5 phút.
        old_time = time.time() - 5 * 60
        os.utime(stale, (old_time, old_time))

        cleanup_stale_temps(tmp_path, max_age_seconds=60)

        remaining = [p.name for p in tmp_path.iterdir()]
        assert "b.json.tmp.cafebabe" in remaining
        assert "a.json.tmp.deadbeef" not in remaining