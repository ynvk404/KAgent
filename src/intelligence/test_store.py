from datetime import datetime, timezone
from pathlib import Path
import json
import pytest

from .store import (
    IntelligenceScenario,
    IntelligenceStore,
    BUILTIN_SCENARIOS,
    redact,
    tokenize,
    stable_scenario_id,
    format_intelligence_context,
)


# =====================================================
# Fixtures
# =====================================================

@pytest.fixture
def temp_store_paths(tmp_path: Path):
    """Tạo thư mục giả lập cho project cwd và user home."""
    cwd = tmp_path / "project_dir"
    home = tmp_path / "home_dir"
    cwd.mkdir()
    home.mkdir()
    return cwd, home


@pytest.fixture
def store(temp_store_paths):
    """Khởi tạo IntelligenceStore dùng môi trường tạm."""
    cwd, home = temp_store_paths
    return IntelligenceStore(cwd=cwd, home=home)


@pytest.fixture
def sample_scenario() -> IntelligenceScenario:
    """Tạo scenario mẫu để test."""
    return IntelligenceScenario(
        id="test-sqli-01",
        title="SQL Injection in Login Endpoint",
        category="vulnerability",
        triggers=["sqli", "login", "admin"],
        technologies=["PostgreSQL", "Express"],
        lesson="Always test blind SQL injection on auth endpoints.",
        recommended_checks=["sqlmap -u", "time-based sleep payloads"],
        avoid_missing=["blind sqli"],
        confidence=0.9,
        scope="project",
    )


# =====================================================
# 1. Data Model Tests (IntelligenceScenario)
# =====================================================

class TestIntelligenceScenarioModel:

    def test_to_wire_camel_case_conversion(self, sample_scenario: IntelligenceScenario):
        """Kiểm tra serialize từ Python snake_case sang JSON wire camelCase."""
        wire = sample_scenario.to_wire()
        assert wire["id"] == "test-sqli-01"
        assert wire["recommendedChecks"] == ["sqlmap -u", "time-based sleep payloads"]
        assert wire["avoidMissing"] == ["blind sqli"]
        assert "recommended_checks" not in wire

    def test_to_wire_omits_none_values(self):
        """Omit các trường None tương tự JSON.stringify trong TypeScript."""
        scenario = IntelligenceScenario(id="test-02", source_session_id=None, updated_at=None)
        wire = scenario.to_wire()
        assert "sourceSessionId" not in wire
        assert "updatedAt" not in wire

    def test_from_wire_parses_camel_case_and_snake_case(self):
        """Đọc đúng cả hai định dạng wire camelCase và legacy snake_case."""
        wire_data = {
            "id": "wire-01",
            "title": "CSRF in Password Reset",
            "recommendedChecks": ["check token validation"],
            "avoid_missing": ["missing anti-csrf token"],  # legacy snake_case
            "unknownField": "should_be_ignored",
        }
        scenario = IntelligenceScenario.from_wire(wire_data)
        assert scenario.id == "wire-01"
        assert scenario.recommended_checks == ["check token validation"]
        assert scenario.avoid_missing == ["missing anti-csrf token"]
        assert not hasattr(scenario, "unknownField")


# =====================================================
# 2. Redaction & String Utility Tests
# =====================================================

class TestRedactAndUtils:

    def test_redact_secrets(self):
        """Kiểm tra việc ẩn thông tin nhạy cảm (passwords, tokens, api keys)."""
        text = "Database config: password = supersecret123 and api_key: abc-123-xyz"
        redacted = redact(text)
        assert "supersecret123" not in redacted
        assert "password=[REDACTED]" in redacted

    def test_stable_scenario_id_consistency(self):
        """Bảo đảm FNV-1a hash sinh ID nhất quán."""
        id1 = stable_scenario_id("vulnerability", "SQL Injection Test")
        id2 = stable_scenario_id("vulnerability", "SQL Injection Test")
        assert id1 == id2
        assert id1.startswith("learned-vulnerability-")

    # src/intelligence/test_store.py

    def test_tokenize_query(self):
        """Test tách từ và làm sạch token cho search engine."""
        tokens = tokenize("SQL Injection in /api/v1/login! express.js")
        assert "sql" in tokens
        assert "injection" in tokens
        assert "express.js" in tokens  # Token giữ nguyên tên file có đuôi .js


# =====================================================
# 3. IntelligenceStore Persistence & Cache Tests
# =====================================================

class TestIntelligenceStorePersistence:

    def test_init_paths(self, store: IntelligenceStore, temp_store_paths):
        """Kiểm tra đường dẫn file lưu trữ project và personal."""
        cwd, home = temp_store_paths
        assert store.project_path == cwd / ".pentesterflow" / "intelligence" / "scenarios.jsonl"
        assert store.personal_path == home / ".pentesterflow" / "intelligence" / "scenarios.jsonl"

    @pytest.mark.asyncio
    async def test_append_and_list_scenarios(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        """Thêm scenario mới và đọc danh sách."""
        saved = await store.append(sample_scenario)
        assert saved is not None
        assert saved.id == sample_scenario.id

        all_scenarios = store.list()
        # Bao gồm cả builtin scenarios + item vừa thêm
        assert len(all_scenarios) == len(BUILTIN_SCENARIOS) + 1
        assert any(s.id == sample_scenario.id for s in all_scenarios)

    @pytest.mark.asyncio
    async def test_file_permissions(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        """Đảm bảo file JSONL được tạo với quyền an toàn (0600)."""
        await store.append(sample_scenario)
        assert store.project_path.exists()
        mode = store.project_path.stat().st_mode & 0o777
        assert mode == 0o600

    @pytest.mark.asyncio
    async def test_append_deduplication(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        """Bảo đảm trùng lặp (ID hoặc Title + Category) không bị ghi ghi đè/nhân bản."""
        await store.append(sample_scenario)
        # Ghi lại scenario trùng ID
        saved_again = await store.append(sample_scenario)
        assert saved_again is None

        # Tổng số scenario trong project scope vẫn chỉ là 1
        stats = store.get_stats()
        assert stats["project"] == 1

    def test_file_caching(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        """Kiểm tra cơ chế file_cache theo mtime và size."""
        store.append_batch([sample_scenario], scope="project")

        # Lần 1: Đọc từ đĩa và cache lại
        res1 = store.read_scenarios(store.project_path, "project")
        cache_key = str(store.project_path)
        assert cache_key in store.file_cache

        # Lần 2: Trả về trực tiếp từ cache
        res2 = store.read_scenarios(store.project_path, "project")
        assert res1 is res2

    def test_corrupt_jsonl_handling(self, store: IntelligenceStore):
        """Đảm bảo bỏ qua các dòng JSONL bị hỏng mà không gây crash crash app."""
        store.project_path.parent.mkdir(parents=True, exist_ok=True)
        store.project_path.write_text(
            '{"id": "valid-1", "title": "Valid"}\n'
            'CORRUPTED_NON_JSON_LINE\n'
            '{"id": "valid-2", "title": "Valid 2"}\n',
            encoding="utf-8"
        )
        scenarios = store.read_scenarios(store.project_path, "project")
        assert len(scenarios) == 2
        assert scenarios[0].id == "valid-1"
        assert scenarios[1].id == "valid-2"


# =====================================================
# 4. Search Engine Tests
# =====================================================

class TestIntelligenceSearch:

# src/intelligence/test_store.py

    def test_search_matching_and_ranking(self, store: IntelligenceStore):
        """Kiểm tra khả năng tìm kiếm và sắp xếp điểm số (score)."""
        s1 = IntelligenceScenario(
            id="s1",
            title="Custom Unique Keyword Scenario",
            triggers=["customuniquequerykey"],
            confidence=1.0
        )
        s2 = IntelligenceScenario(
            id="s2",
            title="Unrelated Vulnerability",
            triggers=["xss"],
            confidence=0.9
        )
        store.append_batch([s1, s2], scope="project")

        results = store.search("customuniquequerykey", limit=5)
        assert len(results) > 0
        top_result = results[0]
        assert top_result["scenario"].id == "s1"


# =====================================================
# 5. Continuous Learning Tests (`learn_from_text`)
# =====================================================

class TestContinuousLearning:

    @pytest.mark.asyncio
    async def test_learn_from_text_extraction(self, store: IntelligenceStore):
        """Kiểm tra việc bóc tách thông tin từ văn bản báo cáo/markdown."""
        input_text = """
        # User Preferences
        - Always keep responses concise without code blocks unless requested.

        # What Worked Well
        - Successfully verified SQL injection using sqlmap time-based payloads.

        # Lessons Learned
        - Missed checking ecosystem.config.js on server.js exposure.
        """

        extracted = await store.learn_from_text(input_text, source_session_id="sess-123")
        assert len(extracted) > 0

        # Mặc định learn_from_text sẽ ghi vào CẢ project và personal scope
        stats = store.get_stats()
        assert stats["project"] > 0
        assert stats["personal"] > 0

    @pytest.mark.asyncio
    async def test_clear_intelligence(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        """Kiểm tra hàm clear xóa sạch dữ liệu theo scope."""
        await store.append(sample_scenario)
        store.append_batch([sample_scenario], scope="personal")

        assert store.get_stats()["project"] == 1
        assert store.get_stats()["personal"] == 1

        # Clear project scope
        await store.clear(scope="project")
        assert store.get_stats()["project"] == 0
        assert store.get_stats()["personal"] == 1

        # Clear all
        await store.clear(scope="all")
        assert store.get_stats()["personal"] == 0


# =====================================================
# 6. LLM Context Formatter Tests
# =====================================================

class TestContextFormatter:

    def test_format_intelligence_context(self, sample_scenario: IntelligenceScenario):
        """Kiểm tra định dạng Markdown output gửi cho LLM."""
        search_results = [
            {
                "scenario": sample_scenario,
                "score": 15.5,
                "matched": ["title:sqli", "triggers:login"],
            }
        ]

        formatted = format_intelligence_context(search_results)
        assert "# Local KAgent Intelligence" in formatted
        assert f"## {sample_scenario.title}" in formatted
        assert "Category: vulnerability" in formatted
        assert "sqlmap -u" in formatted

    def test_format_empty_results(self):
        """Không có kết quả search thì trả về chuỗi rỗng."""
        assert format_intelligence_context([]) == ""