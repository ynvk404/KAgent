import asyncio
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import pytest
import stat
from threading import Event, Thread

from . import store as intelligence_store
from .store import (
    IntelligenceScenario,
    IntelligenceStore,
    BUILTIN_SCENARIOS,
    redact,
    tokenize,
    stable_scenario_id,
    format_intelligence_context,
    INTELLIGENCE_CONTEXT_CHAR_LIMIT,
)

@pytest.fixture
def temp_store_paths(tmp_path: Path):
    cwd = tmp_path / "project_dir"
    home = tmp_path / "home_dir"
    cwd.mkdir()
    home.mkdir()
    return cwd, home

@pytest.fixture
def store(temp_store_paths):
    cwd, home = temp_store_paths
    return IntelligenceStore(cwd=cwd, home=home)

@pytest.fixture
def sample_scenario() -> IntelligenceScenario:
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

class TestIntelligenceScenarioModel:
    def test_to_wire_camel_case_conversion(self, sample_scenario: IntelligenceScenario):
        wire = sample_scenario.to_wire()
        assert wire["id"] == "test-sqli-01"
        assert wire["recommendedChecks"] == ["sqlmap -u", "time-based sleep payloads"]
        assert wire["avoidMissing"] == ["blind sqli"]
        assert "recommended_checks" not in wire

    def test_to_wire_omits_none_values(self):
        scenario = IntelligenceScenario(id="test-02", source_session_id=None, updated_at=None)
        wire = scenario.to_wire()
        assert "sourceSessionId" not in wire
        assert "updatedAt" not in wire

    def test_from_wire_parses_camel_case_and_snake_case(self):
        wire_data = {
            "id": "wire-01",
            "title": "CSRF in Password Reset",
            "recommendedChecks": ["check token validation"],
            "avoid_missing": ["missing anti-csrf token"],
            "unknownField": "should_be_ignored",
        }
        scenario = IntelligenceScenario.from_wire(wire_data)
        assert scenario.id == "wire-01"
        assert scenario.recommended_checks == ["check token validation"]
        assert scenario.avoid_missing == ["missing anti-csrf token"]
        assert not hasattr(scenario, "unknownField")

class TestRedactAndUtils:
    def test_redact_secrets(self):
        text = "Database config: password = supersecret123 and api_key: abc-123-xyz"
        redacted = redact(text)
        assert "supersecret123" not in redacted
        assert "password=[REDACTED]" in redacted

    def test_stable_scenario_id_consistency(self):
        id1 = stable_scenario_id("vulnerability", "SQL Injection Test")
        id2 = stable_scenario_id("vulnerability", "SQL Injection Test")
        assert id1 == id2
        assert id1.startswith("learned-vulnerability-")

    def test_tokenize_query(self):
        tokens = tokenize("SQL Injection in /api/v1/login! express.js")
        assert "sql" in tokens
        assert "injection" in tokens
        assert "express.js" in tokens

class TestIntelligenceStorePersistence:
    def test_init_paths(self, store: IntelligenceStore, temp_store_paths):
        cwd, home = temp_store_paths
        assert store.project_path == cwd / ".kagent" / "intelligence" / "scenarios.jsonl"
        assert store.personal_path == home / ".kagent" / "intelligence" / "scenarios.jsonl"

    @pytest.mark.asyncio
    async def test_append_and_list_scenarios(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        saved = await store.append(sample_scenario)
        assert saved is not None
        assert saved.id == sample_scenario.id

        all_scenarios = store.list()
        assert len(all_scenarios) == len(BUILTIN_SCENARIOS) + 1
        assert any(s.id == sample_scenario.id for s in all_scenarios)

    @pytest.mark.asyncio
    async def test_file_permissions(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        await store.append(sample_scenario)
        assert store.project_path.exists()
        mode = store.project_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_append_creates_file_private_before_chmod(
        self, store: IntelligenceStore, sample_scenario: IntelligenceScenario, monkeypatch
    ):
        observed_modes = []
        real_chmod = os.chmod

        def spy_chmod(path, mode):
            if Path(path) == store.project_path:
                observed_modes.append(stat.S_IMODE(os.stat(path).st_mode))
            real_chmod(path, mode)

        monkeypatch.setattr(os, "chmod", spy_chmod)

        store.append_batch([sample_scenario], scope="project")

        assert observed_modes == [0o600]

    @pytest.mark.asyncio
    async def test_append_deduplication(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        await store.append(sample_scenario)
        saved_again = await store.append(sample_scenario)
        assert saved_again is None

        stats = store.get_stats()
        assert stats["project"] == 1

    def test_file_caching(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        store.append_batch([sample_scenario], scope="project")

        res1 = store.read_scenarios(store.project_path, "project")
        cache_key = str(store.project_path)
        assert cache_key in store.file_cache

        res2 = store.read_scenarios(store.project_path, "project")
        assert res1 is res2

    def test_corrupt_jsonl_handling(self, store: IntelligenceStore):
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

    def test_prune_temp_is_private_before_chmod(self, store: IntelligenceStore, monkeypatch):
        store.project_path.parent.mkdir(parents=True)
        scenarios = [
            IntelligenceScenario(id=f"scenario-{i}", title=f"Scenario {i}")
            for i in range(2)
        ]
        store.project_path.write_text(
            "".join(json.dumps(s.to_wire()) + "\n" for s in scenarios),
            encoding="utf-8",
        )
        monkeypatch.setattr(intelligence_store, "MAX_SCENARIOS_PER_FILE", 1)
        monkeypatch.setattr(intelligence_store.secrets, "token_hex", lambda _: "fixed")
        observed_modes = []
        real_chmod = os.chmod

        def spy_chmod(path, mode):
            if str(path).endswith(".tmp.fixed"):
                observed_modes.append(stat.S_IMODE(os.stat(path).st_mode))
            real_chmod(path, mode)

        monkeypatch.setattr(os, "chmod", spy_chmod)

        store.prune_if_too_long(store.project_path, "project")

        assert observed_modes == [0o600]

    def test_prune_preserves_colliding_temp_file(self, store: IntelligenceStore, monkeypatch):
        store.project_path.parent.mkdir(parents=True)
        scenarios = [
            IntelligenceScenario(id=f"scenario-{i}", title=f"Scenario {i}")
            for i in range(2)
        ]
        original = "".join(json.dumps(s.to_wire()) + "\n" for s in scenarios)
        store.project_path.write_text(original, encoding="utf-8")
        monkeypatch.setattr(intelligence_store, "MAX_SCENARIOS_PER_FILE", 1)
        monkeypatch.setattr(intelligence_store.secrets, "token_hex", lambda _: "fixed")
        temp = Path(f"{store.project_path}.tmp.fixed")
        temp.write_text("another writer's data", encoding="utf-8")

        store.prune_if_too_long(store.project_path, "project")

        assert temp.read_text(encoding="utf-8") == "another writer's data"
        assert store.project_path.read_text(encoding="utf-8") == original

    def test_lock_timeout_does_not_append_without_cross_process_lock(
        self, store: IntelligenceStore, sample_scenario: IntelligenceScenario, monkeypatch
    ):
        class TimedOutLock:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                raise intelligence_store.filelock.Timeout("timed out")

            def __exit__(self, *_args):
                return False

        monkeypatch.setattr(intelligence_store.filelock, "FileLock", TimedOutLock)

        with pytest.raises(intelligence_store.filelock.Timeout):
            store.append_batch([sample_scenario], scope="project")

        assert not store.project_path.exists()

    def test_clear_serializes_with_inflight_append(
        self, temp_store_paths, monkeypatch
    ):
        cwd, home = temp_store_paths
        appending_store = IntelligenceStore(cwd=cwd, home=home)
        clearing_store = IntelligenceStore(cwd=cwd, home=home)
        appending_store.project_path.parent.mkdir(parents=True)
        appending_store.project_path.write_text(
            json.dumps(IntelligenceScenario(id="old", title="Old").to_wire()) + "\n",
            encoding="utf-8",
        )

        append_read = Event()
        release_append = Event()
        original_read = appending_store.read_scenarios

        def pause_after_read(path, scope):
            result = original_read(path, scope)
            append_read.set()
            release_append.wait(timeout=1)
            return result

        monkeypatch.setattr(appending_store, "read_scenarios", pause_after_read)
        append_thread = Thread(
            target=lambda: appending_store.append_batch(
                [IntelligenceScenario(id="new", title="New")], "project"
            )
        )
        append_thread.start()
        assert append_read.wait(timeout=1)

        clear_started = Event()
        real_write_text = Path.write_text

        def spy_write_text(path, data, *args, **kwargs):
            if path == appending_store.project_path and data == "":
                clear_started.set()
            return real_write_text(path, data, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", spy_write_text)
        clear_thread = Thread(
            target=lambda: asyncio.run(clearing_store.clear("project"))
        )
        clear_thread.start()
        clear_started.wait(timeout=0.1)
        release_append.set()
        append_thread.join(timeout=1)
        clear_thread.join(timeout=1)

        assert intelligence_store.read_jsonl(
            appending_store.project_path, "project"
        ) == []

class TestIntelligenceSearch:
    def test_search_matching_and_ranking(self, store: IntelligenceStore):
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

    def test_search_does_not_match_short_tokens_inside_unrelated_words(
        self, store: IntelligenceStore
    ):
        unrelated = IntelligenceScenario(
            id="hidden",
            title="Hidden deployment setting",
            confidence=1.0,
        )
        store.append_batch([unrelated], scope="project")

        results = store.search("id", limit=50)

        assert all(result["scenario"].id != "hidden" for result in results)

class TestContinuousLearning:
    @pytest.mark.asyncio
    async def test_learn_from_text_extraction(self, store: IntelligenceStore):
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

        stats = store.get_stats()
        assert stats["project"] > 0
        assert stats["personal"] > 0

    @pytest.mark.asyncio
    async def test_clear_intelligence(self, store: IntelligenceStore, sample_scenario: IntelligenceScenario):
        await store.append(sample_scenario)
        store.append_batch([sample_scenario], scope="personal")

        assert store.get_stats()["project"] == 1
        assert store.get_stats()["personal"] == 1

        await store.clear(scope="project")
        assert store.get_stats()["project"] == 0
        assert store.get_stats()["personal"] == 1

        await store.clear(scope="all")
        assert store.get_stats()["personal"] == 0

class TestContextFormatter:
    def test_format_intelligence_context(self, sample_scenario: IntelligenceScenario):
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
        assert format_intelligence_context([]) == ""

    def test_format_intelligence_context_is_bounded(self):
        results = [
            {
                "scenario": IntelligenceScenario(
                    id=f"large-{index}",
                    title=f"Large scenario {index}",
                    lesson="x" * 4000,
                    recommended_checks=["y" * 500] * 12,
                ),
                "score": 10,
                "matched": ["large"],
            }
            for index in range(5)
        ]

        rendered = format_intelligence_context(results)
        assert len(rendered) <= INTELLIGENCE_CONTEXT_CHAR_LIMIT
        assert "omitted" in rendered
