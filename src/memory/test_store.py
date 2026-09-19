import logging
import os
import stat
from pathlib import Path

import pytest

import src.memory.store as memory_store
from src.memory.store import (
    MemoryStore,
    AddMemoryInput,
    format_memory_recall,
    MEMORY_INDEX_CHAR_LIMIT,
    MEMORY_RECALL_CHAR_LIMIT,
)

@pytest.fixture
def store(tmp_path):
    cwd = tmp_path / "project"
    home = tmp_path / "home"

    cwd.mkdir()
    home.mkdir()

    return MemoryStore(
        cwd=str(cwd),
        home=str(home)
    )

def test_add_and_list(store):
    fact = store.add(
        AddMemoryInput(
            text="orders API has IDOR via sequential id",
            created_at="2026-06-10T00:00:00Z"
        )
    )
    assert fact is not None

    data = store.list()
    assert len(data) == 1
    assert "orders API" in data[0].description

def test_index_contains_description(store):
    store.add(
        AddMemoryInput(
            text="prefer curl over scanners",
            type="preference",
            created_at="2026-06-10T00:00:00Z"
        )
    )

    index = store.project_dir / "MEMORY.md"
    content = index.read_text()

    assert "[preference]" in content
    assert "prefer curl over scanners" in content

def test_search_relevance(store):
    store.add(
        AddMemoryInput(
            text="orders API IDOR via sequential id on /api/orders/{id}",
            created_at="2026-06-10T00:00:01Z"
        )
    )

    store.add(
        AddMemoryInput(
            text="login uses OAuth vulnerable redirect_uri",
            created_at="2026-06-10T00:00:02Z"
        )
    )

    result = store.search("test orders endpoint idor", 5)
    assert len(result) > 0
    assert "orders API IDOR" in result[0].text

def test_project_personal_scope(store):
    store.add(
        AddMemoryInput(
            text="project-only host scope note",
            scope="project"
        )
    )

    store.add(
        AddMemoryInput(
            text="personal habit always test two accounts",
            scope="personal"
        )
    )

    scopes = sorted([x.scope for x in store.list()])
    assert scopes == ["personal", "project"]

def test_forget(store):
    store.add(
        AddMemoryInput(
            text="orders API IDOR"
        )
    )

    store.add(
        AddMemoryInput(
            text="login OAuth redirect bug"
        )
    )

    removed = store.forget("orders")
    assert len(removed) == 1

    data = store.list()
    assert len(data) == 1
    assert "login OAuth" in data[0].text

def test_empty_text(store):
    result = store.add(
        AddMemoryInput(
            text="   "
        )
    )
    assert result is None

def test_format_memory_empty():
    result = format_memory_recall([])
    assert result == ""


def test_memory_index_and_recall_have_deterministic_context_bounds(store):
    for index in range(80):
        store.add(
            AddMemoryInput(
                text=f"fact {index} " + "x" * 1000,
                description=f"description {index} " + "y" * 140,
            )
        )

    assert len(store.index()) <= MEMORY_INDEX_CHAR_LIMIT
    recalled = format_memory_recall(store.list()[:20])
    assert len(recalled) <= MEMORY_RECALL_CHAR_LIMIT
    assert "omitted" in recalled


def test_atomic_write_temp_is_private_before_chmod(tmp_path, monkeypatch):
    path = tmp_path / "secret.md"
    observed_modes = []
    real_chmod = MemoryStore._chmod_safe

    def spy_chmod(file, mode):
        observed_modes.append(stat.S_IMODE(os.stat(file).st_mode))
        real_chmod(file, mode)

    monkeypatch.setattr(MemoryStore, "_chmod_safe", staticmethod(spy_chmod))

    MemoryStore._atomic_write(path, "secret")

    assert observed_modes == [0o600]


def test_atomic_write_preserves_colliding_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "fact.md"
    monkeypatch.setattr(memory_store.secrets, "token_hex", lambda _: "fixed")
    temp = Path(f"{path}.tmp.fixed")
    temp.write_text("another writer's data", encoding="utf-8")

    with pytest.raises(FileExistsError):
        MemoryStore._atomic_write(path, "new data")

    assert temp.read_text(encoding="utf-8") == "another writer's data"
    assert not path.exists()


def test_list_refreshes_cached_fact_after_manual_edit(store):
    fact = store.add(AddMemoryInput(text="old fact detail"))
    assert fact is not None
    assert store.list()[0].text == "old fact detail"

    file = Path(fact.file)
    file.write_text(
        file.read_text(encoding="utf-8").replace("old fact detail", "new fact detail"),
        encoding="utf-8",
    )

    assert store.list()[0].text == "new fact detail"


def test_non_mapping_front_matter_is_skipped(store, caplog):
    store.project_dir.mkdir(parents=True)
    (store.project_dir / "bad.md").write_text(
        "---\n- not a mapping\n---\nbody", encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING, logger="kagent.memory.store"):
        assert store.list() == []

    assert any("invalid front matter" in r.getMessage() for r in caplog.records)


def test_invalid_metadata_types_are_normalized_before_search(store):
    store.project_dir.mkdir(parents=True)
    (store.project_dir / "bad-types.md").write_text(
        "---\nname: {not: text}\ndescription: [not, text]\n"
        "created_at: [not, a, timestamp]\n---\nsearchable body",
        encoding="utf-8",
    )

    facts = store.search("searchable")

    assert len(facts) == 1
    assert facts[0].name == "bad-types"
    assert facts[0].description == "searchable body"
    assert facts[0].created_at == ""


def test_description_round_trips_without_yaml_front_matter_injection(store):
    fact = store.add(
        AddMemoryInput(
            text="ordinary body",
            description="visible description\nname: injected",
            created_at="2026-06-10T00:00:00Z\nname: injected",
        )
    )
    assert fact is not None

    store.scope_cache.clear()
    loaded = store.list()[0]

    assert loaded.name == fact.name
    assert loaded.description == "visible description\nname: injected"
    assert loaded.created_at == "2026-06-10T00:00:00Z\nname: injected"

def test_unreadable_fact_is_reported_and_skipped(store, caplog):
    store.add(AddMemoryInput(text="target is example.com", scope="project"))

    fact_file = next(
        f for f in store.project_dir.glob("*.md") if f.name != "MEMORY.md"
    )
    fact_file.chmod(0o000)

    try:
        with caplog.at_level(logging.WARNING, logger="kagent.memory.store"):
            store.scope_cache.clear()
            facts = store.list()
    finally:
        fact_file.chmod(0o600)

    assert facts == []
    assert any(fact_file.name in r.getMessage() for r in caplog.records)


def test_forget_reports_facts_it_could_not_delete(store, caplog):
    store.add(AddMemoryInput(text="target is example.com", scope="project"))

    store.project_dir.chmod(0o500)
    try:
        with caplog.at_level(logging.WARNING, logger="kagent.memory.store"):
            removed = store.forget("example.com")
    finally:
        store.project_dir.chmod(0o700)

    assert removed == []
    assert any("could not forget" in r.getMessage() for r in caplog.records)
