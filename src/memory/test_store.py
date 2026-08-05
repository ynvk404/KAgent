import pytest

from src.memory.store import (
    MemoryStore,
    AddMemoryInput,
    format_memory_recall,
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