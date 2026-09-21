import pytest

from src.engagement.state import EngagementState, OutOfScopeError


def test_exact_canonical_origin_scope_and_revision():
    state = EngagementState()

    assert state.initialize_target("HTTPS://App.Example:443/base")
    assert state.revision == 1
    assert state.is_in_scope("https://app.example/another-path")
    assert not state.is_in_scope("http://app.example/")
    assert not state.is_in_scope("https://other.example/")

    assert not state.initialize_target("https://app.example/changed-path")
    assert state.revision == 1


def test_out_of_scope_error_lists_configured_origin():
    state = EngagementState()
    state.initialize_target("https://app.example")

    with pytest.raises(OutOfScopeError, match="outside the active engagement scope"):
        state.require_in_scope("https://other.example/path")


def test_round_trip_preserves_minimal_engagement_state():
    state = EngagementState()
    state.initialize_target("http://juice.lab:3000")

    restored = EngagementState.from_dict(state.to_dict())

    assert restored == state


def test_multiple_origins_mutate_revision_only_on_real_changes():
    state = EngagementState()
    state.initialize_target("http://juice.lab:3000")
    initial_revision = state.revision

    added, changed = state.add_origin("HTTP://JUICE.LAB.:4000/path?q=1")
    assert changed
    assert added.as_url() == "http://juice.lab:4000"
    assert state.revision == initial_revision + 1

    _, changed = state.add_origin("http://juice.lab:4000/another")
    assert not changed
    assert state.revision == initial_revision + 1

    _, changed = state.remove_origin("http://missing.lab:5000")
    assert not changed
    assert state.revision == initial_revision + 1

    _, changed = state.remove_origin("http://juice.lab:4000")
    assert changed
    assert state.revision == initial_revision + 2


def test_scope_uses_exact_origins_even_when_hosts_may_resolve_to_same_ip():
    state = EngagementState()
    state.initialize_target("http://juice.lab:3000")
    state.add_origin("http://juice.lab:4000")

    assert state.is_in_scope("http://juice.lab:3000/a")
    assert state.is_in_scope("http://juice.lab:4000/b")
    assert not state.is_in_scope("http://juice.lab:5000/")
    assert not state.is_in_scope("https://juice.lab:3000/")
    assert not state.is_in_scope("http://127.0.0.1:3000/")
