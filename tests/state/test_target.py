import pytest

from src.target.target import Target, TargetSnapshot, new_target


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            {"baseURL": "  https://app.example.test  ", "name": "  audit  "},
            ("https://app.example.test", "audit"),
        ),
        ({"baseURL": "   ", "name": "   "}, ("", "")),
        ({"baseURL": None, "name": 1}, ("", "")),
        ({"unexpected": "ignored"}, ("", "")),
        (None, ("", "")),
    ],
)
def test_from_dict_preserves_target_normalization(raw, expected):
    target = Target.from_dict(raw)

    assert (target.base_url(), target.name()) == expected
    assert target.empty() is target.is_empty()


def test_copy_from_snapshot_uses_setter_normalization():
    target = Target()

    target.copy_from(
        TargetSnapshot(
            baseURL="  https://app.example.test  ",
            name="  audit  ",
        )
    )

    assert target.to_dict() == {
        "baseURL": "https://app.example.test",
        "name": "audit",
    }


def test_target_round_trip_and_factory_are_independent():
    original = Target("https://app.example.test", "audit")
    restored = Target.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert new_target().empty()
