from src.ui.commands.slash_items import (
    SLASH_ITEMS,
    filter_slash,
)


def test_returns_all_items_when_input_is_just_slash():
    result = filter_slash("/")

    assert len(result) == len(SLASH_ITEMS)



def test_returns_no_items_when_input_does_not_start_with_slash():

    assert filter_slash("hello") == []
    assert filter_slash("") == []



def test_prefix_matches_command_names():

    assert [
        s.name for s in filter_slash("/he")
    ] == [
        "/help"
    ]


    assert [
        s.name for s in filter_slash("/re")
    ] == [
        "/reset"
    ]


    assert sorted(
        s.name for s in filter_slash("/t")
    ) == [
        "/target",
        "/thinking",
    ]


    assert sorted(
        s.name for s in filter_slash("/m")
    ) == [
        "/maxsteps",
        "/memory",
        "/model",
    ]


    assert [
        s.name for s in filter_slash("/pl")
    ] == [
        "/plan"
    ]



def test_includes_provider():

    names = [
        s.name
        for s in SLASH_ITEMS
    ]

    assert "/provider" in names


    assert [
        s.name
        for s in filter_slash("/prov")
    ] == [
        "/provider"
    ]


def test_target_catalog_entry():

    item = next(
        s
        for s in SLASH_ITEMS
        if s.name == "/target"
    )


    assert item.args == "[<url>|clear]"
    assert item.description == "show, set, or clear engagement target"


def test_maxsteps_catalog_entry():

    item = next(
        s
        for s in SLASH_ITEMS
        if s.name == "/maxsteps"
    )


    assert item.args == "[<n>|default]"
    assert item.description == "show or set per-turn tool-call limit"


def test_thinking_catalog_entry():

    item = next(
        s
        for s in SLASH_ITEMS
        if s.name == "/thinking"
    )


    assert item.args == "[on|off|default]"
    assert item.description == "show or set reasoning mode"


def test_yolo_catalog_entry():

    item = next(
        s
        for s in SLASH_ITEMS
        if s.name == "/yolo"
    )


    assert item.args == "[on|off|default]"
    assert item.description == "show or set auto-approve mode for tool calls"



def test_hides_menu_when_typing_arguments():

    assert filter_slash(
        "/target https://"
    ) == []


    assert filter_slash(
        "/maxsteps 20"
    ) == []



def test_matches_case_insensitively():

    assert [
        s.name
        for s in filter_slash("/HELP")
    ] == [
        "/help"
    ]
