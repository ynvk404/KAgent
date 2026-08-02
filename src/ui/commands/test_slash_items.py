from ui.commands.slash_items import (
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