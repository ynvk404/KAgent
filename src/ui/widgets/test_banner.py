# ui/widgets/test_banner.py

from ui.widgets.banner import (
    Banner,
    BannerData,
    model_pill,
)


# ==========================================================
# model_pill
# ==========================================================


def test_model_pill_yes():
    pill = model_pill("yes")

    assert pill is not None
    assert pill.text == "tools ✓"
    assert pill.color == "green"



def test_model_pill_no():
    pill = model_pill("no")

    assert pill is not None
    assert pill.text == "NO TOOLS"
    assert pill.color == "red"



def test_model_pill_unknown():
    pill = model_pill("unknown")

    assert pill is not None
    assert pill.text == "tools ?"



def test_model_pill_probing():
    pill = model_pill("probing")

    assert pill is not None
    assert pill.text == "probing…"



def test_model_pill_none():
    assert model_pill(None) is None



# ==========================================================
# Banner render
# ==========================================================


def get_text(lines):
    """
    Convert BannerLine -> text
    """
    return "\n".join(
        line.text
        for line in lines
    )



def test_banner_basic():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "Welcome to pentestagent" in text
    assert "Provider: ollama" in text
    assert "Model: qwen3.5" in text
    assert "Path: /workspace" in text



def test_banner_provider_state():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            state="local",
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "Provider: ollama (local)" in text



def test_banner_endpoint():

    banner = Banner(
        BannerData(
            provider="openrouter",
            model="deepseek",
            endpoint="https://openrouter.ai",
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "Endpoint: https://openrouter.ai" in text



def test_banner_context_window():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            context_window=256000,
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "ctx 256000" in text



def test_banner_tool_support():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            tool_support="yes",
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "[tools ✓]" in text



def test_banner_status():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            status="ready",
            cwd="/workspace",
        )
    )


    text = get_text(
        banner.render()
    )


    assert "Status: ready" in text



def test_banner_line_has_color():

    banner = Banner(
        BannerData(
            provider="ollama",
            model="qwen3.5",
            cwd="/workspace",
        )
    )


    lines = banner.render()


    assert len(lines) > 0

    assert hasattr(
        lines[0],
        "color"
    )