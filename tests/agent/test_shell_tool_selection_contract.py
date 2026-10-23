"""Offline prompt/example contracts; these do not assert LLM compliance."""
import json
from pathlib import Path
import re

import pytest

from src.agent.system_prompt import BuildOptions, build_system_prompt
from src.engagement.state import EngagementState
from src.skills.registry import Registry
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool


SKILLS = Path(__file__).resolve().parents[2] / "skills"


def playbook(name):
    return (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_both_prompt_profiles_distinguish_shell_selection_review_and_evidence(profile):
    prompt = build_system_prompt(BuildOptions(
        Registry(), False, Target("https://fixture.test"), prompt_profile=profile,
    ))
    text = " ".join(prompt.split())
    assert "Use shell only for necessary local OS execution or request details native tools cannot express" in text
    assert "Write reproducible curl commands without executing them unless execution is requested" in text
    assert "OFF requires per-command review" in text
    assert "Shell tool-output observations are supplementary" in text
    assert "terminal HTTP results still require admissible native-http or imported-capture primary evidence" in text
    assert "or when the user asks for a reproducible command" not in text
    assert "The user is prompted per command" not in text


def test_recon_ct_lookup_does_not_use_shell_to_cross_the_native_scope_gate():
    text = playbook("recon")
    section = " ".join(text.split("## 1b.", 1)[1].split("## 2.", 1)[0].split())
    assert "crt.sh is a separate origin" in section
    assert "explicitly add the lookup origin" in section
    assert "Do not use shell/curl to bypass" in section
    # A bounded native request suffices for CT JSON; a retry loop via shell is
    # not an exception to native-first selection, even for passive research.
    for block in re.findall(r"```(?:sh|bash)\s*\n(.*?)\n```", text, re.S):
        assert not re.search(r"\bcurl\b", block)
    assert "default `max_redirects=0`" in text
    assert "does not follow redirects" not in text


def test_input_analysis_has_no_shell_http_fallback_for_signal_probes():
    intro = " ".join(playbook("web-input-analysis").split("## Target identifier", 1)[0].split())
    assert "Signal probes must use native http" in intro
    assert "Use `curl` only" not in intro
    assert "necessary local processing of already available artifacts" in intro


def test_xss_context_example_prepares_one_inert_native_request():
    text = playbook("cross-site-scripting")
    section = text.split("## 2. Determine the reflection context precisely", 1)[1].split("## 3.", 1)[0]
    examples = [json.loads(block) for block in re.findall(r"```json\s*\n(.*?)\n```", section, re.S)]
    assert len(examples) == 1
    example = examples[0]
    assert example["tool"] == "http"
    args = example["arguments"]
    origin = "https://fixture.test"
    engagement = EngagementState()
    engagement.initialize_target(origin)
    action, request = HTTPTool(Target(origin), engagement).prepare(args)
    assert request.method == "GET" and request.url.host == "fixture.test"
    assert request.url.path == "/search"
    assert request.url.params["q"].isalnum()
    assert args["phase"] == "validation" and 0 < args["max_response_bytes"] <= 8192
    assert action.redirect_limit == 0
    assert not re.search(r"```(?:sh|bash)\b", section)
