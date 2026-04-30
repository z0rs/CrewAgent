"""
Smoke tests for Crew assembly to catch runtime wiring regressions.
"""
from __future__ import annotations

import os
import pytest


@pytest.mark.parametrize(
    "provider_env",
    ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"),
)
def test_single_provider_crew_initializes_without_name_errors(monkeypatch, provider_env):
    """Crew boot should not fail for any single supported provider."""
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(provider_env, "fake-api-key")

    from pentest_crew.crew import PentestCrew

    crew = PentestCrew().crew()
    assert crew is not None
    assert len(crew.agents) >= 1
    assert len(crew.tasks) >= 1
    assert os.path.basename(crew.output_log_file) == "pentest_crew_log.txt"


def test_select_llm_keeps_full_provider_model_override(monkeypatch):
    """provider/model overrides must keep provider prefix in the model string."""
    from pentest_crew import crew as crew_module

    monkeypatch.setattr(
        crew_module,
        "available_llm_providers",
        lambda: ["openrouter", "openai"],
    )
    monkeypatch.setattr(
        crew_module,
        "get_model_for_role",
        lambda role: "openrouter/meta-llama/llama-3-8b",
    )

    calls: list[tuple[str, str, float]] = []

    def fake_llm(provider: str, model: str, temperature: float):
        calls.append((provider, model, temperature))
        return {"provider": provider, "model": model, "temperature": temperature}

    monkeypatch.setattr(crew_module, "_llm_for_provider", fake_llm)

    result = crew_module._select_llm("http_analyst", ("openai", "openrouter"), 0.1)

    assert calls == [("openrouter", "openrouter/meta-llama/llama-3-8b", 0.1)]
    assert result["model"] == "openrouter/meta-llama/llama-3-8b"
