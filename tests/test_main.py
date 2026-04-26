"""
test_main.py
────────────
Unit tests for main.py input building and environment variable validation.
"""
import os
from datetime import datetime
from unittest.mock import patch

import pytest


class TestLlmMode:
    """Tests for shared LLM mode detection."""

    def test_empty_env_has_no_providers(self):
        from pentest_crew.llm_mode import available_llm_providers, mode_label

        assert available_llm_providers({}) == []
        assert mode_label({}) == "No LLM API Key Configured"

    def test_single_and_multi_modes_from_env_mapping(self):
        from pentest_crew.llm_mode import is_multi_agent_mode, is_single_llm_mode

        assert is_single_llm_mode({"OPENAI_API_KEY": "key"})
        assert not is_multi_agent_mode({"OPENAI_API_KEY": "key"})
        assert is_multi_agent_mode({
            "OPENAI_API_KEY": "key",
            "ANTHROPIC_API_KEY": "key",
        })


class TestBuildInputs:
    """Tests for _build_inputs()."""

    def test_defaults_when_env_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            from pentest_crew.main import _build_inputs
            inputs = _build_inputs()

            assert "engagement_id" in inputs
            assert inputs["engagement_id"].startswith("ENG-")
            assert inputs["target_url"] == "burp://active-scope"
            assert inputs["client_name"] == "Client"
            assert inputs["test_type"] == "greybox"
            assert inputs["tester_name"] == "Security Team"
            assert "report_date" in inputs
            # report_date should be today
            assert inputs["report_date"] == datetime.now().strftime("%Y-%m-%d")

    def test_env_overrides_apply(self):
        env_vars = {
            "ENGAGEMENT_ID": "ENG-TEST-001",
            "TARGET_URL": "https://test.example.com",
            "CLIENT_NAME": "TestCorp",
            "TEST_TYPE": "blackbox",
            "TESTER_NAME": "Alice",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            from pentest_crew.main import _build_inputs
            inputs = _build_inputs()

            assert inputs["engagement_id"] == "ENG-TEST-001"
            assert inputs["target_url"] == "https://test.example.com"
            assert inputs["client_name"] == "TestCorp"
            assert inputs["test_type"] == "blackbox"
            assert inputs["tester_name"] == "Alice"


class TestValidateEnv:
    """Tests for _validate_env()."""

    def test_exits_when_all_api_keys_missing(self):
        """At least one supported LLM API key is required."""
        env_vars = {}  # no keys at all
        with patch.dict(os.environ, env_vars, clear=True):
            from pentest_crew.main import _validate_env
            with pytest.raises(SystemExit) as exc_info:
                _validate_env()
            assert exc_info.value.code == 1

    @pytest.mark.parametrize(
        "env_name",
        ["GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
    )
    def test_single_agent_mode_when_only_one_key_set(self, monkeypatch, env_name):
        """Exactly one supported API key → single-agent mode, validation passes."""
        for key in ["GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv(env_name, "fake-key")

        from pentest_crew.main import _validate_env
        _validate_env()  # should not raise

    def test_multi_agent_mode_passes_when_two_keys_present(self, monkeypatch):
        """Any two supported API keys → multi-agent mode, validation passes."""
        monkeypatch.setenv("GOOGLE_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-key")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        from pentest_crew.main import _validate_env
        _validate_env()  # should not raise

    def test_multi_agent_mode_passes_when_all_keys_present(self, monkeypatch):
        """All three supported API keys → multi-agent mode, validation passes."""
        monkeypatch.setenv("GOOGLE_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-key")

        from pentest_crew.main import _validate_env
        _validate_env()  # should not raise
