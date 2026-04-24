"""
test_main.py
────────────
Unit tests for main.py input building and environment variable validation.
"""
import os
from datetime import datetime
from unittest.mock import patch

import pytest


class TestBuildInputs:
    """Tests for _build_inputs()."""

    def test_defaults_when_env_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            from pentest_crew.main import _build_inputs
            inputs = _build_inputs()

            assert "engagement_id" in inputs
            assert inputs["engagement_id"].startswith("ENG-")
            assert inputs["target_url"] == "https://target.example.com"
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

    def test_exits_on_missing_api_keys(self):
        env_vars = {
            # All three missing
        }
        with patch.dict(os.environ, env_vars, clear=True):
            from pentest_crew.main import _validate_env
            with pytest.raises(SystemExit):
                _validate_env()

    def test_passes_when_all_required_keys_present(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-key")

        from pentest_crew.main import _validate_env
        # Should not raise
        _validate_env()

    def test_missing_single_key_reports_correctly(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "fake-gemini-key")
        # OPENAI_API_KEY and ANTHROPIC_API_KEY missing
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        from pentest_crew.main import _validate_env
        with pytest.raises(SystemExit) as exc_info:
            _validate_env()
        # exit code 1
        assert exc_info.value.code == 1