"""
Regression tests for Burp wrapper tools.
"""
import json
from unittest.mock import MagicMock, patch

from pentest_crew.tools.burp_collaborator_tools import URLEncodeTool
from pentest_crew.tools.burp_config_tools import (
    SetProjectOptionsTool,
    SetUserOptionsTool,
    SetProjectOptionsInput,
    SetUserOptionsInput,
)


def test_set_project_options_no_json_module_shadowing():
    tool = SetProjectOptionsTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = tool._run(options_json='{"project_options":{}}')

    parsed = json.loads(result)
    assert parsed["ok"] is True
    mock_client.call.assert_called_once_with(
        "set_project_options",
        {"json": '{"project_options":{}}'},
    )


def test_set_user_options_no_json_module_shadowing():
    tool = SetUserOptionsTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = tool._run(options_json='{"user_options":{}}')

    parsed = json.loads(result)
    assert parsed["ok"] is True
    mock_client.call.assert_called_once_with(
        "set_user_options",
        {"json": '{"user_options":{}}'},
    )


def test_set_options_inputs_keep_json_alias_compatibility():
    project = SetProjectOptionsInput.model_validate({"json": '{"project_options":{}}'})
    user = SetUserOptionsInput.model_validate({"json": '{"user_options":{}}'})

    assert project.options_json == '{"project_options":{}}'
    assert user.options_json == '{"user_options":{}}'


def test_url_encode_does_not_send_unsupported_fullencode_key():
    tool = URLEncodeTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"data": "burp+mcp"}

    with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
        result = tool._run(data="burp mcp", full_encode=False)

    parsed = json.loads(result)
    assert parsed["data"] == "burp+mcp"
    mock_client.call.assert_called_once_with(
        "url_encode",
        {"content": "burp mcp"},
    )


def test_url_encode_ignores_full_encode_flag_for_mcp_compatibility():
    tool = URLEncodeTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"data": "a%2Fb"}

    with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
        result = tool._run(data="a/b", full_encode=True)

    parsed = json.loads(result)
    assert parsed["data"] == "a%2Fb"
    mock_client.call.assert_called_once_with(
        "url_encode",
        {"content": "a/b"},
    )
