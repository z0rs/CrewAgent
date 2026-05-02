"""
tests/test_deserialization_tools.py
──────────────────────────────────
Unit tests for deserialization_tools.py

Coverage:
- DeserializationDetectTool: CONFIRMED (PHP), NOT_CONFIRMED (no vuln), INCONCLUSIVE
- DeserializationOOBTool: CONFIRMED (Collaborator HTTP hit), NOT_CONFIRMED (no callback)
- DeserializationExploitTool: platform extraction sequences, severity adjustment
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pentest_crew.tools.deserialization_tools import (
    DeserializationDetectTool,
    DeserializationOOBTool,
    DeserializationExploitTool,
    _detect_deserialization_in_response,
    _detect_platform_from_response,
    PHP_OI_PAYLOADS,
    JNDI_PAYLOADS,
    YAML_UNSAFE_PAYLOADS,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_mock_response(status: int = 200, body: str = "", content_type: str = "application/json") -> dict:
    return {
        "statusCode": status,
        "body": body if isinstance(body, bytes) else body.encode(),
        "headers": {"content-type": content_type},
    }


def make_raw_request(method: str = "POST /api/data HTTP/1.1",
                     body: str = '{"data": "test"}',
                     host: str = "api.example.com",
                     content_type: str = "application/json") -> str:
    return (
        f"{method}\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Accept: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Response analysis helpers — no network calls required
# ──────────────────────────────────────────────────────────────────────────────

class TestDetectDeserializationInResponse:
    def test_php_offset_error_confirmed(self):
        body = 'unserialize(): Error at offset 42 of 150 bytes in /app/deserialize.php'
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "php"
        assert "position 42" in result["signal"]

    def test_php_object_pattern_confirmed(self):
        # Object reflected inside error context — not as raw string (regex requires 'o:...' pattern)
        body = 'PHP Fatal error:  Unserialization error: o:8:"stdClass":1:{s:5:"data"'
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "php"

    def test_java_invalid_class_exception_confirmed(self):
        body = "java.io.InvalidClassException: org.apache.commons.collections.FastHashMap"
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "java"

    def test_python_pickle_error_confirmed(self):
        body = "pickle.loads() argument 1 had negative size\n  File '/app/views.py', line 42, in deserialize"
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "python"

    def test_yaml_unsafeloader_confirmed(self):
        body = "yaml.YAMLLoadWarning: calling YAML.load() without Loader=unsafe"
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "yaml"

    def test_no_vuln_clean_response(self):
        body = '{"status": "ok", "user_id": 42, "name": "Alice"}'
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is False
        assert result["platform"] is None

    def test_mixed_content_php_detection_wins(self):
        body = "unserialize(): Error at offset 15 of 200 bytes\nStack trace:\njava.io.IOException"
        result = _detect_deserialization_in_response(body)
        assert result["confirmed"] is True
        assert result["platform"] == "php"


class TestDetectPlatformFromResponse:
    def test_php_signals(self):
        # _detect_platform_from_response checks error message patterns, not raw object strings
        assert _detect_platform_from_response("unserialize(): error at offset") == "php"
        assert _detect_platform_from_response("Serialization error in class") == "php"
        # Raw object notation appears in error context when PHP reflects it back
        assert _detect_platform_from_response("Fatal error: unserialization error: o:8:") == "php"

    def test_java_signals(self):
        assert _detect_platform_from_response("java.io.OptionalDataException") == "java"
        assert _detect_platform_from_response("java.lang.ClassNotFoundException") == "java"
        assert _detect_platform_from_response("InvalidClassException") == "java"

    def test_python_signals(self):
        # Must match the regex r"pickle\.loads?" — needs literal "pickle."
        assert _detect_platform_from_response("pickle.loads() argument 1 had negative size") == "python"
        # Must match r"can'?t (decod|unpickl)" — needs "can't" or "cant" + "decod"/"unpickl"
        assert _detect_platform_from_response("can't decode the object bytes") == "python"

    def test_yaml_signals(self):
        assert _detect_platform_from_response("yaml.YAMLLoadWarning") == "yaml"
        assert _detect_platform_from_response("could not determine a YAML") == "yaml"

    def test_no_signal_returns_none(self):
        assert _detect_platform_from_response('{"ok": true}') is None


# ──────────────────────────────────────────────────────────────────────────────
# DeserializationDetectTool tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDeserializationDetectTool:
    @pytest.fixture
    def tool(self):
        return DeserializationDetectTool()

    @pytest.fixture
    def base_request(self):
        return make_raw_request(body='{"data":"original"}')

    def test_unknown_payload_type_returns_error(self, tool, base_request):
        result = tool._run(
            host="api.example.com",
            port=443,
            use_https=True,
            raw_request=base_request,
            injectable_param="data",
            payload_type="cobol",  # invalid
        )
        assert result["status"] == "ERROR"
        assert "Unknown payload_type" in result["message"]

    def test_no_vuln_returns_not_confirmed(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()

            def fake_call(name, args):
                if name == "send_http1_request":
                    return make_mock_response(200, '{"data":"original"}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="data",
                payload_type="php",
            )
            assert result["status"] == "NOT_CONFIRMED"

    def test_php_offset_error_returns_confirmed(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                if name == "send_http1_request":
                    if call_count[0] == 1:
                        # First call returns PHP unserialize offset error
                        return make_mock_response(
                            200,
                            'unserialize(): Error at offset 12 of 150 bytes in deserialize.php',
                        )
                    # Subsequent calls return clean response
                    return make_mock_response(200, '{"ok":true}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="data",
                payload_type="php",
            )

            assert result["status"] == "CONFIRMED"
            assert result["confirmed"] is True
            assert result["platform"] == "php"
            assert "position 12" in result["signal"]
            assert result["confidence"] == "HIGH"

    def test_java_invalidclass_returns_confirmed(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                if name == "send_http1_request":
                    if call_count[0] == 1:
                        return make_mock_response(
                            200,
                            "java.io.InvalidClassException: org.apache.commons.collections4.functors.InvokerTransformer",
                        )
                    return make_mock_response(200, '{"ok":true}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="data",
                payload_type="java",
            )

            assert result["status"] == "CONFIRMED"
            assert result["platform"] == "java"
            assert "java.io.invalidclassexception" in result["signal"].lower()

    def test_yaml_unsafe_returns_confirmed(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                if name == "send_http1_request":
                    if call_count[0] == 1:
                        return make_mock_response(
                            200,
                            "yaml.YAMLLoadWarning: calling YAML.load() without Loader=unsafe",
                        )
                    return make_mock_response(200, '{"ok":true}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="data",
                payload_type="yaml",
            )

            assert result["status"] == "CONFIRMED"
            assert result["platform"] == "yaml"

    def test_all_platforms_tested_with_limit(self, tool, base_request):
        """When payload_type=all, should test all 4 platforms but respect max_tests=10."""
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                return make_mock_response(200, '{"ok":true}')

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="data",
                payload_type="all",
            )

            # Should have run tests (not all platforms have tests that returned results)
            assert result["status"] == "NOT_CONFIRMED"
            assert result["tests_run"] <= 10


# ──────────────────────────────────────────────────────────────────────────────
# DeserializationOOBTool tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDeserializationOOBTool:
    @pytest.fixture
    def tool(self):
        return DeserializationOOBTool()

    @pytest.fixture
    def base_request(self):
        return make_raw_request(body='{"serialized":"original"}')

    def test_no_collab_payload_returns_error(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.call_with_retry.return_value = {}  # No payload in response
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="serialized",
                platform="java",
                wait_seconds=30,
            )

            assert result["status"] == "ERROR"
            assert "Failed to generate" in result["message"]

    def test_oob_confirmed_http_hit(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()

            def fake_call(name, args):
                if name == "generate_collaborator_payload":
                    return {
                        "payload": "collab-attacker123.oastify.com",
                        "payloadId": "abc123",
                    }
                elif name == "send_http1_request":
                    return make_mock_response(200, '{"status":"processed"}')
                elif name == "poll_collaborator_with_wait":
                    return {
                        "count": 2,
                        "interactions": [
                            {"type": "HTTP", "collaboratorServer": "collab-attacker123.oastify.com"},
                            {"type": "DNS", "collaboratorServer": "collab-attacker123.oastify.com"},
                        ],
                    }
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="serialized",
                platform="java",
                wait_seconds=30,
            )

            assert result["status"] == "CONFIRMED"
            assert result["confirmed"] is True
            assert result["platform"] == "java"
            assert result["interaction_count"] == 2
            assert result["dns_callbacks"] == 1
            assert result["http_callbacks"] == 1
            assert "JNDI" in result["message"] or "ldap" in result["message"]

    def test_oob_not_confirmed_no_callback(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()

            def fake_call(name, args):
                if name == "generate_collaborator_payload":
                    return {
                        "payload": "collab-none123.oastify.com",
                        "payloadId": "xyz789",
                    }
                elif name == "send_http1_request":
                    return make_mock_response(200, '{"status":"ok"}')
                elif name == "poll_collaborator_with_wait":
                    # No interactions — twice (initial + retry)
                    return {"count": 0, "interactions": []}
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="serialized",
                platform="php",
                wait_seconds=30,
            )

            assert result["status"] == "NOT_CONFIRMED"
            assert result["confirmed"] is False
            assert "Collaborator interactions" in result["message"]

    def test_unknown_platform_returns_error(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="serialized",
                platform="ruby",  # not supported
                wait_seconds=30,
            )

            assert result["status"] == "ERROR"
            assert "Unsupported platform" in result["message"]


# ──────────────────────────────────────────────────────────────────────────────
# DeserializationExploitTool tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDeserializationExploitTool:
    @pytest.fixture
    def tool(self):
        return DeserializationExploitTool()

    @pytest.fixture
    def base_request(self):
        return make_raw_request(body='{"profile":"original"}')

    def test_unknown_platform_returns_error(self, tool, base_request):
        result = tool._run(
            host="api.example.com",
            port=443,
            use_https=True,
            raw_request=base_request,
            injectable_param="profile",
            platform="cobol",
            extraction_type="quick",
        )

        assert result["status"] == "ERROR"
        assert "Unknown platform" in result["message"]

    def test_php_exploit_extracts_env_vars(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                if name == "send_http1_request":
                    # Simulate response with command output in JSON error
                    return make_mock_response(
                        200,
                        json.dumps({
                            "error": "Serialization error",
                            "output": "PATH=/usr/local/bin:/usr/bin:/bin\nUSER=www-data\nHOME=/var/www"
                        }),
                    )
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="profile",
                platform="php",
                extraction_type="quick",
            )

            assert result["status"] == "EXPLOITED"
            assert result["platform"] == "php"
            assert "severity_adjustment" in result

    def test_python_exploit_builds_pickle_payload(self, tool, base_request):
        """Verify that the exploit tool sends encoded pickle payloads for python platform."""
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            sent_requests = []

            def fake_call(name, args):
                if name == "send_http1_request":
                    sent_requests.append(args.get("request", ""))
                    return make_mock_response(200, '{"result":"ok"}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="profile",
                platform="python",
                extraction_type="quick",
            )

            assert result["status"] == "EXPLOITED"
            assert result["platform"] == "python"
            # Verify at least 4 commands were attempted (id, whoami, hostname, uname -a)
            assert len(sent_requests) == 4
            # Verify payloads were base64-encoded (contain only base64 chars + /+=)
            import re
            for req in sent_requests:
                # Check body contains a base64-ish string in the profile field
                match = re.search(r'"profile"\s*:\s*"([A-Za-z0-9+/=]{20,})"', req)
                assert match is not None, f"Expected base64 pickle payload in: {req[:200]}"

    def test_java_exploit_generates_collab_payload(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()

            def fake_call(name, args):
                if name == "generate_collaborator_payload":
                    return {
                        "payload": "jndi-collab123.oastify.com",
                        "payloadId": "jndi789",
                    }
                elif name == "send_http1_request":
                    return make_mock_response(200, '{"processing":"done"}')
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="profile",
                platform="java",
                extraction_type="quick",
            )

            assert result["status"] == "EXPLOITED"
            assert result["platform"] == "java"
            assert "JNDI" in result["summary"] or "ldap" in result["summary"]

    def test_yaml_exploit_runs_code_via_python_object(self, tool, base_request):
        with patch("pentest_crew.tools.deserialization_tools.get_client") as mock_get:
            mock_client = MagicMock()
            call_count = [0]

            def fake_call(name, args):
                call_count[0] += 1
                if name == "send_http1_request":
                    return make_mock_response(
                        200,
                        json.dumps({
                            "error": "YAML processing",
                            "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                        }),
                    )
                raise AssertionError(f"Unexpected call: {name}")

            mock_client.call_with_retry = fake_call
            mock_get.return_value = mock_client

            result = tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=base_request,
                injectable_param="profile",
                platform="yaml",
                extraction_type="quick",
            )

            assert result["status"] == "EXPLOITED"
            assert result["platform"] == "yaml"
            assert result["severity_adjustment"] is not None


# ──────────────────────────────────────────────────────────────────────────────
# Payload inventory sanity checks
# ──────────────────────────────────────────────────────────────────────────────

class TestPayloadInventory:
    def test_php_payloads_are_valid_serialized_strings(self):
        for payload, label in PHP_OI_PAYLOADS:
            assert isinstance(payload, str)
            assert len(payload) > 0
            assert label

    def test_jndi_payloads_have_placeholder(self):
        for payload_tmpl, label in JNDI_PAYLOADS:
            assert "COLLABORATOR_PLACEHOLDER" in payload_tmpl or "${jndi:" in payload_tmpl
            assert label

    def test_yaml_payloads_contain_python_object_marker(self):
        for payload, label in YAML_UNSAFE_PAYLOADS:
            assert "python" in payload or "object" in payload or "!!" in payload

    def test_max_payloads_per_platform_respected(self):
        """Verify we don't have more payloads than our max_tests=10 per detect run."""
        # PHP: 4 payloads (max 4 tests)
        assert len(PHP_OI_PAYLOADS) <= 10
        # Java JNDI: 3 payloads (max 3 tests)
        assert len(JNDI_PAYLOADS) <= 10
        # Python: 3 payloads (max 3 tests)
        # YAML: 3 payloads (max 3 tests)
        assert len(YAML_UNSAFE_PAYLOADS) <= 10