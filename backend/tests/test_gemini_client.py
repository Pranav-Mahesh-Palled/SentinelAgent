"""Tests for Google Gemini Provider Integration and SDK Verification.

Verifies:
- Settings defaults and SecretStr protection for GEMINI_API_KEY.
- Validation of GEMINI_THINKING_LEVEL.
- Safe client factory initialization and error handling.
- FunctionDeclaration construction.
- FunctionCallingConfig with AUTO.
- AutomaticFunctionCallingConfig(disable=True).
- Part.from_function_response construction and function call ID preservation.
- Content(role="user", parts=[...]) structure.
- Offline SDK construction without network dependencies.
"""

import pytest
from pydantic import SecretStr, ValidationError
from unittest.mock import patch, MagicMock

from google import genai
from google.genai import types

from app.core.config import Settings
from app.services.gemini_client import (
    GeminiConfigurationError,
    GeminiProvider,
    create_gemini_client,
    create_function_response_part,
)


# -----------------------------------------------------------------------------
# Configuration & Settings Tests
# -----------------------------------------------------------------------------

def test_gemini_settings_defaults(monkeypatch):
    """Verify default Gemini configuration values."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    settings = Settings(_env_file=None)
    assert settings.GEMINI_API_KEY is None
    assert settings.GEMINI_MODEL == "gemini-3.8-flash"
    assert settings.GEMINI_MAX_OUTPUT_TOKENS == 8192
    assert settings.GEMINI_TIMEOUT_SECONDS == 120
    assert settings.GEMINI_THINKING_LEVEL == "medium"


def test_gemini_api_key_stored_as_secret_str():
    """Ensure GEMINI_API_KEY is shielded by SecretStr and never leaked via str/repr."""
    secret = "AIza" + "SyFakeKeyForTesting1234567890"
    settings = Settings(GEMINI_API_KEY=SecretStr(secret), _env_file=None)

    assert isinstance(settings.GEMINI_API_KEY, SecretStr)
    assert secret not in str(settings.GEMINI_API_KEY)
    assert secret not in repr(settings.GEMINI_API_KEY)
    assert settings.GEMINI_API_KEY.get_secret_value() == secret


def test_gemini_thinking_level_validation():
    """Verify validation of permitted thinking levels for gemini-3.8-flash.

    Supports: low, medium, high.
    Rejects: minimal (unsupported on 3.8-flash) and arbitrary strings.
    """
    # Permitted values (case-insensitive)
    for level in ["low", "medium", "high", "LOW", "MEDIUM", "HIGH", "Medium"]:
        s = Settings(GEMINI_THINKING_LEVEL=level, _env_file=None)
        assert s.GEMINI_THINKING_LEVEL == level.strip().lower()

    # 'minimal' is specifically unsupported on gemini-3.8-flash and must be rejected
    with pytest.raises(ValidationError):
        Settings(GEMINI_THINKING_LEVEL="minimal", _env_file=None)

    # Other invalid values must raise ValidationError
    for invalid in ["none", "ultra", "extreme", "disabled", ""]:
        with pytest.raises(ValidationError):
            Settings(GEMINI_THINKING_LEVEL=invalid, _env_file=None)


# -----------------------------------------------------------------------------
# Client Factory Tests
# -----------------------------------------------------------------------------

def test_create_gemini_client_fails_when_key_missing():
    """Factory must fail safely when GEMINI_API_KEY is None."""
    settings = Settings(GEMINI_API_KEY=None, _env_file=None)
    with pytest.raises(GeminiConfigurationError, match="GEMINI_API_KEY is not configured"):
        create_gemini_client(settings)


def test_create_gemini_client_fails_when_key_empty():
    """Factory must fail safely when GEMINI_API_KEY is empty or whitespace."""
    settings = Settings(GEMINI_API_KEY=SecretStr("   "), _env_file=None)
    with pytest.raises(GeminiConfigurationError, match="GEMINI_API_KEY is empty"):
        create_gemini_client(settings)


def test_create_gemini_client_success_offline():
    """Factory initializes genai.Client with timeout and credentials."""
    secret = "AIza" + "SyFakeKeyForTesting1234567890"
    settings = Settings(
        GEMINI_API_KEY=SecretStr(secret),
        GEMINI_MODEL="gemini-3.8-flash",
        GEMINI_MAX_OUTPUT_TOKENS=4096,
        GEMINI_TIMEOUT_SECONDS=60,
        GEMINI_THINKING_LEVEL="high",
        _env_file=None,
    )

    provider = create_gemini_client(settings)

    assert isinstance(provider, GeminiProvider)
    assert provider.model == "gemini-3.8-flash"
    assert provider.max_output_tokens == 4096
    assert provider.timeout_seconds == 60
    assert provider.thinking_level == "high"
    assert isinstance(provider.client, genai.Client)
    assert provider.is_closed is False


def test_gemini_provider_close_delegates_to_client():
    """Verify provider.close() invokes client.close(), marks is_closed, and is idempotent."""
    mock_client = MagicMock(spec=genai.Client)

    provider = GeminiProvider(
        client=mock_client,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )

    assert provider.is_closed is False
    assert mock_client.close.call_count == 0

    # First close
    provider.close()
    assert provider.is_closed is True
    assert mock_client.close.call_count == 1

    # Second close must be safe/idempotent and not re-call client.close()
    provider.close()
    assert provider.is_closed is True
    assert mock_client.close.call_count == 1


def test_gemini_provider_context_manager():
    """Verify GeminiProvider functions as a context manager and auto-closes."""
    mock_client = MagicMock(spec=genai.Client)

    with GeminiProvider(
        client=mock_client,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    ) as provider:
        assert provider.is_closed is False
        assert mock_client.close.call_count == 0

    assert provider.is_closed is True
    assert mock_client.close.call_count == 1


# -----------------------------------------------------------------------------
# SDK Function Calling Compatibility Tests (google-genai==3.0.0)
# -----------------------------------------------------------------------------

def test_sdk_function_declaration_construction():
    """Verify construction of types.FunctionDeclaration with JSON Schema."""
    fn_decl = types.FunctionDeclaration(
        name="get_incident_details",
        description="Retrieve details and scope of an incident.",
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "include_events": types.Schema(type=types.Type.BOOLEAN, description="Include raw events."),
            },
            required=["include_events"],
        ),
    )

    assert fn_decl.name == "get_incident_details"
    assert fn_decl.description == "Retrieve details and scope of an incident."
    assert fn_decl.parameters.type == types.Type.OBJECT
    assert "include_events" in fn_decl.parameters.properties

    # Wrap in types.Tool
    tool = types.Tool(function_declarations=[fn_decl])
    assert len(tool.function_declarations) == 1
    assert tool.function_declarations[0].name == "get_incident_details"


def test_sdk_function_calling_config_auto():
    """Verify types.FunctionCallingConfig with AUTO mode."""
    fc_config = types.FunctionCallingConfig(
        mode=types.FunctionCallingConfigMode.AUTO
    )
    assert fc_config.mode == types.FunctionCallingConfigMode.AUTO

    tool_config = types.ToolConfig(function_calling_config=fc_config)
    assert tool_config.function_calling_config.mode == types.FunctionCallingConfigMode.AUTO


def test_sdk_automatic_function_calling_disabled():
    """Verify types.AutomaticFunctionCallingConfig(disable=True)."""
    afc = types.AutomaticFunctionCallingConfig(disable=True)
    assert afc.disable is True


def test_sdk_function_response_construction_and_id_preservation():
    """Verify function response part creation preserves function name, payload, and call ID."""
    call_id = "call_sentinel_xyz123"
    tool_name = "search_ssh_events_by_ip"
    payload = {
        "result": {
            "status": "success",
            "count": 2,
            "events": [{"event_id": "ev-1"}, {"event_id": "ev-2"}],
        }
    }

    # Test helper
    part = create_function_response_part(
        name=tool_name,
        response=payload,
        call_id=call_id,
    )

    assert isinstance(part, types.Part)
    assert part.function_response is not None
    assert part.function_response.name == tool_name
    assert part.function_response.id == call_id
    assert part.function_response.response == payload

    # Verify model_dump preserves id
    dumped = part.model_dump(exclude_none=True)
    assert dumped["function_response"]["name"] == tool_name
    assert dumped["function_response"]["id"] == call_id
    assert dumped["function_response"]["response"] == payload


def test_sdk_function_response_without_id():
    """Verify function response part creation when call_id is None."""
    tool_name = "get_related_incidents_for_ip"
    payload = {"result": {"status": "success", "count": 0, "incidents": []}}

    part = create_function_response_part(
        name=tool_name,
        response=payload,
        call_id=None,
    )

    assert isinstance(part, types.Part)
    assert part.function_response is not None
    assert part.function_response.name == tool_name
    assert part.function_response.id is None
    assert part.function_response.response == payload


def test_sdk_turn_content_role_user_grouping():
    """Verify types.Content(role='user', parts=[...]) groups function responses into a user turn."""
    part1 = create_function_response_part(
        name="tool_a",
        response={"result": "ok_a"},
        call_id="call_a",
    )
    part2 = create_function_response_part(
        name="tool_b",
        response={"result": "ok_b"},
        call_id="call_b",
    )

    turn = types.Content(role="user", parts=[part1, part2])

    assert turn.role == "user"
    assert len(turn.parts) == 2
    assert turn.parts[0].function_response.name == "tool_a"
    assert turn.parts[0].function_response.id == "call_a"
    assert turn.parts[1].function_response.name == "tool_b"
    assert turn.parts[1].function_response.id == "call_b"


def test_sdk_generate_content_config_assembly():
    """Verify full GenerateContentConfig assembly combining tools, thinking, tokens, and AFC disable."""
    tool = types.Tool(
        function_declarations=[
            types.FunctionDeclaration(
                name="test_tool",
                description="Test tool",
                parameters=types.Schema(type=types.Type.OBJECT),
            )
        ]
    )
    fc_config = types.FunctionCallingConfig(mode=types.FunctionCallingConfigMode.AUTO)
    tool_config = types.ToolConfig(function_calling_config=fc_config)
    afc_config = types.AutomaticFunctionCallingConfig(disable=True)
    thinking_config = types.ThinkingConfig(thinking_level="medium")

    config = types.GenerateContentConfig(
        tools=[tool],
        tool_config=tool_config,
        automatic_function_calling=afc_config,
        max_output_tokens=8192,
        thinking_config=thinking_config,
    )

    assert config.tools[0].function_declarations[0].name == "test_tool"
    assert config.tool_config.function_calling_config.mode == types.FunctionCallingConfigMode.AUTO
    assert config.automatic_function_calling.disable is True
    assert config.max_output_tokens == 8192
    assert config.thinking_config.thinking_level == types.ThinkingLevel.MEDIUM
