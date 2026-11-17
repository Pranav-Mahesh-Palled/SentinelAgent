"""Google Gemini Provider Integration and Client Factory for SentinelAgent.

Initialises the google-genai client from application configuration, applying
timeout settings and fail-safe API key validation.
"""

from typing import Optional
from google import genai
from google.genai import types

from app.core.config import Settings, get_settings


class GeminiConfigurationError(Exception):
    """Raised when Gemini configuration is missing or invalid."""
    pass


class GeminiProvider:
    """Encapsulates the Google Gemini API client and configuration."""

    def __init__(
        self,
        client: genai.Client,
        model: str,
        max_output_tokens: int,
        timeout_seconds: int,
        thinking_level: str,
    ) -> None:
        self._client = client
        self._model = model
        self._max_output_tokens = max_output_tokens
        self._timeout_seconds = timeout_seconds
        self._thinking_level = thinking_level
        self._closed = False

    @property
    def client(self) -> genai.Client:
        """Return the underlying google-genai Client."""
        return self._client

    @property
    def is_closed(self) -> bool:
        """Return True if the underlying client has been closed."""
        return self._closed

    def close(self) -> None:
        """Explicitly close the client and release underlying HTTP resources.

        Safe to invoke multiple times.
        """
        if not self._closed:
            self._client.close()
            self._closed = True

    def __enter__(self) -> "GeminiProvider":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    @property
    def model(self) -> str:
        """Configured Gemini model name."""
        return self._model

    @property
    def max_output_tokens(self) -> int:
        """Configured maximum output tokens."""
        return self._max_output_tokens

    @property
    def timeout_seconds(self) -> int:
        """Configured request timeout in seconds."""
        return self._timeout_seconds

    @property
    def thinking_level(self) -> str:
        """Configured thinking level."""
        return self._thinking_level


def create_gemini_client(
    settings: Optional[Settings] = None,
) -> GeminiProvider:
    """Create a validated GeminiProvider instance using application settings.

    Args:
        settings: Optional Settings instance; uses cached settings if omitted.

    Returns:
        GeminiProvider instance wrapping the initialized genai.Client.

    Raises:
        GeminiConfigurationError: If GEMINI_API_KEY is not configured or empty.
    """
    app_settings = settings or get_settings()

    if not app_settings.GEMINI_API_KEY:
        raise GeminiConfigurationError(
            "GEMINI_API_KEY is not configured. Google Gemini operations cannot be initialized."
        )

    raw_api_key = app_settings.GEMINI_API_KEY.get_secret_value().strip()
    if not raw_api_key:
        raise GeminiConfigurationError(
            "GEMINI_API_KEY is empty. Google Gemini operations cannot be initialized."
        )

    timeout_ms = app_settings.GEMINI_TIMEOUT_SECONDS * 1000
    http_options = types.HttpOptions(timeout=timeout_ms)

    client = genai.Client(
        api_key=raw_api_key,
        http_options=http_options,
    )

    return GeminiProvider(
        client=client,
        model=app_settings.GEMINI_MODEL,
        max_output_tokens=app_settings.GEMINI_MAX_OUTPUT_TOKENS,
        timeout_seconds=app_settings.GEMINI_TIMEOUT_SECONDS,
        thinking_level=app_settings.GEMINI_THINKING_LEVEL,
    )


def create_function_response_part(
    name: str,
    response: dict[str, object],
    call_id: Optional[str] = None,
) -> types.Part:
    """Create a function response Part conforming to google-genai 3.0.0.

    Preserves the function-call ID on the FunctionResponse if provided.

    Args:
        name: Name of the executed tool.
        response: Execution payload dict (e.g. {'result': ...}).
        call_id: Function-call ID from Gemini (optional, preserved when present).

    Returns:
        types.Part with function_response populated.
    """
    fn_resp = types.FunctionResponse(
        name=name,
        response=response,
        id=call_id,
    )
    return types.Part(function_response=fn_resp)

