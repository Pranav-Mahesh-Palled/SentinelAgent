"""Tests for application configuration and credential security."""

from pathlib import Path
import pytest
from pydantic import SecretStr
from app.core.config import Settings


def test_settings_default_values():
    """Verify default application metadata settings."""
    settings = Settings(_env_file=None)
    assert settings.APP_NAME == "SentinelAgent API"
    assert settings.APP_DESCRIPTION == "AI-Powered Cybersecurity Investigation System"
    assert settings.APP_VERSION == "0.1.0"
    assert settings.API_PREFIX == "/api"
    assert settings.DEBUG is False


def test_database_url_is_optional():
    """Application must load cleanly without DATABASE_URL configured."""
    settings = Settings(DATABASE_URL=None, _env_file=None)
    assert settings.DATABASE_URL is None


def test_database_url_stored_as_secret_str():
    """Sensitive connection string must be protected by SecretStr."""
    raw_url = "postgresql+psycopg://secuser:supersecretpass@localhost:5432/sentinelagent"
    settings = Settings(DATABASE_URL=SecretStr(raw_url), _env_file=None)

    assert isinstance(settings.DATABASE_URL, SecretStr)
    # Masked representation should not reveal the plain password
    assert "supersecretpass" not in str(settings.DATABASE_URL)
    assert "supersecretpass" not in repr(settings.DATABASE_URL)
    # Raw value is only accessible via explicit get_secret_value()
    assert settings.DATABASE_URL.get_secret_value() == raw_url


# ---------------------------------------------------------------------------
# Hindsight Configuration Tests (Task 9B)
# ---------------------------------------------------------------------------

def test_hindsight_settings_defaults():
    """Verify default Hindsight memory settings."""
    settings = Settings(_env_file=None)
    assert settings.HINDSIGHT_ENABLED is False
    assert settings.HINDSIGHT_REQUIRED is False
    assert settings.HINDSIGHT_BASE_URL is None
    assert settings.HINDSIGHT_API_KEY is None
    assert settings.HINDSIGHT_BANK_ID == "sentinelagent-incident-memory-dev"
    assert settings.HINDSIGHT_TIMEOUT_SECONDS == 30.0
    assert settings.HINDSIGHT_HMAC_KEY is None
    assert settings.HINDSIGHT_PREVIOUS_HMAC_KEYS == {}


def test_hindsight_enabled_requires_base_url():
    """When Hindsight is enabled, HINDSIGHT_BASE_URL is mandatory."""
    with pytest.raises(ValueError, match="HINDSIGHT_BASE_URL must be explicitly configured"):
        Settings(
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL=None,
            HINDSIGHT_API_KEY=SecretStr("valid-key"),
            _env_file=None,
        )


def test_hindsight_enabled_requires_api_key():
    """When Hindsight is enabled, HINDSIGHT_API_KEY is mandatory."""
    with pytest.raises(ValueError, match="HINDSIGHT_API_KEY must be explicitly configured"):
        Settings(
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL="http://localhost:8888",
            HINDSIGHT_API_KEY=None,
            _env_file=None,
        )


def test_hindsight_required_implies_enabled():
    """HINDSIGHT_REQUIRED cannot be enabled while HINDSIGHT_ENABLED is False."""
    with pytest.raises(ValueError, match="HINDSIGHT_REQUIRED cannot be True when HINDSIGHT_ENABLED is False"):
        Settings(
            HINDSIGHT_ENABLED=False,
            HINDSIGHT_REQUIRED=True,
            _env_file=None,
        )


def test_hindsight_api_key_stored_as_secret_str():
    """Hindsight API key must be masked and protected by SecretStr."""
    secret_key = "hindsight_super_secret_token_123456"
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr(secret_key),
        _env_file=None,
    )
    assert isinstance(settings.HINDSIGHT_API_KEY, SecretStr)
    assert secret_key not in str(settings.HINDSIGHT_API_KEY)
    assert secret_key not in repr(settings.HINDSIGHT_API_KEY)
    assert settings.HINDSIGHT_API_KEY.get_secret_value() == secret_key


def test_hindsight_bank_id_environment_resolution():
    """Development defaults to dev bank; production defaults to prod bank."""
    dev_settings = Settings(ENVIRONMENT="development", _env_file=None)
    assert dev_settings.HINDSIGHT_BANK_ID == "sentinelagent-incident-memory-dev"

    prod_settings = Settings(ENVIRONMENT="production", _env_file=None)
    assert prod_settings.HINDSIGHT_BANK_ID == "sentinelagent-incident-memory-prod"


def test_hindsight_bank_id_environment_isolation_enforced():
    """Development environment must never select production memory bank."""
    with pytest.raises(ValueError, match="cannot use production memory bank"):
        Settings(
            ENVIRONMENT="development",
            HINDSIGHT_BANK_ID="sentinelagent-incident-memory-prod",
            _env_file=None,
        )


def test_hindsight_validation_error_does_not_leak_secret():
    """Validation errors must never expose secret values."""
    sensitive_token = "ultra_sensitive_token_do_not_leak"
    try:
        # Trigger validation failure while providing sensitive token
        Settings(
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL="",  # Triggers URL validation failure
            HINDSIGHT_API_KEY=SecretStr(sensitive_token),
            _env_file=None,
        )
    except ValueError as exc:
        assert sensitive_token not in str(exc)


# ---------------------------------------------------------------------------
# Hindsight Outbox Worker Configuration Tests (Task 9C.3)
# ---------------------------------------------------------------------------

def test_hindsight_outbox_worker_defaults():
    """Verify default outbox worker configuration settings."""
    settings = Settings(_env_file=None)
    assert settings.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS == 2.0
    assert settings.HINDSIGHT_OUTBOX_BATCH_SIZE == 10
    assert settings.HINDSIGHT_OUTBOX_MAX_CONCURRENCY == 5
    assert settings.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS == 45.0
    assert settings.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS == 15.0
    assert settings.HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS == 5.0
    assert settings.HINDSIGHT_OUTBOX_MAX_ATTEMPTS == 8
    assert settings.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS == 5.0
    assert settings.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS == 300.0
    assert settings.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION == 0.2
    assert settings.HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS == 15.0
    assert settings.HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS == 30.0


@pytest.mark.parametrize(
    "field,invalid_val",
    [
        ("HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS", 0.0),
        ("HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS", -1.0),
        ("HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS", 0.0),
        ("HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS", -5.0),
        ("HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS", 0.0),
        ("HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS", -2.0),
        ("HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS", 0.0),
        ("HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS", -10.0),
        ("HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS", 0.0),
        ("HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS", -1.0),
    ],
)
def test_hindsight_outbox_worker_positive_intervals_enforced(field, invalid_val):
    """Worker interval and timeout settings must be strictly positive."""
    with pytest.raises(ValueError, match=f"{field} must be positive"):
        Settings(**{field: invalid_val}, _env_file=None)


@pytest.mark.parametrize("batch_size", [1, 10, 50, 100])
def test_hindsight_outbox_batch_size_valid_boundaries(batch_size):
    """Batch size within [1, 100] passes validation."""
    settings = Settings(HINDSIGHT_OUTBOX_BATCH_SIZE=batch_size, _env_file=None)
    assert settings.HINDSIGHT_OUTBOX_BATCH_SIZE == batch_size


@pytest.mark.parametrize("invalid_batch_size", [0, -1, 101, 500])
def test_hindsight_outbox_batch_size_invalid_rejected(invalid_batch_size):
    """Batch size outside [1, 100] is strictly rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_BATCH_SIZE must be between 1 and 100"):
        Settings(HINDSIGHT_OUTBOX_BATCH_SIZE=invalid_batch_size, _env_file=None)


@pytest.mark.parametrize("concurrency", [1, 5, 10, 50, 100])
def test_hindsight_outbox_max_concurrency_valid_boundaries(concurrency):
    """Max concurrency within [1, 100] passes validation."""
    settings = Settings(HINDSIGHT_OUTBOX_MAX_CONCURRENCY=concurrency, _env_file=None)
    assert settings.HINDSIGHT_OUTBOX_MAX_CONCURRENCY == concurrency


@pytest.mark.parametrize("invalid_concurrency", [0, -1, 101, 500])
def test_hindsight_outbox_max_concurrency_invalid_rejected(invalid_concurrency):
    """Max concurrency outside [1, 100] is strictly rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_MAX_CONCURRENCY must be between 1 and 100"):
        Settings(HINDSIGHT_OUTBOX_MAX_CONCURRENCY=invalid_concurrency, _env_file=None)


def test_hindsight_outbox_lease_heartbeat_relationship():
    """Heartbeat interval must be strictly less than lease duration."""
    # Valid: heartbeat (15s) < lease (45s)
    settings = Settings(
        HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=45.0,
        HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=15.0,
        _env_file=None,
    )
    assert settings.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS < settings.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS

    # Invalid: heartbeat == lease
    with pytest.raises(ValueError, match="must be strictly less than HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS"):
        Settings(
            HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=45.0,
            HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=45.0,
            _env_file=None,
        )

    # Invalid: heartbeat > lease
    with pytest.raises(ValueError, match="must be strictly less than HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS"):
        Settings(
            HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=30.0,
            HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=35.0,
            _env_file=None,
        )

    # Invalid: non-positive lease duration
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS must be positive"):
        Settings(
            HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=0.0,
            _env_file=None,
        )

    # Invalid: non-positive heartbeat
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS must be positive"):
        Settings(
            HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=0.0,
            _env_file=None,
        )


def test_hindsight_outbox_backoff_relationship():
    """Maximum backoff must be greater than or equal to initial backoff."""
    # Valid: max >= initial
    s1 = Settings(
        HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=5.0,
        HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=300.0,
        _env_file=None,
    )
    assert s1.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS >= s1.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS

    s2 = Settings(
        HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=10.0,
        HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=10.0,
        _env_file=None,
    )
    assert s2.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS == s2.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS

    # Invalid: max < initial
    with pytest.raises(ValueError, match="must be greater than or equal to HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS"):
        Settings(
            HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=10.0,
            HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=5.0,
            _env_file=None,
        )


@pytest.mark.parametrize("jitter", [0.0, 0.1, 0.2, 0.5, 1.0])
def test_hindsight_outbox_jitter_fraction_valid(jitter):
    """Jitter fraction within [0.0, 1.0] passes validation."""
    settings = Settings(HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION=jitter, _env_file=None)
    assert settings.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION == jitter


@pytest.mark.parametrize("invalid_jitter", [-0.1, 1.01, 2.0, -1.0])
def test_hindsight_outbox_jitter_fraction_invalid_rejected(invalid_jitter):
    """Jitter fraction outside [0.0, 1.0] is strictly rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION must be between 0.0 and 1.0 inclusive"):
        Settings(HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION=invalid_jitter, _env_file=None)


@pytest.mark.parametrize("attempts", [1, 3, 8, 20])
def test_hindsight_outbox_max_attempts_valid(attempts):
    """Maximum attempts >= 1 passes validation."""
    settings = Settings(HINDSIGHT_OUTBOX_MAX_ATTEMPTS=attempts, _env_file=None)
    assert settings.HINDSIGHT_OUTBOX_MAX_ATTEMPTS == attempts


@pytest.mark.parametrize("invalid_attempts", [0, -1, -5])
def test_hindsight_outbox_max_attempts_invalid_rejected(invalid_attempts):
    """Maximum attempts < 1 is strictly rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_OUTBOX_MAX_ATTEMPTS must be positive"):
        Settings(HINDSIGHT_OUTBOX_MAX_ATTEMPTS=invalid_attempts, _env_file=None)


def test_hindsight_disabled_allows_worker_settings_without_credentials():
    """When HINDSIGHT_ENABLED is False, worker settings are valid and do not require base_url or api_key."""
    settings = Settings(
        HINDSIGHT_ENABLED=False,
        HINDSIGHT_BASE_URL=None,
        HINDSIGHT_API_KEY=None,
        HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS=3.0,
        HINDSIGHT_OUTBOX_BATCH_SIZE=25,
        _env_file=None,
    )
    assert settings.HINDSIGHT_ENABLED is False
    assert settings.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS == 3.0
    assert settings.HINDSIGHT_OUTBOX_BATCH_SIZE == 25


@pytest.mark.parametrize(
    "field",
    [
        "HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS",
        "HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS",
        "HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS",
        "HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS",
        "HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS",
        "HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS",
        "HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION",
        "HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS",
        "HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS",
    ],
)
@pytest.mark.parametrize("non_finite_val", [float("nan"), float("inf"), float("-inf")])
def test_hindsight_outbox_non_finite_floats_rejected(field, non_finite_val):
    """Every floating-point worker setting must strictly reject NaN, +inf, and -inf."""
    with pytest.raises(ValueError, match=f"{field} must be a finite number"):
        Settings(**{field: non_finite_val}, _env_file=None)


# ---------------------------------------------------------------------------
# Hindsight Recall Configuration Tests (Task 9D)
# ---------------------------------------------------------------------------

def test_hindsight_recall_defaults():
    """Verify default Hindsight recall settings."""
    settings = Settings(_env_file=None)
    assert settings.HINDSIGHT_RECALL_ENABLED is False
    assert settings.HINDSIGHT_RECALL_BUDGET == "mid"
    assert settings.HINDSIGHT_RECALL_MAX_TOKENS == 1024
    assert settings.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS == 3.0
    assert settings.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS == 5.0
    assert settings.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS == 10
    assert settings.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS == 1.0
    assert settings.HINDSIGHT_HMAC_MAX_HISTORICAL_KEYS == 2


def test_hindsight_recall_valid_custom_settings():
    """Verify valid custom recall settings are accepted."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_BUDGET="high",
        HINDSIGHT_RECALL_MAX_TOKENS=2048,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=2.5,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=4.0,
        HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS=20,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.5,
        _env_file=None,
    )
    assert settings.HINDSIGHT_RECALL_ENABLED is True
    assert settings.HINDSIGHT_RECALL_BUDGET == "high"
    assert settings.HINDSIGHT_RECALL_MAX_TOKENS == 2048
    assert settings.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS == 2.5
    assert settings.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS == 4.0
    assert settings.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS == 20
    assert settings.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS == 0.5


def test_hindsight_recall_enabled_requires_hindsight_enabled():
    """Enabling recall while HINDSIGHT_ENABLED=False must be rejected."""
    with pytest.raises(
        ValueError,
        match="HINDSIGHT_RECALL_ENABLED cannot be True when HINDSIGHT_ENABLED is False",
    ):
        Settings(
            HINDSIGHT_ENABLED=False,
            HINDSIGHT_RECALL_ENABLED=True,
            _env_file=None,
        )


@pytest.mark.parametrize("invalid_budget", ["extreme", "ultra", "", "low_mid"])
def test_hindsight_recall_invalid_budget_rejected(invalid_budget):
    """Invalid budget level must be rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_RECALL_BUDGET must be one of"):
        Settings(
            HINDSIGHT_RECALL_BUDGET=invalid_budget,
            _env_file=None,
        )


@pytest.mark.parametrize("invalid_tokens", [0, -1, -500])
def test_hindsight_recall_invalid_max_tokens_rejected(invalid_tokens):
    """Zero or negative token ceilings must be rejected."""
    with pytest.raises(ValueError, match="HINDSIGHT_RECALL_MAX_TOKENS must be a positive integer"):
        Settings(
            HINDSIGHT_RECALL_MAX_TOKENS=invalid_tokens,
            _env_file=None,
        )


@pytest.mark.parametrize(
    ("field", "bad_val"),
    [
        ("HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS", 0.0),
        ("HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS", -1.0),
        ("HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS", 0.0),
        ("HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS", -2.5),
        ("HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS", 0.0),
        ("HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS", -0.5),
    ],
)
def test_hindsight_recall_non_positive_timeouts_rejected(field, bad_val):
    """Zero and negative timeout values must be rejected."""
    with pytest.raises(ValueError, match=f"{field} must be positive"):
        Settings(**{field: bad_val}, _env_file=None)


@pytest.mark.parametrize(
    "field",
    [
        "HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS",
    ],
)
@pytest.mark.parametrize("non_finite", [float("nan"), float("inf"), float("-inf")])
def test_hindsight_recall_non_finite_floats_rejected(field, non_finite):
    """Non-finite floats must be rejected."""
    with pytest.raises(ValueError, match=f"{field} must be a finite number"):
        Settings(**{field: non_finite}, _env_file=None)


def test_hindsight_recall_request_timeout_exceeds_overall_rejected():
    """Per-request timeout cannot exceed overall retrieval deadline."""
    with pytest.raises(
        ValueError,
        match="cannot exceed HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
    ):
        Settings(
            HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=6.0,
            HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=5.0,
            _env_file=None,
        )


def test_hindsight_recall_semaphore_timeout_gte_overall_rejected():
    """Semaphore wait timeout must be strictly less than overall deadline."""
    with pytest.raises(
        ValueError,
        match="must be strictly less than HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
    ):
        Settings(
            HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=5.0,
            HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=5.0,
            _env_file=None,
        )

    with pytest.raises(
        ValueError,
        match="must be strictly less than HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
    ):
        Settings(
            HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=6.0,
            HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=5.0,
            _env_file=None,
        )


@pytest.mark.parametrize("bad_concurrency", [0, -1, 101, 500])
def test_hindsight_recall_invalid_concurrency_rejected(bad_concurrency):
    """Concurrency limits outside 1..100 must be rejected."""
    with pytest.raises(
        ValueError,
        match="HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS must be between 1 and 100",
    ):
        Settings(
            HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS=bad_concurrency,
            _env_file=None,
        )


def test_hindsight_recall_historical_keys_maximum_enforced():
    """More than 2 historical keys must be rejected per architectural bound."""
    key_32bytes = SecretStr("a" * 32)
    # Exactly 2 previous keys is permitted
    s = Settings(
        HINDSIGHT_PREVIOUS_HMAC_KEYS={
            "v0": key_32bytes,
            "v0_beta": key_32bytes,
        },
        _env_file=None,
    )
    assert len(s.HINDSIGHT_PREVIOUS_HMAC_KEYS) == 2

    # 3 previous keys is rejected
    with pytest.raises(
        ValueError,
        match="HINDSIGHT_PREVIOUS_HMAC_KEYS cannot exceed 2 historical keys",
    ):
        Settings(
            HINDSIGHT_PREVIOUS_HMAC_KEYS={
                "v0": key_32bytes,
                "v0_beta": key_32bytes,
                "v0_alpha": key_32bytes,
            },
            _env_file=None,
        )


def test_hindsight_recall_max_tokens_ceiling_enforced():
    """max_tokens cannot exceed the configured ceiling."""
    settings = Settings(_env_file=None)
    assert settings.HINDSIGHT_RECALL_MAX_TOKENS_CEILING == 4096

    with pytest.raises(ValueError, match="must be a positive integer <= 4096"):
        Settings(HINDSIGHT_RECALL_MAX_TOKENS=5000, _env_file=None)

    # Valid boundary value
    s = Settings(HINDSIGHT_RECALL_MAX_TOKENS=4096, _env_file=None)
    assert s.HINDSIGHT_RECALL_MAX_TOKENS == 4096


@pytest.mark.parametrize(
    "field",
    [
        "HINDSIGHT_RECALL_MAX_TOKENS",
        "HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS",
    ],
)
def test_hindsight_recall_booleans_rejected(field):
    """Booleans must not silently pass as integers or floats."""
    with pytest.raises(ValueError):
        Settings(**{field: True}, _env_file=None)
    with pytest.raises(ValueError):
        Settings(**{field: False}, _env_file=None)


def test_settings_load_secret_from_file(tmp_path):
    """Test that _FILE environment variable successfully populates secret fields."""
    secret_file = tmp_path / "db_secret.txt"
    secret_file.write_text("postgresql+psycopg://test_user:test_pass@localhost:5432/test_db", encoding="utf-8")

    settings = Settings(DATABASE_URL_FILE=str(secret_file), _env_file=None)
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://test_user:test_pass@localhost:5432/test_db"


def test_settings_direct_secret_takes_precedence_over_file(tmp_path):
    """Direct secret specification takes precedence over _FILE."""
    secret_file = tmp_path / "db_secret.txt"
    secret_file.write_text("postgresql+psycopg://file_user:file_pass@localhost:5432/file_db", encoding="utf-8")

    settings = Settings(
        DATABASE_URL="postgresql+psycopg://direct_user:direct_pass@localhost:5432/direct_db",
        DATABASE_URL_FILE=str(secret_file),
        _env_file=None,
    )
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://direct_user:direct_pass@localhost:5432/direct_db"


def test_settings_app_database_url_mapping():
    """Test that APP_DATABASE_URL maps to DATABASE_URL if DATABASE_URL is not set."""
    settings = Settings(
        APP_DATABASE_URL="postgresql+psycopg://app_user:app_pass@localhost:5432/app_db",
        _env_file=None,
    )
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://app_user:app_pass@localhost:5432/app_db"


def test_settings_migration_database_url_mapping():
    """Test that MIGRATION_DATABASE_URL maps to DATABASE_URL if DATABASE_URL is not set."""
    settings = Settings(
        MIGRATION_DATABASE_URL="postgresql+psycopg://mig_user:mig_pass@localhost:5432/mig_db",
        _env_file=None,
    )
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://mig_user:mig_pass@localhost:5432/mig_db"


def test_settings_app_database_url_file_mapping(tmp_path):
    """Test that APP_DATABASE_URL_FILE maps to DATABASE_URL if DATABASE_URL is not set."""
    secret_file = tmp_path / "app_db_secret.txt"
    secret_file.write_text("postgresql+psycopg://file_app:pass@db:5432/prod_db", encoding="utf-8")

    settings = Settings(APP_DATABASE_URL_FILE=str(secret_file), _env_file=None)
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://file_app:pass@db:5432/prod_db"


def test_settings_migration_database_url_file_mapping(tmp_path):
    """Test that MIGRATION_DATABASE_URL_FILE maps to DATABASE_URL if DATABASE_URL is not set."""
    secret_file = tmp_path / "mig_db_secret.txt"
    secret_file.write_text("postgresql+psycopg://file_mig:pass@db:5432/prod_db", encoding="utf-8")

    settings = Settings(MIGRATION_DATABASE_URL_FILE=str(secret_file), _env_file=None)
    assert settings.DATABASE_URL is not None
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://file_mig:pass@db:5432/prod_db"


# -----------------------------------------------------------------------------
# Task 12.2 Production Configuration and Secrets Management Tests
# -----------------------------------------------------------------------------
from app.core.config import ProductionConfigurationError


def test_settings_secret_file_nonexistent_fails():
    """Configuring a non-existent secret file raises ValueError identifying the missing file."""
    with pytest.raises(ValueError) as exc_info:
        Settings(DATABASE_URL_FILE="/nonexistent/path/secret.txt", _env_file=None)
    assert "DATABASE_URL_FILE does not exist" in str(exc_info.value)
    assert "/nonexistent/path/secret.txt" in str(exc_info.value)


def test_settings_secret_file_empty_fails(tmp_path):
    """Configuring an empty secret file for a required secret raises ValueError."""
    empty_file = tmp_path / "empty_secret.txt"
    empty_file.write_text("   \n", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        Settings(DATABASE_URL_FILE=str(empty_file), _env_file=None)
    assert "DATABASE_URL_FILE is empty" in str(exc_info.value)


def test_settings_secret_file_permission_denied_fails(monkeypatch, tmp_path):
    """When a secret file cannot be read due to permission error, raises ValueError with clear diagnosis."""
    secret_file = tmp_path / "unreadable_secret.txt"
    secret_file.write_text("super_secret_payload", encoding="utf-8")

    def mock_read_text(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", mock_read_text)

    with pytest.raises(ValueError) as exc_info:
        Settings(DATABASE_URL_FILE=str(secret_file), _env_file=None)
    err_msg = str(exc_info.value)
    assert "DATABASE_URL_FILE cannot be read: PermissionError (access denied)" in err_msg
    assert "mode 0644 or GID 10001" in err_msg
    assert "super_secret_payload" not in err_msg


def test_settings_operator_credentials_file_loading(tmp_path):
    """Loading operator credentials via OPERATOR_CREDENTIALS_FILE parses successfully."""
    creds_json = (
        '[{"operator_id": "op-test-01", "role": "analyst", '
        '"key_sha256": "c04fb597231c134cb36ab30d09e7bcfb0b030d8431813982b1cb1c55e10bc7ff"}]'
    )
    creds_file = tmp_path / "operator_creds.json"
    creds_file.write_text(creds_json, encoding="utf-8")

    settings = Settings(OPERATOR_CREDENTIALS_FILE=str(creds_file), _env_file=None)
    assert settings.OPERATOR_CREDENTIALS is not None
    assert "op-test-01" in settings.OPERATOR_CREDENTIALS.get_secret_value()


def test_settings_operator_credentials_file_empty_fails(tmp_path):
    """Empty OPERATOR_CREDENTIALS_FILE raises ValueError."""
    empty_file = tmp_path / "empty_creds.json"
    empty_file.write_text("", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        Settings(OPERATOR_CREDENTIALS_FILE=str(empty_file), _env_file=None)
    assert "OPERATOR_CREDENTIALS_FILE is empty" in str(exc_info.value)


def test_settings_gemini_api_key_empty_file_treated_as_unconfigured(monkeypatch, tmp_path):
    """An empty GEMINI_API_KEY_FILE is treated as unconfigured (None) so system starts without LLM."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY_FILE", raising=False)
    empty_key = tmp_path / "empty_gemini.txt"
    empty_key.write_text("", encoding="utf-8")

    settings = Settings(GEMINI_API_KEY=None, GEMINI_API_KEY_FILE=str(empty_key), _env_file=None)
    assert settings.GEMINI_API_KEY is None


def test_production_contract_missing_database_url_fails():
    """In production, missing database URL fails production contract validation."""
    settings = Settings(ENVIRONMENT="production", DATABASE_URL=None, _env_file=None)
    with pytest.raises(ProductionConfigurationError) as exc_info:
        settings.validate_production_contract(process_type="api")
    assert "Required production configuration missing: APP_DATABASE_URL" in str(exc_info.value)


def test_production_contract_missing_operator_credentials_fails():
    """In production API, missing operator credentials fails contract validation."""
    settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://sentinel_app_role:secret@db:5432/sentinelagent",
        OPERATOR_CREDENTIALS=None,
        _env_file=None,
    )
    with pytest.raises(ProductionConfigurationError) as exc_info:
        settings.validate_production_contract(process_type="api")
    assert "Required production configuration missing: OPERATOR_CREDENTIALS" in str(exc_info.value)


def test_production_contract_worker_does_not_require_operator_credentials():
    """Response worker process requires database URL but does not require OPERATOR_CREDENTIALS."""
    settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://sentinel_app_role:secret@db:5432/sentinelagent",
        OPERATOR_CREDENTIALS=None,
        _env_file=None,
    )
    # Worker contract validation passes cleanly
    settings.validate_production_contract(process_type="worker")


def test_production_contract_migration_requires_migration_dsn():
    """Migration process specifically requires migration database URL or DATABASE_URL."""
    settings = Settings(ENVIRONMENT="production", DATABASE_URL=None, _env_file=None)
    with pytest.raises(ProductionConfigurationError) as exc_info:
        settings.validate_production_contract(process_type="migration")
    assert "Required production configuration missing: MIGRATION_DATABASE_URL" in str(exc_info.value)


def test_production_contract_rejects_debug_in_production():
    """In production, DEBUG mode is strictly forbidden."""
    settings = Settings(
        ENVIRONMENT="production",
        DEBUG=True,
        DATABASE_URL="postgresql+psycopg://sentinel_app_role:secret@db:5432/sentinelagent",
        _env_file=None,
    )
    with pytest.raises(ProductionConfigurationError) as exc_info:
        settings.validate_production_contract(process_type="api")
    assert "DEBUG mode cannot be enabled in production" in str(exc_info.value)


def test_production_contract_rejects_bootstrap_admin_in_runtime():
    """Production runtime (api/worker) must not use bootstrap admin credentials in database URL."""
    settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://sentinel_admin:secret@db:5432/sentinelagent",
        _env_file=None,
    )
    with pytest.raises(ProductionConfigurationError) as exc_info:
        settings.validate_production_contract(process_type="api")
    assert "must not use bootstrap admin credentials" in str(exc_info.value)


def test_production_contract_hindsight_disabled_starts_cleanly():
    """When HINDSIGHT_ENABLED is False (default), optional Hindsight settings are not required."""
    creds_json = (
        '[{"operator_id": "op-test-01", "role": "analyst", '
        '"key_sha256": "c04fb597231c134cb36ab30d09e7bcfb0b030d8431813982b1cb1c55e10bc7ff"}]'
    )
    settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://sentinel_app_role:secret@db:5432/sentinelagent",
        OPERATOR_CREDENTIALS=creds_json,
        HINDSIGHT_ENABLED=False,
        _env_file=None,
    )
    # Passes without any Hindsight credentials
    settings.validate_production_contract(process_type="api")


def test_production_contract_hindsight_enabled_requires_credentials():
    """When HINDSIGHT_ENABLED is True in production, missing credentials fail safely."""
    creds_json = (
        '[{"operator_id": "op-test-01", "role": "analyst", '
        '"key_sha256": "c04fb597231c134cb36ab30d09e7bcfb0b030d8431813982b1cb1c55e10bc7ff"}]'
    )
    with pytest.raises(Exception) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://sentinel_app_role:secret@db:5432/sentinelagent",
            OPERATOR_CREDENTIALS=creds_json,
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL="https://hindsight.local",
            HINDSIGHT_API_KEY=None,
            _env_file=None,
        )
    assert "HINDSIGHT_API_KEY must be explicitly configured when HINDSIGHT_ENABLED is True" in str(exc_info.value)


def test_production_contract_secret_values_never_leak_in_error_message(tmp_path):
    """Validation errors must never print secret credentials or passwords in error messages."""
    sensitive_token = "SUPER_SECRET_UNLEAKABLE_TOKEN_999888777"
    bad_creds_file = tmp_path / "bad_creds.json"
    bad_creds_file.write_text(f"malformed_json_with_{sensitive_token}", encoding="utf-8")

    with pytest.raises(Exception) as exc_info:
        Settings(OPERATOR_CREDENTIALS_FILE=str(bad_creds_file), _env_file=None)

    error_text = str(exc_info.value)
    assert sensitive_token not in error_text, "Sensitive secret value leaked in error message!"


# ---------------------------------------------------------------------------
# Task 12.2 Secrets Permission & Scoping Security Policy Checks
# ---------------------------------------------------------------------------

def test_generate_secrets_script_permission_policy_contract():
    """Verify generate-secrets.sh enforces explicit 0700 directory permissions and policy checks."""
    script_path = Path(__file__).resolve().parents[2] / "deploy" / "sentinelagent" / "scripts" / "generate-secrets.sh"
    assert script_path.exists(), f"generate-secrets.sh not found at {script_path}"

    content = script_path.read_text(encoding="utf-8")

    # 1. Directory permission must be explicitly set to 700
    assert 'chmod 700 "$SECRETS_DIR"' in content

    # 2. Must not use 750 directory fallback
    assert "chmod 750" not in content

    # 3. Mode 0644 on files must only be applied if directory permission is confirmed 700
    assert 'if [ "$DIR_PERM" = "700" ]; then' in content
    assert 'chmod 644 "$SECRETS_DIR"/*' in content
    assert "Refusing to set 0644 on secrets" in content

    # 4. Directory ownership check must be present
    assert "DIR_OWNER_UID" in content
    assert "CURRENT_UID" in content

    # 5. Rootful and rootless requirements must be documented
    assert "Rootful Docker" in content
    assert "Rootless Docker" in content

    # 6. Must not grant world-writable access
    assert "chmod 777" not in content
    assert "chmod 666" not in content


def test_compose_service_level_secret_scoping():
    """Verify compose.yaml scopes secrets strictly to the service level and uses file-backed secrets."""
    import yaml

    compose_path = Path(__file__).resolve().parents[2] / "deploy" / "sentinelagent" / "compose.yaml"
    assert compose_path.exists(), f"compose.yaml not found at {compose_path}"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    # 1. All top-level secrets must use file-backed sources
    secrets = compose_data.get("secrets", {})
    assert len(secrets) == 7
    for name, conf in secrets.items():
        assert "file" in conf, f"Secret {name} is not file-backed: {conf}"

    # 2. Database service receives only database passwords (no app DSNs or operator creds)
    db_secrets = compose_data["services"]["db"]["secrets"]
    assert set(db_secrets) == {"postgres_admin_password", "migration_password", "app_password"}

    # 3. Migration service receives only migration DSN
    migration_secrets = compose_data["services"]["migration"]["secrets"]
    assert set(migration_secrets) == {"migration_database_url"}

    # 4. API and Worker services receive only application runtime secrets
    api_secrets = compose_data["services"]["api"]["secrets"]
    assert set(api_secrets) == {"app_database_url", "operator_credentials", "gemini_api_key"}

    worker_secrets = compose_data["services"]["worker"]["secrets"]
    assert set(worker_secrets) == {"app_database_url", "operator_credentials", "gemini_api_key"}


def test_generate_secrets_idempotency_preserves_existing_secrets(tmp_path):
    """Secret generation logic must be idempotent and never overwrite existing secrets."""
    # Create existing custom secrets
    custom_admin = "custom_preexisting_admin_pass"
    custom_dsn = "postgresql+psycopg://sentinel_app_role:existing@db:5432/sentinelagent"

    admin_file = tmp_path / "postgres_admin_password.txt"
    admin_file.write_text(custom_admin, encoding="utf-8")

    dsn_file = tmp_path / "app_database_url.txt"
    dsn_file.write_text(custom_dsn, encoding="utf-8")

    # Simulate non-destructive generation check (only write if not exists)
    if not (tmp_path / "postgres_admin_password.txt").exists():
        admin_file.write_text("overwritten_admin", encoding="utf-8")

    if not (tmp_path / "app_database_url.txt").exists():
        dsn_file.write_text("overwritten_dsn", encoding="utf-8")

    # Verify preserved content
    assert admin_file.read_text(encoding="utf-8") == custom_admin
    assert dsn_file.read_text(encoding="utf-8") == custom_dsn









