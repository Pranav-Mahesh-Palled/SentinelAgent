"""Application configuration using Pydantic Settings."""

from functools import lru_cache
import math
from pathlib import Path
from typing import Any, Literal, Optional
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Root directory of SentinelAgent project
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Permitted thinking levels for Gemini 3.8 reasoning models (low, medium, high)
PermittedThinkingLevel = Literal["low", "medium", "high"]
VALID_THINKING_LEVELS = {"low", "medium", "high"}

# Non-overridable hard ceiling for recall token budget across all environments
HINDSIGHT_RECALL_MAX_TOKENS_ABSOLUTE_CEILING: int = 4096


class ProductionConfigurationError(ValueError):
    """Raised when required production configuration or credentials are missing or invalid."""
    pass


class Settings(BaseSettings):
    """SentinelAgent application configuration loaded from environment or .env file."""

    APP_NAME: str = "SentinelAgent API"
    APP_DESCRIPTION: str = "AI-Powered Cybersecurity Investigation System"
    APP_VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = False

    # PostgreSQL connection URL using Psycopg 3 driver
    # Format: postgresql+psycopg://sentinelagent_user:<password>@localhost:5432/sentinelagent
    DATABASE_URL: Optional[SecretStr] = None
    APP_DATABASE_URL: Optional[SecretStr] = None
    MIGRATION_DATABASE_URL: Optional[SecretStr] = None

    # Application environment ("development", "production", "test")
    ENVIRONMENT: str = "development"

    # Google Gemini API Settings (Task 7B Investigation Agent)
    GEMINI_API_KEY: Optional[SecretStr] = None
    GEMINI_MODEL: str = "gemini-3.8-flash"
    GEMINI_MAX_OUTPUT_TOKENS: int = 8192
    GEMINI_TIMEOUT_SECONDS: int = 120
    GEMINI_THINKING_LEVEL: PermittedThinkingLevel = "medium"

    # MITRE ATT&CK Catalogue Settings (Task 8B/8E)
    MITRE_REQUIRED: bool = False
    MITRE_CATALOGUE_PATH: Path = (
        PROJECT_ROOT / "backend" / "app" / "data" / "mitre" / "mitre_attack_enterprise_v20_1.json"
    )

    # Hindsight Persistent Incident Memory Settings (Task 9)
    HINDSIGHT_ENABLED: bool = False
    HINDSIGHT_REQUIRED: bool = False
    HINDSIGHT_BASE_URL: Optional[str] = None
    HINDSIGHT_API_KEY: Optional[SecretStr] = None
    HINDSIGHT_BANK_ID: Optional[str] = None
    HINDSIGHT_TIMEOUT_SECONDS: float = 30.0
    HINDSIGHT_HMAC_KEY: Optional[SecretStr] = None
    HINDSIGHT_HMAC_KEY_VERSION: str = "v1"
    HINDSIGHT_PREVIOUS_HMAC_KEYS: dict[str, SecretStr] = Field(default_factory=dict)

    # Hindsight Asynchronous Outbox Retention Worker Settings (Task 9C.3)
    HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS: float = 2.0
    HINDSIGHT_OUTBOX_BATCH_SIZE: int = 10
    HINDSIGHT_OUTBOX_MAX_CONCURRENCY: int = 5
    HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS: float = 45.0
    HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS: float = 15.0
    HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS: float = 5.0
    HINDSIGHT_OUTBOX_MAX_ATTEMPTS: int = 8
    HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS: float = 5.0
    HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS: float = 300.0
    HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION: float = 0.2
    HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS: float = 15.0
    HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS: float = 30.0

    # Hindsight Historical Incident Memory Recall Settings (Task 9D)
    HINDSIGHT_RECALL_ENABLED: bool = False
    HINDSIGHT_RECALL_BUDGET: str = "mid"
    HINDSIGHT_RECALL_MAX_TOKENS: int = 1024
    HINDSIGHT_RECALL_MAX_TOKENS_CEILING: int = 4096
    HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS: float = 3.0
    HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS: float = 5.0
    HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS: int = 10
    HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS: float = 1.0
    HINDSIGHT_HMAC_MAX_HISTORICAL_KEYS: int = 2

    # Operator Authentication and Authorization Settings (Task 11.1)
    OPERATOR_CREDENTIALS: Optional[SecretStr] = None

    # Response Orchestration Outbox & Background Worker Settings (Task 11.3B)
    RESPONSE_OUTBOX_POLL_INTERVAL_SECONDS: float = 2.0
    RESPONSE_OUTBOX_BATCH_SIZE: int = 5
    RESPONSE_OUTBOX_MAX_CONCURRENCY: int = 5
    RESPONSE_OUTBOX_LEASE_DURATION_SECONDS: int = 60
    RESPONSE_SWEEPER_INTERVAL_SECONDS: float = 10.0
    RESPONSE_SWEEPER_BATCH_SIZE: int = 20

    @model_validator(mode="before")
    @classmethod
    def load_secret_files(cls, data: Any) -> Any:
        """Resolve Docker and system secrets from _FILE environment variables if provided.

        Preserves precedence: direct environment variables take precedence over file-based secrets.
        Also maps APP_DATABASE_URL or MIGRATION_DATABASE_URL to DATABASE_URL if not directly set.
        Rejects non-existent or empty required secret files without leaking secret values.
        """
        if isinstance(data, dict):
            import os
            secret_keys = [
                "DATABASE_URL",
                "APP_DATABASE_URL",
                "MIGRATION_DATABASE_URL",
                "GEMINI_API_KEY",
                "OPERATOR_CREDENTIALS",
                "HINDSIGHT_API_KEY",
                "HINDSIGHT_HMAC_KEY",
            ]
            for key in secret_keys:
                file_key = f"{key}_FILE"
                file_path = data.get(file_key) or os.environ.get(file_key)
                if file_path:
                    # Precedence: direct key takes precedence if already set and non-empty
                    direct_val = data.get(key)
                    if direct_val is None:
                        direct_val = os.environ.get(key)
                    if direct_val is not None:
                        if isinstance(direct_val, SecretStr):
                            raw_direct = direct_val.get_secret_value().strip()
                        else:
                            raw_direct = str(direct_val).strip()
                        if raw_direct:
                            continue

                    # Validate file existence
                    p = Path(str(file_path).strip())
                    if not p.exists() or not p.is_file():
                        raise ValueError(f"Secret file configured by {file_key} does not exist: {file_path}")

                    try:
                        content = p.read_text(encoding="utf-8").strip()
                    except PermissionError as exc:
                        raise ValueError(
                            f"Secret file configured by {file_key} cannot be read: PermissionError (access denied). "
                            "Verify host file permissions (e.g. mode 0644 or GID 10001 for non-root containers)."
                        ) from exc
                    except Exception as exc:
                        raise ValueError(f"Secret file configured by {file_key} cannot be read: {exc.__class__.__name__}") from exc

                    # For core required secrets, an empty file is invalid
                    if not content:
                        if key in ("DATABASE_URL", "APP_DATABASE_URL", "MIGRATION_DATABASE_URL", "OPERATOR_CREDENTIALS"):
                            raise ValueError(f"Secret file configured by {file_key} is empty: {file_path}")
                        # Optional secrets like GEMINI_API_KEY or HINDSIGHT keys: empty file means unconfigured
                        continue

                    data[key] = content

            # Map APP_DATABASE_URL or MIGRATION_DATABASE_URL to DATABASE_URL if DATABASE_URL is not set
            if not data.get("DATABASE_URL") and not os.environ.get("DATABASE_URL"):
                if data.get("APP_DATABASE_URL"):
                    data["DATABASE_URL"] = data["APP_DATABASE_URL"]
                elif data.get("MIGRATION_DATABASE_URL"):
                    data["DATABASE_URL"] = data["MIGRATION_DATABASE_URL"]

        return data

    @model_validator(mode="after")
    def validate_operator_credentials_settings(self) -> "Settings":
        """Validate operator credentials format if explicitly provided."""
        if self.OPERATOR_CREDENTIALS is not None:
            raw = self.OPERATOR_CREDENTIALS.get_secret_value().strip()
            if raw:
                from app.core.auth import validate_operator_credentials_json
                validate_operator_credentials_json(raw)
        return self

    def validate_production_contract(self, process_type: str = "api") -> None:
        """Validate production configuration contract.

        Ensures that required settings and credentials are configured for production
        execution and fail clearly and safely without printing secrets in error messages.

        Args:
            process_type: The role of the executing process ("api", "worker", or "migration").

        Raises:
            ProductionConfigurationError: If any required setting is missing or invalid.
        """
        env_lower = self.ENVIRONMENT.strip().lower() if self.ENVIRONMENT else "development"
        is_prod = env_lower in ("production", "prod")

        if not is_prod:
            return

        # 1. In production, DEBUG mode must never be enabled
        if self.DEBUG:
            raise ProductionConfigurationError(
                "Invalid production configuration: DEBUG mode cannot be enabled in production."
            )

        # 2. Database Connection URL Validation
        if not self.DATABASE_URL or not self.DATABASE_URL.get_secret_value().strip():
            if process_type == "migration":
                raise ProductionConfigurationError(
                    "Required production configuration missing: MIGRATION_DATABASE_URL (or DATABASE_URL)."
                )
            else:
                raise ProductionConfigurationError(
                    "Required production configuration missing: APP_DATABASE_URL (or DATABASE_URL)."
                )

        # 3. Process-specific credential requirements
        if process_type in ("api", "worker"):
            db_val = self.DATABASE_URL.get_secret_value().lower()
            if "sentinel_admin" in db_val:
                raise ProductionConfigurationError(
                    f"Production {process_type} process must not use bootstrap admin credentials in database URL."
                )

        if process_type == "api":
            if not self.OPERATOR_CREDENTIALS or not self.OPERATOR_CREDENTIALS.get_secret_value().strip():
                raise ProductionConfigurationError(
                    "Required production configuration missing: OPERATOR_CREDENTIALS (or OPERATOR_CREDENTIALS_FILE)."
                )
            try:
                from app.core.auth import validate_operator_credentials_json
                validate_operator_credentials_json(self.OPERATOR_CREDENTIALS.get_secret_value().strip())
            except Exception as exc:
                raise ProductionConfigurationError(
                    f"Invalid production configuration: OPERATOR_CREDENTIALS validation failed: {exc.__class__.__name__}"
                ) from exc

        # 4. Optional Hindsight Configuration
        # If disabled (default), optional Hindsight settings must not block startup.
        # If enabled in production, base URL, API key, and prod bank ID are verified.
        if self.HINDSIGHT_ENABLED:
            if not self.HINDSIGHT_BASE_URL or not self.HINDSIGHT_BASE_URL.strip():
                raise ProductionConfigurationError(
                    "Required configuration missing: HINDSIGHT_BASE_URL when HINDSIGHT_ENABLED is true."
                )
            if not self.HINDSIGHT_API_KEY or not self.HINDSIGHT_API_KEY.get_secret_value().strip():
                raise ProductionConfigurationError(
                    "Required configuration missing: HINDSIGHT_API_KEY when HINDSIGHT_ENABLED is true."
                )


    @model_validator(mode="after")
    def validate_hindsight_settings(self) -> "Settings":
        """Validate Hindsight settings consistency and environment bank isolation."""
        if self.HINDSIGHT_REQUIRED and not self.HINDSIGHT_ENABLED:
            raise ValueError(
                "HINDSIGHT_REQUIRED cannot be True when HINDSIGHT_ENABLED is False."
            )

        if self.HINDSIGHT_ENABLED:
            if not self.HINDSIGHT_BASE_URL or not self.HINDSIGHT_BASE_URL.strip():
                raise ValueError(
                    "HINDSIGHT_BASE_URL must be explicitly configured when HINDSIGHT_ENABLED is True."
                )
            if not self.HINDSIGHT_API_KEY or not self.HINDSIGHT_API_KEY.get_secret_value().strip():
                raise ValueError(
                    "HINDSIGHT_API_KEY must be explicitly configured when HINDSIGHT_ENABLED is True."
                )
            self.HINDSIGHT_BASE_URL = self.HINDSIGHT_BASE_URL.rstrip("/")

            # Validate active HMAC key configuration if configured
            if self.HINDSIGHT_HMAC_KEY:
                raw_active = self.HINDSIGHT_HMAC_KEY.get_secret_value().strip()
                if not raw_active:
                    raise ValueError("HINDSIGHT_HMAC_KEY cannot be empty.")
                if len(raw_active.encode("utf-8")) < 32:
                    raise ValueError(
                        "HINDSIGHT_HMAC_KEY must be at least 32 UTF-8 bytes (256 bits) for cryptographic security."
                    )
            if self.HINDSIGHT_HMAC_KEY_VERSION is not None and not self.HINDSIGHT_HMAC_KEY_VERSION.strip():
                raise ValueError(
                    "HINDSIGHT_HMAC_KEY_VERSION cannot be empty."
                )

            # Validate previous rotation keys if present
            if self.HINDSIGHT_PREVIOUS_HMAC_KEYS:
                for prev_ver, prev_key in self.HINDSIGHT_PREVIOUS_HMAC_KEYS.items():
                    if not prev_ver or not prev_ver.strip():
                        raise ValueError("Previous HMAC key version identifier cannot be empty.")
                    if prev_ver.strip() == self.HINDSIGHT_HMAC_KEY_VERSION.strip():
                        raise ValueError(
                            f"Previous HMAC key version '{prev_ver}' conflicts with active key version."
                        )
                    raw_prev = prev_key.get_secret_value().strip() if prev_key else ""
                    if not raw_prev:
                        raise ValueError(f"Previous HMAC key for version '{prev_ver}' cannot be empty.")
                    if len(raw_prev.encode("utf-8")) < 32:
                        raise ValueError(
                            f"Previous HMAC key for version '{prev_ver}' must be at least 32 UTF-8 bytes."
                        )

        # Resolve and validate HINDSIGHT_BANK_ID
        env_lower = self.ENVIRONMENT.strip().lower() if self.ENVIRONMENT else "development"
        is_prod = env_lower in ("production", "prod")

        if not self.HINDSIGHT_BANK_ID or not self.HINDSIGHT_BANK_ID.strip():
            self.HINDSIGHT_BANK_ID = (
                "sentinelagent-incident-memory-prod" if is_prod else "sentinelagent-incident-memory-dev"
            )
        else:
            if not is_prod and "prod" in self.HINDSIGHT_BANK_ID.lower():
                raise ValueError(
                    f"Non-production environment ('{self.ENVIRONMENT}') cannot use production memory bank '{self.HINDSIGHT_BANK_ID}'."
                )

        return self

    @model_validator(mode="after")
    def validate_hindsight_worker_settings(self) -> "Settings":
        """Validate Hindsight outbox worker configuration parameters."""
        # Validate that all floating-point worker settings are finite numbers (reject NaN, +inf, -inf)
        float_fields = (
            ("HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS", self.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS),
            ("HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS", self.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS),
            ("HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS", self.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS),
            ("HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS", self.HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS),
            ("HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS", self.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS),
            ("HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS", self.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS),
            ("HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION", self.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION),
            ("HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS", self.HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS),
            ("HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS", self.HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS),
        )
        for name, val in float_fields:
            if not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(f"{name} must be a finite number, got {val}.")

        if self.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS}."
            )
        if not (1 <= self.HINDSIGHT_OUTBOX_BATCH_SIZE <= 100):
            raise ValueError(
                f"HINDSIGHT_OUTBOX_BATCH_SIZE must be between 1 and 100, got {self.HINDSIGHT_OUTBOX_BATCH_SIZE}."
            )
        if not (1 <= self.HINDSIGHT_OUTBOX_MAX_CONCURRENCY <= 100):
            raise ValueError(
                f"HINDSIGHT_OUTBOX_MAX_CONCURRENCY must be between 1 and 100, got {self.HINDSIGHT_OUTBOX_MAX_CONCURRENCY}."
            )
        if self.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS}."
            )
        if self.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS}."
            )
        if self.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS >= self.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS ({self.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS}) "
                f"must be strictly less than HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS ({self.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS})."
            )
        if self.HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS}."
            )
        if self.HINDSIGHT_OUTBOX_MAX_ATTEMPTS < 1:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_MAX_ATTEMPTS must be positive (>= 1), got {self.HINDSIGHT_OUTBOX_MAX_ATTEMPTS}."
            )
        if self.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS}."
            )
        if self.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS < self.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS ({self.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS}) "
                f"must be greater than or equal to HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS ({self.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS})."
            )
        if not (0.0 <= self.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION <= 1.0):
            raise ValueError(
                f"HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION must be between 0.0 and 1.0 inclusive, got {self.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION}."
            )
        if self.HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS}."
            )
        if self.HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS <= 0:
            raise ValueError(
                f"HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS must be positive, got {self.HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS}."
            )
        return self

    @model_validator(mode="after")
    def validate_hindsight_recall_settings(self) -> "Settings":
        """Validate Hindsight historical incident-memory recall settings (Task 9D)."""
        if self.HINDSIGHT_RECALL_ENABLED and not self.HINDSIGHT_ENABLED:
            raise ValueError(
                "HINDSIGHT_RECALL_ENABLED cannot be True when HINDSIGHT_ENABLED is False."
            )

        if self.HINDSIGHT_RECALL_BUDGET not in ("low", "mid", "high"):
            raise ValueError(
                f"HINDSIGHT_RECALL_BUDGET must be one of ('low', 'mid', 'high'), got '{self.HINDSIGHT_RECALL_BUDGET}'."
            )

        if (
            isinstance(self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING, bool)
            or not isinstance(self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING, int)
            or not (1 <= self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING <= HINDSIGHT_RECALL_MAX_TOKENS_ABSOLUTE_CEILING)
        ):
            raise ValueError(
                f"HINDSIGHT_RECALL_MAX_TOKENS_CEILING must be a positive integer <= {HINDSIGHT_RECALL_MAX_TOKENS_ABSOLUTE_CEILING}, "
                f"got {self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING}."
            )

        if (
            isinstance(self.HINDSIGHT_RECALL_MAX_TOKENS, bool)
            or not isinstance(self.HINDSIGHT_RECALL_MAX_TOKENS, int)
            or not (1 <= self.HINDSIGHT_RECALL_MAX_TOKENS <= self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING)
        ):
            raise ValueError(
                f"HINDSIGHT_RECALL_MAX_TOKENS must be a positive integer <= {self.HINDSIGHT_RECALL_MAX_TOKENS_CEILING}, "
                f"got {self.HINDSIGHT_RECALL_MAX_TOKENS}."
            )

        float_recall_fields = (
            ("HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS", self.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS),
            ("HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS", self.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS),
            ("HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS", self.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS),
        )
        for name, val in float_recall_fields:
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(f"{name} must be a finite number, got {val}.")
            if val <= 0:
                raise ValueError(f"{name} must be positive, got {val}.")

        if self.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS > self.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS:
            raise ValueError(
                f"HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS ({self.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS}) "
                f"cannot exceed HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS ({self.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS})."
            )

        if self.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS >= self.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS:
            raise ValueError(
                f"HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS ({self.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS}) "
                f"must be strictly less than HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS ({self.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS})."
            )

        if (
            isinstance(self.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS, bool)
            or not isinstance(self.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS, int)
            or not (1 <= self.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS <= 100)
        ):
            raise ValueError(
                f"HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS must be between 1 and 100, got {self.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS}."
            )

        if len(self.HINDSIGHT_PREVIOUS_HMAC_KEYS) > self.HINDSIGHT_HMAC_MAX_HISTORICAL_KEYS:
            raise ValueError(
                f"HINDSIGHT_PREVIOUS_HMAC_KEYS cannot exceed {self.HINDSIGHT_HMAC_MAX_HISTORICAL_KEYS} historical keys, "
                f"got {len(self.HINDSIGHT_PREVIOUS_HMAC_KEYS)}."
            )

        return self

    @field_validator(
        "HINDSIGHT_RECALL_MAX_TOKENS",
        "HINDSIGHT_RECALL_MAX_TOKENS_CEILING",
        "HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS",
        "HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS",
        mode="before",
    )
    @classmethod
    def reject_bool_for_numeric_recall_settings(cls, v: object, info: Any) -> object:
        """Reject booleans from being silently coerced to numeric integers or floats."""
        if isinstance(v, bool):
            raise ValueError(f"{info.field_name} must be a number, not a boolean.")
        return v

    @field_validator("GEMINI_THINKING_LEVEL", mode="before")
    @classmethod
    def validate_thinking_level(cls, v: object) -> str:
        """Validate that thinking level matches permitted Gemini reasoning levels."""
        if isinstance(v, str):
            v_lower = v.strip().lower()
            if v_lower in VALID_THINKING_LEVELS:
                return v_lower
        raise ValueError(
            f"Invalid GEMINI_THINKING_LEVEL: '{v}'. Permitted levels are: {sorted(VALID_THINKING_LEVELS)}"
        )

    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()

