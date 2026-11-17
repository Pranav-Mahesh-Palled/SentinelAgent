"""Authentication, Principal, and Credential Management for SentinelAgent Phase 11.

Provides server-side identity verification, operator principal construction,
and role authorization mapping using SHA-256 hashed API keys and constant-time
digest comparison via hmac.compare_digest.
"""

from collections.abc import Sequence
from enum import Enum
import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

logger = logging.getLogger(__name__)

# Regular expression for 64-character lowercase hexadecimal SHA-256 hash
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Minimum required API key entropy length (characters for urlsafe token)
MINIMUM_API_KEY_ENTROPY_LENGTH = 32


# =============================================================================
# Role Definitions
# =============================================================================

class OperatorRole(str, Enum):
    """Permitted operator roles within SentinelAgent."""

    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"


# =============================================================================
# Exceptions
# =============================================================================

class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    pass


class AuthenticationConfigurationError(AuthenticationError):
    """Raised when operator credentials configuration is missing, malformed, or invalid."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when an API key is missing, malformed, or rejected."""
    pass


class PermissionDeniedError(AuthenticationError):
    """Raised when an authenticated principal lacks the required role or permission."""
    pass


# =============================================================================
# Principal Model
# =============================================================================

class OperatorPrincipal(BaseModel):
    """Immutable operator principal constructed exclusively after successful credential verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operator_id: str = Field(..., min_length=1, max_length=128, description="Unique operator identifier")
    role: OperatorRole = Field(..., description="Server-validated operator role")


# =============================================================================
# Credential Configuration Schema
# =============================================================================

class OperatorCredential(BaseModel):
    """Server-side configuration representing a single authorized operator credential."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operator_id: str = Field(..., min_length=1, max_length=128)
    role: OperatorRole
    key_sha256: str = Field(..., description="64-character lowercase SHA-256 hash of the API key")

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("operator_id cannot be empty or whitespace")
        return trimmed

    @field_validator("key_sha256")
    @classmethod
    def validate_key_sha256(cls, v: str) -> str:
        trimmed = v.strip().lower()
        if not SHA256_HEX_PATTERN.match(trimmed):
            raise ValueError("key_sha256 must be a valid 64-character lowercase hexadecimal SHA-256 digest")
        return trimmed


# =============================================================================
# Cryptographic and Verification Helpers
# =============================================================================

def hash_api_key(api_key: str) -> str:
    """Compute standard lowercase hexadecimal SHA-256 digest of an API key."""
    if not api_key or not api_key.strip():
        raise ValueError("Cannot hash empty API key")
    return hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest().lower()


def generate_operator_api_key(prefix: str = "sa_") -> str:
    """Generate a high-entropy operator API key (minimum 256 bits of CSPRNG entropy)."""
    random_part = secrets.token_urlsafe(MINIMUM_API_KEY_ENTROPY_LENGTH)
    return f"{prefix}{random_part}"


def validate_operator_credentials_json(raw_json: str) -> list[OperatorCredential]:
    """Parse and validate JSON operator credentials string, rejecting malformed and duplicate configurations.

    Raises:
        AuthenticationConfigurationError: If the JSON is invalid, empty, contains duplicates,
                                         or fails schema validation.
    """
    if not raw_json or not raw_json.strip():
        raise AuthenticationConfigurationError("Operator credentials configuration string is empty")

    try:
        data = json.loads(raw_json)
    except Exception as exc:
        raise AuthenticationConfigurationError(f"Malformed operator credentials JSON: {exc}") from exc

    if not isinstance(data, list):
        raise AuthenticationConfigurationError("Operator credentials JSON must be a list of credential objects")

    if not data:
        raise AuthenticationConfigurationError("Operator credentials configuration list cannot be empty")

    credentials: list[OperatorCredential] = []
    seen_operator_ids: set[str] = set()
    seen_key_hashes: set[str] = set()

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise AuthenticationConfigurationError(
                f"Credential at index {idx} must be a JSON object, got {type(item).__name__}"
            )
        try:
            cred = OperatorCredential.model_validate(item)
        except Exception as exc:
            raise AuthenticationConfigurationError(
                f"Credential at index {idx} failed validation: {exc}"
            ) from exc

        if cred.operator_id in seen_operator_ids:
            raise AuthenticationConfigurationError(
                f"Duplicate operator_id detected in credentials configuration: '{cred.operator_id}'"
            )
        seen_operator_ids.add(cred.operator_id)

        if cred.key_sha256 in seen_key_hashes:
            raise AuthenticationConfigurationError(
                f"Duplicate key_sha256 hash detected in credentials configuration for operator: '{cred.operator_id}'"
            )
        seen_key_hashes.add(cred.key_sha256)

        credentials.append(cred)

    return credentials


def load_operator_credentials(credentials_secret: Optional[SecretStr]) -> list[OperatorCredential]:
    """Load and validate credentials from a Pydantic SecretStr.

    Fails closed if the secret is unconfigured or empty.
    """
    if credentials_secret is None:
        raise AuthenticationConfigurationError("OPERATOR_CREDENTIALS configuration is missing")

    raw_val = credentials_secret.get_secret_value().strip()
    if not raw_val:
        raise AuthenticationConfigurationError("OPERATOR_CREDENTIALS configuration is empty")

    return validate_operator_credentials_json(raw_val)


def authenticate_api_key(
    api_key: str,
    credentials: Sequence[OperatorCredential],
) -> Optional[OperatorPrincipal]:
    """Verify an API key against server-side hashed credentials using constant-time comparison.

    Uses hmac.compare_digest on the SHA-256 digest of the candidate key against configured hashes.
    Performs comparison across all candidate credentials to mitigate timing side-channels.

    Args:
        api_key: The plaintext candidate API key provided by the caller.
        credentials: The authoritative list of OperatorCredential records.

    Returns:
        OperatorPrincipal if valid credentials match; None otherwise.
    """
    if not api_key or not api_key.strip() or not credentials:
        return None

    try:
        candidate_hash = hash_api_key(api_key)
    except Exception:
        return None

    matched_principal: Optional[OperatorPrincipal] = None

    # Iterate through all configured credentials to maintain constant-time behavior
    for cred in credentials:
        if hmac.compare_digest(candidate_hash, cred.key_sha256):
            # Record the first match
            if matched_principal is None:
                matched_principal = OperatorPrincipal(
                    operator_id=cred.operator_id,
                    role=cred.role,
                )

    return matched_principal
