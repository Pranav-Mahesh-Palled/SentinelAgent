"""Core configuration and authentication module for SentinelAgent."""

from app.core.auth import (
    AuthenticationConfigurationError,
    AuthenticationError,
    InvalidCredentialsError,
    OperatorCredential,
    OperatorPrincipal,
    OperatorRole,
    PermissionDeniedError,
    authenticate_api_key,
    generate_operator_api_key,
    hash_api_key,
    load_operator_credentials,
    validate_operator_credentials_json,
)
from app.core.config import Settings, get_settings, settings

__all__ = [
    "AuthenticationConfigurationError",
    "AuthenticationError",
    "InvalidCredentialsError",
    "OperatorCredential",
    "OperatorPrincipal",
    "OperatorRole",
    "PermissionDeniedError",
    "Settings",
    "authenticate_api_key",
    "generate_operator_api_key",
    "get_settings",
    "hash_api_key",
    "load_operator_credentials",
    "settings",
    "validate_operator_credentials_json",
]


