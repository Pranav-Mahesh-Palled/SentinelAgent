"""FastAPI Security and Principal Authorization Dependencies for SentinelAgent.

Provides reusable dependencies for:
- API-key authentication via HTTP Bearer scheme (get_current_principal).
- Server-side role-based access control (require_roles).
- Proposer/approver identity separation verification.
"""

from collections.abc import Callable, Sequence
import logging
from typing import Optional, Union

from fastapi import Depends, Header, HTTPException, Request, status

from app.core.auth import (
    AuthenticationConfigurationError,
    OperatorPrincipal,
    OperatorRole,
    authenticate_api_key,
    load_operator_credentials,
)
from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

# Standard WWW-Authenticate challenge header value for Bearer scheme
BEARER_AUTH_HEADER = {"WWW-Authenticate": "Bearer"}


def get_app_settings(request: Request) -> Settings:
    """Resolve active application settings from application state or configuration loader."""
    return getattr(request.app.state, "settings", None) or get_settings()


def get_current_principal(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    settings: Settings = Depends(get_app_settings),
) -> OperatorPrincipal:
    """FastAPI dependency: Authenticate incoming request and construct validated OperatorPrincipal.

    Authentication Mechanism:
        Authorization: Bearer <API_KEY>

    Security Invariants:
        1. Tokens are verified exclusively against server-side SHA-256 hashes via constant-time hmac.compare_digest.
        2. Never logs Authorization headers, credentials, or hashes.
        3. Never leaks whether an operator ID exists in error responses (standard generic 401).
        4. Fails closed if operator credentials are not configured or invalid (500 Internal Server Error).
        5. Rejects any client-supplied identity parameters (X-User, operator_id, role).
    """
    # 1. Check presence of Authorization header
    if not authorization or not authorization.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers=BEARER_AUTH_HEADER,
        )

    # 2. Parse Bearer scheme
    parts = authorization.strip().split(maxsplit=1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme; Bearer token required",
            headers=BEARER_AUTH_HEADER,
        )

    raw_token = parts[1].strip()
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty Bearer token",
            headers=BEARER_AUTH_HEADER,
        )

    # 3. Resolve active application settings
    app_settings = settings or getattr(request.app.state, "settings", None) or get_settings()

    # 4. Load configured operator credentials (fails closed if unconfigured or malformed)
    try:
        credentials = load_operator_credentials(app_settings.OPERATOR_CREDENTIALS)
    except AuthenticationConfigurationError as exc:
        logger.error("Authentication rejected: server-side operator credentials misconfigured: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service is improperly configured",
        ) from exc

    # 5. Verify API key against credentials
    principal = authenticate_api_key(raw_token, credentials)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized API key",
            headers=BEARER_AUTH_HEADER,
        )

    return principal


def require_roles(*allowed_roles: Union[OperatorRole, str]) -> Callable[[OperatorPrincipal], OperatorPrincipal]:
    """Dependency factory: Enforce server-side role-based access control.

    Args:
        *allowed_roles: One or more OperatorRole instances or string values permitted to access the endpoint.

    Returns:
        FastAPI dependency function validating that the current principal holds an allowed role.

    Security Invariant:
        An 'admin' role does NOT automatically possess permissions of 'analyst' or 'approver'
        unless explicitly passed in allowed_roles. This guarantees strict least privilege
        and prevents administrative bypass of approval workflows.
    """
    normalized_roles: set[OperatorRole] = set()
    for r in allowed_roles:
        if isinstance(r, OperatorRole):
            normalized_roles.add(r)
        else:
            try:
                normalized_roles.add(OperatorRole(str(r).strip().lower()))
            except ValueError as exc:
                raise ValueError(f"Invalid OperatorRole specification: '{r}'") from exc

    def role_dependency(
        principal: OperatorPrincipal = Depends(get_current_principal),
    ) -> OperatorPrincipal:
        if principal.role not in normalized_roles:
            logger.warning(
                "Access denied for operator '%s': role '%s' not in permitted roles %s",
                principal.operator_id,
                principal.role.value,
                [r.value for r in normalized_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Insufficient operator permissions",
            )
        return principal

    return role_dependency


def validate_proposer_approver_separation(proposer_id: str, approver_id: str) -> None:
    """Validate that the proposer and approver are distinct operator identities.

    Raises:
        HTTPException(403): If the proposer and approver operator IDs match.
    """
    if not proposer_id or not approver_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Proposer and approver identities must be specified",
        )

    if proposer_id.strip() == approver_id.strip():
        logger.warning(
            "Two-person approval violation: operator '%s' attempted to approve their own proposal",
            approver_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Proposer cannot approve their own response proposal (two-person approval required)",
        )
