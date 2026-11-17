"""API router and dependency package for SentinelAgent."""

from app.api.deps import (
    get_current_principal,
    require_roles,
    validate_proposer_approver_separation,
)
from app.api.events import router as events_router
from app.api.health import router as health_router

__all__ = [
    "events_router",
    "get_current_principal",
    "health_router",
    "require_roles",
    "validate_proposer_approver_separation",
]

