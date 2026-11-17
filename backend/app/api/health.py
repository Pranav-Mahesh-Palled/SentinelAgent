"""Health and readiness endpoints for SentinelAgent API."""

from typing import Optional
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.core.config import get_settings
from app.db.connection import check_db_connectivity

router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    """Response schema for application liveness check."""

    status: str


class ReadinessResponse(BaseModel):
    """Response schema for application, database, MITRE, and Hindsight readiness check."""

    status: str
    database: str
    mitre_catalogue: str
    mitre_required: bool
    hindsight: str
    hindsight_required: bool
    detail: Optional[str] = None


@router.get(
    "/live",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Liveness Check",
    description="Checks whether the FastAPI application process is running and responding.",
)
def get_liveness() -> dict:
    """Return alive status indicating application process is operational."""
    return {"status": "alive"}


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    summary="Application & Dependency Readiness Check",
    description=(
        "Verifies that the application can reach and query the primary PostgreSQL database "
        "and verifies MITRE ATT&CK catalogue readiness. "
        "Returns 200 when ready, or 503 if required dependencies are unavailable."
    ),
    responses={
        200: {
            "description": "Dependencies are ready to accept traffic.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "ready",
                        "database": "connected",
                        "mitre_catalogue": "loaded",
                        "mitre_required": False,
                    }
                }
            },
        },
        503: {
            "description": "Readiness check failed for database or required dependencies.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "unavailable",
                        "database": "disconnected",
                        "mitre_catalogue": "unavailable",
                        "mitre_required": False,
                        "detail": "Database service is unavailable",
                    }
                }
            },
        },
    },
)
async def get_readiness(request: Request):
    """Verify primary database connectivity, MITRE catalogue, and Hindsight availability."""
    catalogue = getattr(request.app.state, "mitre_catalogue", None)
    mitre_status = "loaded" if catalogue is not None else "unavailable"
    app_settings = get_settings()
    mitre_required = bool(app_settings.MITRE_REQUIRED)

    # 1. Primary database connectivity check
    is_connected, _ = check_db_connectivity()
    mitre_ready = (not mitre_required) or (mitre_status == "loaded")

    # 2. Hindsight persistent incident memory readiness check
    hindsight_client = getattr(request.app.state, "hindsight_client", None)
    hindsight_enabled = bool(app_settings.HINDSIGHT_ENABLED)
    hindsight_required = bool(app_settings.HINDSIGHT_REQUIRED)

    if not hindsight_enabled:
        hindsight_status = "disabled"
        hindsight_ready = True
    else:
        if hindsight_client is not None:
            is_hindsight_healthy, _ = await hindsight_client.check_health()
            hindsight_status = "available" if is_hindsight_healthy else "unavailable"
        else:
            hindsight_status = "unavailable"
        hindsight_ready = (not hindsight_required) or (hindsight_status == "available")

    if is_connected and mitre_ready and hindsight_ready:
        return {
            "status": "ready",
            "database": "connected",
            "mitre_catalogue": mitre_status,
            "mitre_required": mitre_required,
            "hindsight": hindsight_status,
            "hindsight_required": hindsight_required,
        }

    detail_parts = []
    if not is_connected:
        detail_parts.append("Database service is unavailable")
    if not mitre_ready:
        detail_parts.append("Required MITRE catalogue is unavailable")
    if not hindsight_ready:
        detail_parts.append("Required Hindsight service is unavailable")

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "unavailable",
            "database": "connected" if is_connected else "disconnected",
            "mitre_catalogue": mitre_status,
            "mitre_required": mitre_required,
            "hindsight": hindsight_status,
            "hindsight_required": hindsight_required,
            "detail": "; ".join(detail_parts) if detail_parts else None,
        },
    )
