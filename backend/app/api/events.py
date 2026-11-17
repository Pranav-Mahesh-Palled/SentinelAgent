"""SSH Authentication Event Ingestion Endpoints.

Provides endpoints for ingesting single and batch SSH authentication events into PostgreSQL.
Enforces strict schema validation, atomicity, and conflict handling.
"""

import logging
from typing import Union
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.models.ssh_event import SSHEvent
from app.schemas.ssh_event import (
    SSHEventBatchCreate,
    SSHEventBatchResponse,
    SSHEventCreate,
    SSHEventIngestResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/events/ssh", tags=["events"])

MAX_BATCH_SIZE = 500
PG_SQLSTATE_UNIQUE_VIOLATION = "23505"


def _is_unique_violation(exc: IntegrityError) -> bool:
    """Check if the underlying exception is a PostgreSQL unique constraint violation (SQLSTATE 23505)."""
    orig = getattr(exc, "orig", None)
    sqlstate = getattr(orig, "sqlstate", None)
    return sqlstate == PG_SQLSTATE_UNIQUE_VIOLATION


@router.post(
    "",
    response_model=SSHEventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Single SSH Authentication Event",
    description="Validate and ingest a single SSH authentication event into PostgreSQL.",
    responses={
        201: {"description": "Event ingested successfully"},
        409: {"description": "Event with this ID already exists"},
        422: {"description": "Validation error in request payload"},
        503: {"description": "Database service is unavailable"},
    },
)
def ingest_single_event(
    event_in: SSHEventCreate,
    db: Session = Depends(get_db_session),
) -> SSHEventIngestResponse:
    """Ingest a single validated SSH event into PostgreSQL."""
    # Pre-check for duplicate primary key
    existing = db.get(SSHEvent, event_in.event_id)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with ID '{event_in.event_id}' already exists.",
        )

    db_event = SSHEvent(
        event_id=event_in.event_id,
        event_timestamp=event_in.event_timestamp,
        source_ip=str(event_in.source_ip),
        username=event_in.username,
        authentication_result=event_in.authentication_result,
        event_type=event_in.event_type,
    )

    db.add(db_event)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if _is_unique_violation(exc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Event with ID '{event_in.event_id}' already exists.",
            )
        orig = getattr(exc, "orig", None)
        logger.error(
            "Single event ingestion integrity error: %s (sqlstate=%s)",
            type(orig).__name__ if orig else type(exc).__name__,
            getattr(orig, "sqlstate", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist event due to an internal database error.",
        )
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Single event ingestion failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist event due to an internal database error.",
        )

    return SSHEventIngestResponse(
        event_id=db_event.event_id,
        status="created",
        message="Event ingested successfully",
    )


@router.post(
    "/batch",
    response_model=SSHEventBatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Batch SSH Authentication Events",
    description="Validate and ingest a batch of up to 500 SSH events atomically into PostgreSQL.",
    responses={
        201: {"description": "Batch ingested successfully"},
        409: {"description": "One or more event IDs already exist in the database"},
        422: {"description": "Validation error, empty batch, duplicate IDs in batch, or exceeds 500 limit"},
        503: {"description": "Database service is unavailable"},
    },
)
def ingest_batch_events(
    payload: Union[list[SSHEventCreate], SSHEventBatchCreate] = Body(...),
    db: Session = Depends(get_db_session),
) -> SSHEventBatchResponse:
    """Ingest a batch of SSH events in a single atomic transaction."""
    events = payload.events if isinstance(payload, SSHEventBatchCreate) else payload

    # Validate batch boundaries
    if len(events) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Batch cannot be empty.",
        )
    if len(events) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Batch size exceeds maximum limit of {MAX_BATCH_SIZE} events (received {len(events)}).",
        )

    # Validate uniqueness of event_id within the submitted batch
    seen_ids: set[uuid.UUID] = set()
    for ev in events:
        if ev.event_id in seen_ids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Duplicate event_id '{ev.event_id}' detected within the submitted batch.",
            )
        seen_ids.add(ev.event_id)

    # Pre-check database for any conflicting event IDs
    existing_ids = db.execute(
        select(SSHEvent.event_id).where(SSHEvent.event_id.in_(list(seen_ids)))
    ).scalars().all()

    if existing_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with ID '{existing_ids[0]}' already exists in the database.",
        )

    db_events = [
        SSHEvent(
            event_id=ev.event_id,
            event_timestamp=ev.event_timestamp,
            source_ip=str(ev.source_ip),
            username=ev.username,
            authentication_result=ev.authentication_result,
            event_type=ev.event_type,
        )
        for ev in events
    ]

    db.add_all(db_events)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if _is_unique_violation(exc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="One or more event identifiers already exist in the database.",
            )
        orig = getattr(exc, "orig", None)
        logger.error(
            "Batch event ingestion integrity error: %s (sqlstate=%s)",
            type(orig).__name__ if orig else type(exc).__name__,
            getattr(orig, "sqlstate", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist batch due to an internal database error.",
        )
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Batch event ingestion failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist batch due to an internal database error.",
        )

    return SSHEventBatchResponse(
        accepted_count=len(db_events),
        event_ids=[ev.event_id for ev in db_events],
        status="created",
        message="Batch ingested successfully",
    )
