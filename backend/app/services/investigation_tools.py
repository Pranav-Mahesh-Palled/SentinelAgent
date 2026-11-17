"""Read-Only Investigation Retrieval Tools for SentinelAgent.

Implements the six approved read-only database retrieval functions:
1. get_incident_context
2. get_ssh_events
3. get_detection_results
4. get_prior_evidence
5. search_ssh_events_by_username
6. get_related_incidents_for_ip

Safety and Scoping Guarantees:
- Every query executes in a short-lived SQLAlchemy session enforcing SET TRANSACTION READ ONLY.
- Active investigation context is supplied server-side (model cannot override incident_id, investigation_id, or source_ip).
- Uses the 'limit + 1' pattern for bounded list retrievals, setting truncated=True only when len > limit.
- Fixed 1-hour correlation window anchored to incident.created_at: [created_at - 1h, created_at + 1h].
- Historical incidents strictly precede the active incident's created_at anchor.
- Returns JSON-compatible DTOs/records validated against Task 7B.2 Pydantic output schemas.
- Zero ORM instances escape session boundaries.
- No writes or transaction commits permitted in this module.
"""

from collections.abc import Callable, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
from typing import Any, Generator, Optional, TypeVar
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.db.connection import get_engine
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    DetectionResultRecord,
    DetectionResultsOutput,
    EmptyArgs,
    EvidenceItemRecord,
    GetRelatedIncidentsForIPArgs,
    GetSSHEventsArgs,
    IncidentContextOutput,
    PriorEvidenceOutput,
    RelatedIncidentRecord,
    RelatedIncidentsOutput,
    SSHEventRecord,
    SSHEventsOutput,
    SearchSSHEventsByUsernameArgs,
    UsernameSSHEventsOutput,
)
from app.services.mitre_mapping_engine import EventRetrievalMetadata

logger = logging.getLogger(__name__)


class InvestigationContextError(Exception):
    """Raised when investigation context is missing or invalid."""
    pass


class ActiveInvestigationContext:
    """Immutable server-side context holding identifiers and metadata for the active investigation."""

    def __init__(
        self,
        incident_id: uuid.UUID,
        investigation_id: uuid.UUID,
        source_ip: str,
        created_at: datetime,
        *,
        username: Optional[str] = None,
        incident_type: Optional[str] = None,
        auth_pattern: Optional[str] = None,
        detection_category: Optional[str] = None,
        validated_mitre_mappings: Optional[Sequence[Any]] = None,
    ) -> None:
        self._incident_id = incident_id
        self._investigation_id = investigation_id
        self._source_ip = str(source_ip).strip() if source_ip is not None else None
        self._created_at = created_at
        self._username = str(username).strip() if username is not None else None
        self._incident_type = str(incident_type).strip() if incident_type is not None else None
        self._auth_pattern = str(auth_pattern).strip() if auth_pattern is not None else None
        self._detection_category = str(detection_category).strip() if detection_category is not None else None
        self._validated_mitre_mappings = tuple(validated_mitre_mappings) if validated_mitre_mappings else ()

    @property
    def incident_id(self) -> uuid.UUID:
        return self._incident_id

    @property
    def investigation_id(self) -> uuid.UUID:
        return self._investigation_id

    @property
    def source_ip(self) -> Optional[str]:
        return self._source_ip

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def username(self) -> Optional[str]:
        return self._username

    @property
    def incident_type(self) -> Optional[str]:
        return self._incident_type

    @property
    def auth_pattern(self) -> Optional[str]:
        return self._auth_pattern

    @property
    def detection_category(self) -> Optional[str]:
        return self._detection_category

    @property
    def validated_mitre_mappings(self) -> tuple[Any, ...]:
        return self._validated_mitre_mappings


@contextmanager
def readonly_db_session(
    session_factory: Optional[sessionmaker[Session]] = None,
) -> Generator[Session, None, None]:
    """Context manager yielding a short-lived SQLAlchemy Session in PostgreSQL READ ONLY mode.

    Enforces 'SET TRANSACTION READ ONLY' before any queries are executed.
    Guarantees session rollback and closure.
    """
    if session_factory is None:
        engine = get_engine()
        if engine is None:
            raise InvestigationContextError("Database engine is not initialized.")
        session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    session = session_factory()
    try:
        session.execute(text("SET TRANSACTION READ ONLY"))
        yield session
    finally:
        session.rollback()
        session.close()


# =============================================================================
# Tool 1: get_incident_context
# =============================================================================

def get_incident_context(
    context: ActiveInvestigationContext,
    args: Optional[EmptyArgs] = None,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> IncidentContextOutput:
    """Retrieve metadata, status, and telemetry counts for the active incident.

    Args:
        context: Active server-side investigation context.
        args: Optional EmptyArgs (model can pass no parameters).
        session_factory: Optional sessionmaker for dependency injection in tests.

    Returns:
        IncidentContextOutput validated schema.
    """
    with readonly_db_session(session_factory) as session:
        incident = session.execute(
            select(Incident).where(Incident.incident_id == context.incident_id)
        ).scalar_one_or_none()

        if incident is None:
            raise InvestigationContextError(
                f"Active incident {context.incident_id} not found in database."
            )

        # Count associated SSH events
        event_count = session.execute(
            select(func.count()).select_from(IncidentEvent).where(
                IncidentEvent.incident_id == context.incident_id
            )
        ).scalar_one()

        # Count associated detection results
        detection_count = session.execute(
            select(func.count()).select_from(DetectionResult).where(
                DetectionResult.incident_id == context.incident_id
            )
        ).scalar_one()

        return IncidentContextOutput(
            incident_id=incident.incident_id,
            title=incident.title,
            incident_type=incident.incident_type,
            source_ip=str(incident.source_ip),
            severity=incident.severity,
            detection_method=incident.detection_method,
            status=incident.status,
            investigation_status=incident.investigation_status,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            associated_event_count=event_count,
            associated_detection_count=detection_count,
        )


# =============================================================================
# Tool 2: get_ssh_events
# =============================================================================

def get_ssh_events(
    context: ActiveInvestigationContext,
    args: Optional[GetSSHEventsArgs] = None,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> SSHEventsOutput:
    """Retrieve SSH events linked to the active incident via incident_events.

    Ordering: event_timestamp ASC, event_id ASC.
    Bounded by limit + 1.
    """
    effective_args = args or GetSSHEventsArgs()
    limit = effective_args.limit

    with readonly_db_session(session_factory) as session:
        query = (
            select(SSHEvent)
            .join(IncidentEvent, IncidentEvent.event_id == SSHEvent.event_id)
            .where(IncidentEvent.incident_id == context.incident_id)
            .order_by(SSHEvent.event_timestamp.asc(), SSHEvent.event_id.asc())
            .limit(limit + 1)
        )
        rows = session.execute(query).scalars().all()

        truncated = len(rows) > limit
        selected_rows = rows[:limit]

        records = [
            SSHEventRecord(
                event_id=r.event_id,
                event_timestamp=r.event_timestamp,
                source_ip=str(r.source_ip),
                username=r.username,
                authentication_result=r.authentication_result,
                event_type=r.event_type,
                ingested_at=r.ingested_at,
            )
            for r in selected_rows
        ]

        return SSHEventsOutput(
            events=records,
            count=len(records),
            truncated=truncated,
        )


# =============================================================================
# Tool 3: get_detection_results
# =============================================================================

def get_detection_results(
    context: ActiveInvestigationContext,
    args: Optional[EmptyArgs] = None,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> DetectionResultsOutput:
    """Retrieve detection results associated with the active incident.

    Ordering: evaluated_at ASC, result_id ASC.
    Bounded by limit 50 (+ 1).
    """
    limit = 50

    with readonly_db_session(session_factory) as session:
        query = (
            select(DetectionResult)
            .where(DetectionResult.incident_id == context.incident_id)
            .order_by(DetectionResult.window_start.asc(), DetectionResult.result_id.asc())
            .limit(limit + 1)
        )
        rows = session.execute(query).scalars().all()

        truncated = len(rows) > limit
        selected_rows = rows[:limit]

        records = [
            DetectionResultRecord(
                result_id=r.result_id,
                incident_id=r.incident_id,
                source_ip=str(r.source_ip),
                window_start=r.window_start,
                window_end=r.window_end,
                detector_type=r.detector_type,
                is_suspicious=r.is_suspicious,
                triggered_rules=r.triggered_rules or [],
                feature_snapshot=r.feature_snapshot or {},
                normality_score=r.normality_score,
                calibrated_threshold=r.calibrated_threshold,
                model_version=r.model_version,
                evaluated_at=r.evaluated_at,
            )
            for r in selected_rows
        ]

        return DetectionResultsOutput(
            results=records,
            count=len(records),
            truncated=truncated,
        )


# =============================================================================
# Tool 4: get_prior_evidence
# =============================================================================

def get_prior_evidence(
    context: ActiveInvestigationContext,
    args: Optional[EmptyArgs] = None,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> PriorEvidenceOutput:
    """Retrieve previously recorded evidence for the active investigation.

    Ordering: collected_at ASC, evidence_id ASC.
    Bounded by limit 50 (+ 1).
    """
    limit = 50

    with readonly_db_session(session_factory) as session:
        query = (
            select(EvidenceItem)
            .where(EvidenceItem.investigation_id == context.investigation_id)
            .order_by(EvidenceItem.collected_at.asc(), EvidenceItem.evidence_id.asc())
            .limit(limit + 1)
        )
        rows = session.execute(query).scalars().all()

        truncated = len(rows) > limit
        selected_rows = rows[:limit]

        records = [
            EvidenceItemRecord(
                evidence_id=r.evidence_id,
                investigation_id=r.investigation_id,
                event_id=r.event_id,
                evidence_type=r.evidence_type,
                title=r.title,
                description=r.description,
                evidence_data=r.evidence_data,
                source_reference=r.source_reference,
                collected_at=r.collected_at,
            )
            for r in selected_rows
        ]

        return PriorEvidenceOutput(
            evidence_items=records,
            count=len(records),
            truncated=truncated,
        )


# =============================================================================
# Tool 5: search_ssh_events_by_username
# =============================================================================

def search_ssh_events_by_username(
    context: ActiveInvestigationContext,
    args: SearchSSHEventsByUsernameArgs,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> UsernameSSHEventsOutput:
    """Search SSH authentication events for the active incident's source IP and given username.

    Scoped strictly to:
    - source_ip from active context
    - Fixed 1-hour correlation window: [created_at - 1h, created_at + 1h]
    - username from validated args
    - Ordering: event_timestamp ASC, event_id ASC
    - Bounded by limit + 1
    """
    limit = args.limit
    window_start = context.created_at - timedelta(hours=1)
    window_end = context.created_at + timedelta(hours=1)

    with readonly_db_session(session_factory) as session:
        query = (
            select(SSHEvent)
            .where(
                SSHEvent.source_ip == context.source_ip,
                SSHEvent.username == args.username,
                SSHEvent.event_timestamp >= window_start,
                SSHEvent.event_timestamp <= window_end,
            )
            .order_by(SSHEvent.event_timestamp.asc(), SSHEvent.event_id.asc())
            .limit(limit + 1)
        )
        rows = session.execute(query).scalars().all()

        truncated = len(rows) > limit
        selected_rows = rows[:limit]

        records = [
            SSHEventRecord(
                event_id=r.event_id,
                event_timestamp=r.event_timestamp,
                source_ip=str(r.source_ip),
                username=r.username,
                authentication_result=r.authentication_result,
                event_type=r.event_type,
                ingested_at=r.ingested_at,
            )
            for r in selected_rows
        ]

        return UsernameSSHEventsOutput(
            events=records,
            count=len(records),
            truncated=truncated,
        )


# =============================================================================
# Tool 6: get_related_incidents_for_ip
# =============================================================================

def get_related_incidents_for_ip(
    context: ActiveInvestigationContext,
    args: Optional[GetRelatedIncidentsForIPArgs] = None,
    session_factory: Optional[sessionmaker[Session]] = None,
) -> RelatedIncidentsOutput:
    """Retrieve historical incidents associated with the active incident's source IP.

    Scoped strictly to:
    - Same source IP
    - Excludes the current incident (incident_id != context.incident_id)
    - Strictly historical: created_at < context.created_at
    - Ordering: created_at DESC, incident_id ASC
    - Bounded by limit + 1
    """
    effective_args = args or GetRelatedIncidentsForIPArgs()
    limit = effective_args.limit

    with readonly_db_session(session_factory) as session:
        query = (
            select(Incident)
            .where(
                Incident.source_ip == context.source_ip,
                Incident.incident_id != context.incident_id,
                Incident.created_at < context.created_at,
            )
            .order_by(Incident.created_at.desc(), Incident.incident_id.asc())
            .limit(limit + 1)
        )
        rows = session.execute(query).scalars().all()

        truncated = len(rows) > limit
        selected_rows = rows[:limit]

        records = [
            RelatedIncidentRecord(
                incident_id=r.incident_id,
                title=r.title,
                incident_type=r.incident_type,
                status=r.status,
                investigation_status=r.investigation_status,
                created_at=r.created_at,
            )
            for r in selected_rows
        ]

        return RelatedIncidentsOutput(
            incidents=records,
            count=len(records),
            truncated=truncated,
        )


# =============================================================================
# Server-Authoritative Supplemental SSH Telemetry Retrieval (Task 8E.3)
# =============================================================================

INTERNAL_RETRIEVAL_PRE_HOURS: int = 2
INTERNAL_RETRIEVAL_POST_HOURS: int = 1
INTERNAL_RETRIEVAL_LIMIT: int = 1000
INTERNAL_RETRIEVAL_TOOL_NAME: str = "internal_mitre_ssh_retrieval"


def retrieve_incident_ssh_telemetry(
    context: ActiveInvestigationContext,
    session_factory: Optional[sessionmaker[Session]] = None,
    provenance_set: Optional[Any] = None,
    investigation_service: Optional[Any] = None,
) -> tuple[tuple[SSHEventRecord, ...], EventRetrievalMetadata]:
    """Server-authoritative supplemental SSH telemetry retrieval for deterministic MITRE evaluation.

    Safety & Scoping Guarantees:
    - Strictly scoped to the active investigation and its parent incident's authoritative source IP.
    - Bound to fixed interval: [incident.created_at - 2h, incident.created_at + 1h] in UTC.
    - Deterministic ordering: event_timestamp ASC, event_id ASC.
    - Limit-plus-one query capped at 1000 selected records (fetches up to 1001).
    - If truncated (> 1000), sets truncated=True and coverage_complete=False.
    - If complete (<= 1000), sets truncated=False and coverage_complete=True.
    - Read-only execution via PostgreSQL SET TRANSACTION READ ONLY.
    - Zero ORM instances escape; records returned as immutable SSHEventRecord DTO tuple.
    - Directly registers returned event UUIDs in the authorized provenance set (if supplied).
    - Audited via InvestigationService in investigation_tool_runs under 'internal_mitre_ssh_retrieval'.

    Args:
        context: Active server-side investigation context.
        session_factory: Optional sessionmaker for dependency injection in tests.
        provenance_set: Optional AuthorizedProvenanceSet to register retrieved event UUIDs.
        investigation_service: Optional InvestigationService to record audit tool run entries.

    Returns:
        Tuple of (tuple of SSHEventRecord DTOs, EventRetrievalMetadata).

    Raises:
        InvestigationContextError: If context, source_ip, or created_at is missing/malformed.
        InvestigationTerminatedError: If parent investigation is terminated (via investigation_service).
        Exception: If database query or transaction fails.
    """
    if context is None:
        raise InvestigationContextError("Active investigation context is required.")

    if not hasattr(context, "source_ip") or context.source_ip is None:
        raise InvestigationContextError("Active investigation context is missing source IP.")

    raw_ip = str(context.source_ip).strip()
    if not raw_ip or raw_ip.lower() in ("none", "null"):
        raise InvestigationContextError("Active investigation context is missing source IP.")

    try:
        clean_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise InvestigationContextError(
            f"Active investigation context contains invalid source IP '{raw_ip}': {exc}"
        ) from exc

    if not hasattr(context, "created_at") or context.created_at is None:
        raise InvestigationContextError("Active investigation context is missing created_at timestamp.")

    if not isinstance(context.created_at, datetime):
        raise InvestigationContextError("Active investigation context created_at must be a datetime instance.")

    if context.created_at.tzinfo is None or context.created_at.tzinfo.utcoffset(context.created_at) is None:
        raise InvestigationContextError(
            "Active investigation context created_at timestamp must be timezone-aware."
        )

    # 1. Compute authoritative UTC query boundaries
    created_at_utc = context.created_at.astimezone(timezone.utc)
    window_start = created_at_utc - timedelta(hours=INTERNAL_RETRIEVAL_PRE_HOURS)
    window_end = created_at_utc + timedelta(hours=INTERNAL_RETRIEVAL_POST_HOURS)

    # 2. Audit Trail: Start Record
    tool_run_id = None
    if investigation_service is not None:
        tool_run_id = investigation_service.record_tool_run_start(
            investigation_id=context.investigation_id,
            tool_name=INTERNAL_RETRIEVAL_TOOL_NAME,
            input_summary={
                "incident_id": str(context.incident_id),
                "source_ip": clean_ip,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "limit": INTERNAL_RETRIEVAL_LIMIT,
            },
        )

    # 3. Read-Only Query Execution
    try:
        with readonly_db_session(session_factory) as session:
            query = (
                select(SSHEvent)
                .where(
                    SSHEvent.source_ip == clean_ip,
                    SSHEvent.event_timestamp >= window_start,
                    SSHEvent.event_timestamp <= window_end,
                )
                .order_by(SSHEvent.event_timestamp.asc(), SSHEvent.event_id.asc())
                .limit(INTERNAL_RETRIEVAL_LIMIT + 1)
            )
            rows = session.execute(query).scalars().all()

            truncated = len(rows) > INTERNAL_RETRIEVAL_LIMIT
            selected_rows = rows[:INTERNAL_RETRIEVAL_LIMIT]
            coverage_complete = not truncated

            # Convert ORM instances to immutable Pydantic DTOs with UTC timestamps inside active session
            records = tuple(
                SSHEventRecord(
                    event_id=r.event_id,
                    event_timestamp=(
                        r.event_timestamp
                        if (r.event_timestamp.tzinfo and r.event_timestamp.tzinfo.utcoffset(r.event_timestamp) is not None)
                        else r.event_timestamp.replace(tzinfo=timezone.utc)
                    ),
                    source_ip=str(r.source_ip),
                    username=r.username,
                    authentication_result=r.authentication_result,
                    event_type=r.event_type,
                    ingested_at=(
                        r.ingested_at
                        if (r.ingested_at.tzinfo and r.ingested_at.tzinfo.utcoffset(r.ingested_at) is not None)
                        else r.ingested_at.replace(tzinfo=timezone.utc)
                    ),
                )
                for r in selected_rows
            )

        # 4. Provenance Registration
        if provenance_set is not None and hasattr(provenance_set, "add_ssh_event"):
            for rec in records:
                provenance_set.add_ssh_event(rec.event_id)

        metadata = EventRetrievalMetadata(
            truncated=truncated,
            window_start=window_start,
            window_end=window_end,
            coverage_complete=coverage_complete,
            incident_id=context.incident_id,
            source_ip=clean_ip,
        )

        # 5. Audit Trail: Success Record
        if investigation_service is not None and tool_run_id is not None:
            investigation_service.record_tool_run_success(
                tool_run_id=tool_run_id,
                output_summary={
                    "event_count": len(records),
                    "truncated": truncated,
                    "coverage_complete": coverage_complete,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                },
            )

        logger.info(
            "Internal MITRE SSH telemetry retrieval completed: investigation=%s, events=%d, truncated=%s, window=[%s, %s]",
            context.investigation_id,
            len(records),
            truncated,
            window_start.isoformat(),
            window_end.isoformat(),
        )

        return records, metadata

    except Exception as exc:
        if investigation_service is not None and tool_run_id is not None:
            try:
                investigation_service.record_tool_run_failure(
                    tool_run_id=tool_run_id,
                    error_code="RETRIEVAL_ERROR",
                    output_summary={
                        "error": type(exc).__name__,
                        "detail": str(exc)[:255],
                        "window_start": window_start.isoformat(),
                        "window_end": window_end.isoformat(),
                    },
                )
            except Exception as audit_exc:
                logger.warning("Failed to record tool run failure for %s: %s", tool_run_id, audit_exc)
        raise

