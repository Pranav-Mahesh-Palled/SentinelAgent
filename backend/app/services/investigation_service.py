"""Investigation Service and Lifecycle Management for SentinelAgent.

Implements Task 7B.4 service layer (Audited and Hardened):
- Strict lock-ordering hierarchy: Parent Incident -> Investigation -> ToolRun
- Parent-first batch recovery with FOR UPDATE SKIP LOCKED preventing lock inversions
- Fail-closed provenance validation:
    * Missing or empty provenance_set rejects confirmed findings with evidence references
    * Insufficient-evidence reports with empty findings cleanly accepted
    * Full database existence and incident relevance verification
- Transactional parent investigation state validation on every tool-run write and evidence insertion
- Automatic recovery of abandoned running tool runs when parent investigation fails
- Reliable parent incident synchronization (prevents older failed jobs from clobbering newer active ones)
- Short-lived database transactions returning immutable DTOs
"""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Optional, Set
import uuid

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.connection import get_engine
from app.db.session import get_session_factory
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem, VALID_EVIDENCE_TYPES
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    EvidenceItemDTO,
    InvestigationDTO,
    InvestigationReport,
    SSHEventRecord,
    ToolRunDTO,
    validate_canonical_source_reference,
)
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreCandidateProposal,
)
from app.services.hmac_pseudonymizer import get_pseudonymizer_from_settings
from app.services.incident_memory_serializer import IncidentMemorySerializer
from app.services.investigation_tools import ActiveInvestigationContext
from app.services.memory_outbox_service import MemoryOutboxService
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import EventRetrievalMetadata
from app.services.mitre_mapping_validator import (
    MitreMappingValidationError,
    MitreMappingValidator,
)

logger = logging.getLogger(__name__)

# Constants
MAX_TOOL_NAME_LEN = 100
MAX_JSON_SUMMARY_BYTES = 64 * 1024  # 64 KB
MAX_ERROR_CODE_LEN = 64
RECOVERY_BATCH_LIMIT = 50


# =============================================================================
# Custom Service Exceptions
# =============================================================================

class InvestigationServiceError(Exception):
    """Base exception for investigation service operations."""
    pass


class IncidentNotFoundError(InvestigationServiceError):
    """Raised when the specified incident does not exist."""
    pass


class InvestigationNotFoundError(InvestigationServiceError):
    """Raised when the specified investigation does not exist."""
    pass


class InvestigationConflictError(InvestigationServiceError):
    """Raised when an investigation cannot be created or started due to state conflicts."""
    pass


class InvestigationTerminatedError(InvestigationServiceError):
    """Raised when a worker attempts an operation on an investigation that was completed, failed, or recovered."""
    pass


class ProvenanceValidationError(InvestigationServiceError):
    """Raised when evidence or report findings cannot be verified against authorized telemetry."""
    pass


class ToolRunLifecycleError(InvestigationServiceError):
    """Raised when a tool-run transition is invalid."""
    pass


class MissingMemoryPayloadError(InvestigationServiceError):
    """Raised when Hindsight is enabled and complete_investigation is called without serialized_memory_payload."""
    pass


# =============================================================================
# Helper: Sanitization and Bounding
# =============================================================================

def _sanitize_and_bound_json(data: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Sanitize and bound JSON summaries to MAX_JSON_SUMMARY_BYTES (64 KB)."""
    if data is None:
        return None

    try:
        serialized = json.dumps(data, default=str)
    except Exception:
        return {"error": "unserializable_summary"}

    if len(serialized.encode("utf-8")) > MAX_JSON_SUMMARY_BYTES:
        return {
            "truncated": True,
            "original_length": len(serialized),
            "preview": serialized[:1024],
        }

    return json.loads(serialized)


# =============================================================================
# AuthorizedProvenanceSet
# =============================================================================

class AuthorizedProvenanceSet:
    """Typed registry of source record UUIDs and identifiers authorized via read-only tools.

    Tracks identifiers by exact source type:
    - ssh_events: SSH event UUIDs returned by get_ssh_events or search_ssh_events_by_username
    - detection_results: Detection result UUIDs returned by get_detection_results
    - historical_incidents: Incident UUIDs returned by get_related_incidents_for_ip
    - evidence_items: Previously collected EvidenceItem UUIDs returned by get_prior_evidence
    """

    def __init__(self) -> None:
        self.ssh_events: Set[uuid.UUID] = set()
        self.detection_results: Set[uuid.UUID] = set()
        self.historical_incidents: Set[uuid.UUID] = set()
        self.evidence_items: Set[uuid.UUID] = set()
        self.mitre_techniques: Set[str] = set()
        self.security_playbooks: Set[str] = set()

    def add_ssh_event(self, event_id: uuid.UUID) -> None:
        self.ssh_events.add(event_id)

    def add_detection_result(self, result_id: uuid.UUID) -> None:
        self.detection_results.add(result_id)

    def add_historical_incident(self, incident_id: uuid.UUID) -> None:
        self.historical_incidents.add(incident_id)

    def add_evidence_item(self, evidence_id: uuid.UUID) -> None:
        self.evidence_items.add(evidence_id)

    def add_mitre_technique(self, technique_id: str) -> None:
        self.mitre_techniques.add(technique_id.strip())

    def add_security_playbook(self, playbook_id: str) -> None:
        self.security_playbooks.add(playbook_id.strip())

    def register_tool_output(self, tool_output: Any) -> None:
        """Register identifiers directly from typed tool outputs returned by read-only tools."""
        if hasattr(tool_output, "events"):
            for ev in getattr(tool_output, "events", []):
                ev_id = getattr(ev, "event_id", None)
                if isinstance(ev_id, uuid.UUID):
                    self.add_ssh_event(ev_id)
        if hasattr(tool_output, "detection_results"):
            for dr in getattr(tool_output, "detection_results", []):
                dr_id = getattr(dr, "result_id", None)
                if isinstance(dr_id, uuid.UUID):
                    self.add_detection_result(dr_id)
        if hasattr(tool_output, "results"):
            for dr in getattr(tool_output, "results", []):
                dr_id = getattr(dr, "result_id", None)
                if isinstance(dr_id, uuid.UUID):
                    self.add_detection_result(dr_id)
        if hasattr(tool_output, "incidents"):
            for inc in getattr(tool_output, "incidents", []):
                inc_id = getattr(inc, "incident_id", None)
                if isinstance(inc_id, uuid.UUID):
                    self.add_historical_incident(inc_id)
        if hasattr(tool_output, "evidence_items"):
            for item in getattr(tool_output, "evidence_items", []):
                ev_id = getattr(item, "evidence_id", None)
                if isinstance(ev_id, uuid.UUID):
                    self.add_evidence_item(ev_id)

    def validate_reference(self, canonical_ref: str) -> tuple[str, Any]:
        """Validate format and ensure reference exists in the corresponding source category.

        Raises ProvenanceValidationError on any inconsistency or omission.
        """
        try:
            trimmed = validate_canonical_source_reference(canonical_ref)
        except ValueError as err:
            raise ProvenanceValidationError(f"Malformed source reference '{canonical_ref}': {err}") from err

        prefix, ident = trimmed.split("/", 1)
        if prefix == "ssh_events":
            uid = uuid.UUID(ident)
            if uid not in self.ssh_events:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (ssh_events) '{canonical_ref}' not found in provenance set."
                )
            return prefix, uid
        elif prefix == "detection_results":
            uid = uuid.UUID(ident)
            if uid not in self.detection_results:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (detection_results) '{canonical_ref}' not found in provenance set."
                )
            return prefix, uid
        elif prefix == "incidents":
            uid = uuid.UUID(ident)
            if uid not in self.historical_incidents:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (incidents) '{canonical_ref}' not found in provenance set."
                )
            return prefix, uid
        elif prefix == "evidence_items":
            uid = uuid.UUID(ident)
            if uid not in self.evidence_items:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (evidence_items) '{canonical_ref}' not found in provenance set."
                )
            return prefix, uid
        elif prefix == "mitre":
            if ident not in self.mitre_techniques:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (mitre) '{canonical_ref}'."
                )
            return prefix, ident
        elif prefix == "playbooks":
            if ident not in self.security_playbooks:
                raise ProvenanceValidationError(
                    f"Report contains unauthorized evidence reference (playbooks) '{canonical_ref}'."
                )
            return prefix, ident
        else:
            raise ProvenanceValidationError(f"Unsupported source reference category '{prefix}'.")

    def contains_reference(self, canonical_ref: str) -> bool:
        """Verify whether a canonical reference string exists in this authorized set."""
        try:
            self.validate_reference(canonical_ref)
            return True
        except (ProvenanceValidationError, ValueError):
            return False


# =============================================================================
# InvestigationService
# =============================================================================

class InvestigationService:
    """Service managing investigation lifecycles, tool runs, evidence, and recovery."""

    def __init__(self, session_factory: Optional[sessionmaker[Session]] = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def _get_session(self) -> Session:
        return self._session_factory()

    def get_investigation(self, investigation_id: uuid.UUID) -> InvestigationDTO:
        """Retrieve an immutable snapshot of an investigation.

        Raises:
            InvestigationNotFoundError: If investigation does not exist.
        """
        with self._get_session() as session:
            inv = session.execute(
                select(Investigation)
                .where(Investigation.investigation_id == investigation_id)
            ).scalar_one_or_none()

            if inv is None:
                raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

            return InvestigationDTO.model_validate(inv)

    def get_active_investigation_context(
        self,
        investigation_id: uuid.UUID,
    ) -> ActiveInvestigationContext:
        """Retrieve and validate the active investigation and parent incident context.

        Verifies:
        1. Investigation exists.
        2. Investigation is in_progress.
        3. Parent incident exists.

        Returns:
            Server-side ActiveInvestigationContext.

        Raises:
            InvestigationNotFoundError: If investigation does not exist.
            InvestigationTerminatedError: If investigation is not in_progress.
            IncidentNotFoundError: If parent incident does not exist.
        """
        with self._get_session() as session:
            row = session.execute(
                select(
                    Investigation.status,
                    Incident.incident_id,
                    Incident.source_ip,
                    Incident.created_at,
                    Incident.incident_type,
                )
                .join(Incident, Incident.incident_id == Investigation.incident_id)
                .where(Investigation.investigation_id == investigation_id)
            ).first()

            if row is None:
                # Disambiguate missing investigation from missing incident
                inv_exists = session.execute(
                    select(Investigation.investigation_id)
                    .where(Investigation.investigation_id == investigation_id)
                ).scalar_one_or_none()
                if inv_exists is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")
                raise IncidentNotFoundError(f"Parent incident for investigation {investigation_id} not found.")

            status, incident_id, source_ip, created_at, incident_type = row
            if status != "in_progress":
                raise InvestigationTerminatedError(
                    f"Investigation {investigation_id} is not in_progress (current status: '{status}')."
                )

            # Query primary targeted username strictly from authorized current-incident PostgreSQL telemetry
            primary_username = session.execute(
                select(SSHEvent.username)
                .join(IncidentEvent, IncidentEvent.event_id == SSHEvent.event_id)
                .where(IncidentEvent.incident_id == incident_id)
                .group_by(SSHEvent.username)
                .order_by(func.count(SSHEvent.event_id).desc(), SSHEvent.username.asc())
                .limit(1)
            ).scalar_one_or_none()

            # Query authoritative validated MITRE mappings strictly from persisted EvidenceItems
            # Using authoritative storage contract: evidence_type == 'mitre_technique'
            mitre_evidence_rows = session.execute(
                select(EvidenceItem.evidence_data)
                .where(
                    EvidenceItem.investigation_id == investigation_id,
                    EvidenceItem.evidence_type == "mitre_technique",
                )
                .order_by(EvidenceItem.collected_at.asc())
            ).scalars().all()

            persisted_validated_mappings: list[MitreAttackMapping] = []
            for ev_data in mitre_evidence_rows:
                if isinstance(ev_data, dict):
                    try:
                        mapping = MitreAttackMapping.model_validate(ev_data)
                        persisted_validated_mappings.append(mapping)
                    except Exception:
                        # Corrupted or malformed mapping data results in omission, not speculative replacement
                        continue

            return ActiveInvestigationContext(
                incident_id=incident_id,
                investigation_id=investigation_id,
                source_ip=str(source_ip),
                created_at=created_at,
                username=str(primary_username) if primary_username else None,
                incident_type=str(incident_type) if incident_type else None,
                validated_mitre_mappings=tuple(persisted_validated_mappings),
            )

    # -------------------------------------------------------------------------
    # 1. Investigation Creation
    # -------------------------------------------------------------------------

    def create_investigation(self, incident_id: uuid.UUID) -> uuid.UUID:
        """Create a pending investigation for the specified incident.

        Locks the parent incident row using SELECT FOR UPDATE to prevent race conditions.
        Rejects creation if a pending or in_progress investigation already exists.

        Returns:
            UUID of the newly created Investigation.
        """
        with self._get_session() as session:
            try:
                # 1. Lock parent incident (Hierarchy: Parent Incident First)
                incident = session.execute(
                    select(Incident)
                    .where(Incident.incident_id == incident_id)
                    .with_for_update()
                ).scalar_one_or_none()

                if incident is None:
                    raise IncidentNotFoundError(f"Incident {incident_id} not found.")

                # 2. Check for active or queued investigations
                existing_active = session.execute(
                    select(Investigation.investigation_id)
                    .where(
                        Investigation.incident_id == incident_id,
                        Investigation.status.in_(["pending", "in_progress"]),
                    )
                ).first()

                if existing_active is not None:
                    raise InvestigationConflictError(
                        f"Incident {incident_id} already has an active or pending investigation: {existing_active[0]}."
                    )

                # 3. Create investigation with status=pending
                new_inv = Investigation(
                    investigation_id=uuid.uuid4(),
                    incident_id=incident_id,
                    status="pending",
                    started_at=None,
                    completed_at=None,
                )
                session.add(new_inv)

                # Update incident investigation status
                incident.investigation_status = "pending"

                session.commit()
                return new_inv.investigation_id
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 2. Investigation Start
    # -------------------------------------------------------------------------

    def start_investigation(self, investigation_id: uuid.UUID) -> InvestigationDTO:
        """Transition an investigation from pending to in_progress.

        Locks parent incident, then investigation (strict lock hierarchy).
        Sets started_at timestamp and updates incident investigation_status.

        Returns:
            Immutable InvestigationDTO snapshot.
        """
        with self._get_session() as session:
            try:
                # Resolve incident_id first for consistent parent-first locking
                inv_meta = session.execute(
                    select(Investigation.incident_id, Investigation.status)
                    .where(Investigation.investigation_id == investigation_id)
                ).first()

                if inv_meta is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

                parent_incident_id, current_status = inv_meta

                # Lock parent incident first
                incident = session.execute(
                    select(Incident)
                    .where(Incident.incident_id == parent_incident_id)
                    .with_for_update()
                ).scalar_one()

                # Lock investigation second
                investigation = session.execute(
                    select(Investigation)
                    .where(Investigation.investigation_id == investigation_id)
                    .with_for_update()
                ).scalar_one()

                if investigation.status != "pending":
                    raise InvestigationConflictError(
                        f"Cannot start investigation {investigation_id}: current status is '{investigation.status}', expected 'pending'."
                    )

                # Verify no other investigation is active for this incident
                other_active = session.execute(
                    select(Investigation.investigation_id)
                    .where(
                        Investigation.incident_id == parent_incident_id,
                        Investigation.investigation_id != investigation_id,
                        Investigation.status == "in_progress",
                    )
                ).first()

                if other_active is not None:
                    raise InvestigationConflictError(
                        f"Incident {parent_incident_id} already has another in_progress investigation: {other_active[0]}."
                    )

                now = datetime.now(timezone.utc)
                investigation.status = "in_progress"
                investigation.started_at = now
                investigation.updated_at = now
                incident.investigation_status = "in_progress"
                incident.updated_at = now

                session.commit()

                return InvestigationDTO(
                    investigation_id=investigation.investigation_id,
                    incident_id=investigation.incident_id,
                    status=investigation.status,
                    investigation_summary=investigation.investigation_summary,
                    investigation_report=investigation.investigation_report,
                    root_cause_assessment=investigation.root_cause_assessment,
                    started_at=investigation.started_at,
                    completed_at=investigation.completed_at,
                    created_at=investigation.created_at,
                    updated_at=investigation.updated_at,
                )
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 3. Heartbeat and Execution Guard
    # -------------------------------------------------------------------------

    def update_heartbeat(self, investigation_id: uuid.UUID) -> None:
        """Update the heartbeat (updated_at) for an active investigation.

        Uses a conditional update (WHERE status = 'in_progress').
        Raises InvestigationTerminatedError if affected rowcount == 0.
        """
        with self._get_session() as session:
            try:
                now = datetime.now(timezone.utc)
                stmt = (
                    update(Investigation)
                    .where(
                        Investigation.investigation_id == investigation_id,
                        Investigation.status == "in_progress",
                    )
                    .values(updated_at=now)
                )
                res = session.execute(stmt)
                if res.rowcount == 0:
                    raise InvestigationTerminatedError(
                        f"Heartbeat failed: Investigation {investigation_id} is no longer in_progress."
                    )
                session.commit()
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 4. Investigation Completion
    # -------------------------------------------------------------------------

    def complete_investigation(
        self,
        investigation_id: uuid.UUID,
        report: InvestigationReport,
        summary: Optional[str] = None,
        root_cause: Optional[str] = None,
        provenance_set: Optional[AuthorizedProvenanceSet] = None,
        serialized_memory_payload: Optional[dict[str, Any]] = None,
    ) -> InvestigationDTO:
        """Finalize an investigation, storing report, summary, and root cause assessment.

        Fails closed: if any confirmed finding or observation has evidence references,
        a valid AuthorizedProvenanceSet MUST be provided containing every referenced item.
        Performs atomic terminal completion, committing investigation completion and
        Hindsight incident memory outbox insertion in the same PostgreSQL transaction.
        """
        # Collect all source references from the report (findings and observations)
        all_report_references: list[str] = []
        for finding in report.confirmed_findings:
            all_report_references.extend(finding.evidence_references)
        for obs in report.observations:
            all_report_references.extend(obs.evidence_references)

        # Provenance validation: fail-closed against AuthorizedProvenanceSet
        if all_report_references:
            if provenance_set is None:
                raise ProvenanceValidationError(
                    "Cannot complete investigation with source references: AuthorizedProvenanceSet was omitted."
                )
            for ref in all_report_references:
                provenance_set.validate_reference(ref)

        with self._get_session() as session:
            try:
                # Lock parent incident first, then investigation
                inv_meta = session.execute(
                    select(Investigation.incident_id, Investigation.status, Investigation.started_at)
                    .where(Investigation.investigation_id == investigation_id)
                ).first()

                if inv_meta is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

                parent_incident_id, current_status, inv_started_at = inv_meta
                if current_status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot complete investigation {investigation_id}: current status is '{current_status}'."
                    )

                # Lock parent incident
                incident = session.execute(
                    select(Incident)
                    .where(Incident.incident_id == parent_incident_id)
                    .with_for_update()
                ).scalar_one()

                # Database-level provenance and relevance verification for all report references
                if all_report_references:
                    self._validate_report_references_in_db(
                        session=session,
                        incident_id=parent_incident_id,
                        inc_source_ip=str(incident.source_ip),
                        inc_created_at=incident.created_at,
                        investigation_id=investigation_id,
                        references=all_report_references,
                    )

                now = datetime.now(timezone.utc)
                report_dict = report.model_dump(mode="json")
                final_summary = summary or report.summary
                final_root_cause = root_cause or report.root_cause_assessment

                stmt = (
                    update(Investigation)
                    .where(
                        Investigation.investigation_id == investigation_id,
                        Investigation.status == "in_progress",
                    )
                    .values(
                        status="completed",
                        investigation_summary=final_summary,
                        investigation_report=report_dict,
                        root_cause_assessment=final_root_cause,
                        completed_at=now,
                        updated_at=now,
                    )
                )
                res = session.execute(stmt)
                if res.rowcount == 0:
                    raise InvestigationTerminatedError(
                        f"Cannot complete investigation {investigation_id}: concurrent modification detected."
                    )

                # Update parent incident
                incident.investigation_status = "completed"
                incident.updated_at = now

                # Enqueue incident memory in transactional outbox within the same atomic transaction
                if settings.HINDSIGHT_ENABLED:
                    if serialized_memory_payload is None:
                        # Fail closed: Hindsight memory retention requires explicit, pre-serialized allowlisted memory payload.
                        # Direct invocation of complete_investigation without an allowlisted payload is strictly rejected.
                        raise MissingMemoryPayloadError(
                            f"Investigation {investigation_id} completed with HINDSIGHT_ENABLED=True, "
                            "but serialized_memory_payload was omitted. Cannot enqueue outbox entry without "
                            "sanitized memory payload."
                        )

                    MemoryOutboxService.enqueue_investigation_memory(
                        session=session,
                        investigation_id=investigation_id,
                        incident_id=parent_incident_id,
                        serialized_memory_payload=serialized_memory_payload,
                        bank_id=settings.HINDSIGHT_BANK_ID,
                    )

                session.commit()

                return InvestigationDTO(
                    investigation_id=investigation_id,
                    incident_id=parent_incident_id,
                    status="completed",
                    investigation_summary=final_summary,
                    investigation_report=report_dict,
                    root_cause_assessment=final_root_cause,
                    started_at=inv_started_at or incident.created_at,
                    completed_at=now,
                    created_at=incident.created_at,
                    updated_at=now,
                )
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _validate_report_references_in_db(
        session: Session,
        incident_id: uuid.UUID,
        inc_source_ip: str,
        inc_created_at: datetime,
        investigation_id: uuid.UUID,
        references: list[str],
    ) -> None:
        """Verify each source reference exists in PostgreSQL and is strictly relevant to the active incident."""
        for ref in references:
            canonical_ref = validate_canonical_source_reference(ref)
            prefix, ident = canonical_ref.split("/", 1)

            if prefix == "ssh_events":
                ev_uuid = uuid.UUID(ident)
                ev_row = session.execute(
                    select(SSHEvent.source_ip, SSHEvent.event_timestamp)
                    .where(SSHEvent.event_id == ev_uuid)
                ).first()
                if ev_row is None:
                    raise ProvenanceValidationError(f"SSH event {ev_uuid} does not exist in database.")
                ev_ip, ev_time = ev_row
                is_linked = session.execute(
                    select(IncidentEvent.event_id)
                    .where(
                        IncidentEvent.incident_id == incident_id,
                        IncidentEvent.event_id == ev_uuid,
                    )
                ).first() is not None

                if not is_linked:
                    window_start = inc_created_at - timedelta(hours=1)
                    window_end = inc_created_at + timedelta(hours=1)
                    if str(ev_ip) != inc_source_ip or not (window_start <= ev_time <= window_end):
                        raise ProvenanceValidationError(
                            f"SSH event {ev_uuid} is neither linked to incident nor within correlation window of source IP."
                        )

            elif prefix == "detection_results":
                dr_uuid = uuid.UUID(ident)
                dr_row = session.execute(
                    select(DetectionResult.incident_id)
                    .where(DetectionResult.result_id == dr_uuid)
                ).first()
                if dr_row is None:
                    raise ProvenanceValidationError(f"Detection result {dr_uuid} does not exist.")
                if dr_row[0] != incident_id:
                    raise ProvenanceValidationError(
                        f"Detection result {dr_uuid} belongs to incident {dr_row[0]}, not current incident {incident_id}."
                    )

            elif prefix == "incidents":
                hist_uuid = uuid.UUID(ident)
                hist_row = session.execute(
                    select(Incident.source_ip, Incident.created_at)
                    .where(Incident.incident_id == hist_uuid)
                ).first()
                if hist_row is None:
                    raise ProvenanceValidationError(f"Historical incident {hist_uuid} does not exist.")
                if hist_uuid == incident_id:
                    raise ProvenanceValidationError("Historical incident reference cannot be the current incident itself.")
                if str(hist_row[0]) != inc_source_ip:
                    raise ProvenanceValidationError(
                        f"Historical incident {hist_uuid} source IP {hist_row[0]} does not match current incident {inc_source_ip}."
                    )
                if hist_row[1] >= inc_created_at:
                    raise ProvenanceValidationError(
                        f"Incident {hist_uuid} created at {hist_row[1]} is not strictly historical relative to {inc_created_at}."
                    )

            elif prefix == "evidence_items":
                prior_uuid = uuid.UUID(ident)
                prior_row = session.execute(
                    select(EvidenceItem.investigation_id)
                    .where(EvidenceItem.evidence_id == prior_uuid)
                ).first()
                if prior_row is None:
                    raise ProvenanceValidationError(f"Prior evidence item {prior_uuid} does not exist.")
                if prior_row[0] != investigation_id:
                    raise ProvenanceValidationError(
                        f"Prior evidence item {prior_uuid} belongs to investigation {prior_row[0]}, not {investigation_id}."
                    )

    # -------------------------------------------------------------------------
    # 5. Investigation Failure
    # -------------------------------------------------------------------------

    def fail_investigation(
        self,
        investigation_id: uuid.UUID,
        error_code: str,
        safe_summary: str,
    ) -> None:
        """Mark an investigation as failed.

        Sanitizes and writes error summary to investigation_summary.
        Automatically fails any running tool runs associated with this investigation.
        Synchronizes parent Incident status only if no other active investigation exists.
        """
        sanitized_code = str(error_code)[:MAX_ERROR_CODE_LEN]
        sanitized_summary = f"[FAILED:{sanitized_code}] {str(safe_summary)[:2000]}"

        with self._get_session() as session:
            try:
                inv_meta = session.execute(
                    select(Investigation.incident_id, Investigation.status)
                    .where(Investigation.investigation_id == investigation_id)
                ).first()

                if inv_meta is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

                parent_incident_id, current_status = inv_meta
                if current_status in ["completed", "failed"]:
                    logger.warning(
                        "Investigation %s already in terminal status '%s'; ignoring fail_investigation.",
                        investigation_id, current_status,
                    )
                    return

                # Lock parent incident first (Hierarchy)
                incident = session.execute(
                    select(Incident)
                    .where(Incident.incident_id == parent_incident_id)
                    .with_for_update()
                ).scalar_one()

                now = datetime.now(timezone.utc)
                stmt = (
                    update(Investigation)
                    .where(
                        Investigation.investigation_id == investigation_id,
                        Investigation.status.in_(["pending", "in_progress"]),
                    )
                    .values(
                        status="failed",
                        investigation_summary=sanitized_summary,
                        completed_at=now,
                        updated_at=now,
                    )
                )
                res = session.execute(stmt)
                if res.rowcount > 0:
                    # Automatically fail associated running tool runs
                    session.execute(
                        text("""
                            UPDATE investigation_tool_runs
                            SET execution_status = 'failed',
                                completed_at = :now,
                                error_code = 'INVESTIGATION_RECOVERED',
                                duration_ms = CASE
                                    WHEN started_at IS NOT NULL THEN GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (:now - started_at)) * 1000)::INTEGER)
                                    ELSE 0
                                END
                            WHERE investigation_id = :inv_id
                              AND execution_status = 'running'
                        """),
                        {"inv_id": investigation_id, "now": now},
                    )

                    # Check if other pending/in_progress investigations exist for incident
                    other_active = session.execute(
                        select(Investigation.investigation_id)
                        .where(
                            Investigation.incident_id == parent_incident_id,
                            Investigation.investigation_id != investigation_id,
                            Investigation.status.in_(["pending", "in_progress"]),
                        )
                    ).first()

                    if other_active is None:
                        incident.investigation_status = "failed"
                        incident.updated_at = now

                session.commit()
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 6. Tool-Run Audit Lifecycle
    # -------------------------------------------------------------------------

    def record_tool_run_start(
        self,
        investigation_id: uuid.UUID,
        tool_name: str,
        input_summary: Optional[dict[str, Any]] = None,
    ) -> uuid.UUID:
        """Create a tool run record with execution_status='running'."""
        bounded_name = str(tool_name)[:MAX_TOOL_NAME_LEN]
        bounded_input = _sanitize_and_bound_json(input_summary)

        with self._get_session() as session:
            try:
                # Verify investigation is in_progress
                inv_status = session.execute(
                    select(Investigation.status)
                    .where(Investigation.investigation_id == investigation_id)
                ).scalar_one_or_none()

                if inv_status is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")
                if inv_status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot start tool run: Investigation {investigation_id} is in status '{inv_status}'."
                    )

                now = datetime.now(timezone.utc)
                tool_run = InvestigationToolRun(
                    tool_run_id=uuid.uuid4(),
                    investigation_id=investigation_id,
                    tool_name=bounded_name,
                    execution_status="running",
                    input_summary=bounded_input,
                    started_at=now,
                    completed_at=None,
                    duration_ms=None,
                )
                session.add(tool_run)
                session.commit()
                return tool_run.tool_run_id
            except Exception:
                session.rollback()
                raise

    def record_tool_run_success(
        self,
        tool_run_id: uuid.UUID,
        output_summary: Optional[dict[str, Any]] = None,
    ) -> None:
        """Mark tool run as succeeded, verifying parent investigation remains in_progress.

        Enforces strict lock hierarchy: Investigation (first) -> InvestigationToolRun (second).
        """
        bounded_output = _sanitize_and_bound_json(output_summary)

        with self._get_session() as session:
            try:
                # 1. Resolve parent investigation_id
                tr_meta = session.execute(
                    select(InvestigationToolRun.investigation_id)
                    .where(InvestigationToolRun.tool_run_id == tool_run_id)
                ).first()

                if tr_meta is None:
                    raise ToolRunLifecycleError(f"Tool run {tool_run_id} not found.")

                inv_id = tr_meta[0]

                # 2. Strict Lock Hierarchy: Lock parent Investigation first
                inv_status = session.execute(
                    select(Investigation.status)
                    .where(Investigation.investigation_id == inv_id)
                    .with_for_update()
                ).scalar_one_or_none()

                if inv_status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot complete tool run {tool_run_id}: parent investigation is in status '{inv_status}'."
                    )

                # 3. Lock InvestigationToolRun second
                tool_run = session.execute(
                    select(InvestigationToolRun)
                    .where(InvestigationToolRun.tool_run_id == tool_run_id)
                    .with_for_update()
                ).scalar_one()

                if tool_run.execution_status != "running":
                    raise ToolRunLifecycleError(
                        f"Cannot mark tool run {tool_run_id} as succeeded: current status is '{tool_run.execution_status}'."
                    )

                now = datetime.now(timezone.utc)
                duration = None
                if tool_run.started_at:
                    duration = max(0, int((now - tool_run.started_at).total_seconds() * 1000))

                tool_run.execution_status = "succeeded"
                tool_run.output_summary = bounded_output
                tool_run.completed_at = now
                tool_run.duration_ms = duration

                session.commit()
            except Exception:
                session.rollback()
                raise

    def record_tool_run_failure(
        self,
        tool_run_id: uuid.UUID,
        error_code: str,
        output_summary: Optional[dict[str, Any]] = None,
    ) -> None:
        """Mark tool run as failed, verifying parent investigation remains in_progress.

        Enforces strict lock hierarchy: Investigation (first) -> InvestigationToolRun (second).
        """
        bounded_code = str(error_code)[:MAX_ERROR_CODE_LEN]
        bounded_output = _sanitize_and_bound_json(output_summary)

        with self._get_session() as session:
            try:
                # 1. Resolve parent investigation_id
                tr_meta = session.execute(
                    select(InvestigationToolRun.investigation_id)
                    .where(InvestigationToolRun.tool_run_id == tool_run_id)
                ).first()

                if tr_meta is None:
                    raise ToolRunLifecycleError(f"Tool run {tool_run_id} not found.")

                inv_id = tr_meta[0]

                # 2. Strict Lock Hierarchy: Lock parent Investigation first
                inv_status = session.execute(
                    select(Investigation.status)
                    .where(Investigation.investigation_id == inv_id)
                    .with_for_update()
                ).scalar_one_or_none()

                if inv_status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot fail tool run {tool_run_id}: parent investigation is in status '{inv_status}'."
                    )

                # 3. Lock InvestigationToolRun second
                tool_run = session.execute(
                    select(InvestigationToolRun)
                    .where(InvestigationToolRun.tool_run_id == tool_run_id)
                    .with_for_update()
                ).scalar_one()

                if tool_run.execution_status != "running":
                    raise ToolRunLifecycleError(
                        f"Cannot mark tool run {tool_run_id} as failed: current status is '{tool_run.execution_status}'."
                    )

                now = datetime.now(timezone.utc)
                duration = None
                if tool_run.started_at:
                    duration = max(0, int((now - tool_run.started_at).total_seconds() * 1000))

                tool_run.execution_status = "failed"
                tool_run.error_code = bounded_code
                tool_run.output_summary = bounded_output
                tool_run.completed_at = now
                tool_run.duration_ms = duration

                session.commit()
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 7. Evidence Persistence and Provenance
    # -------------------------------------------------------------------------

    def record_evidence(
        self,
        investigation_id: uuid.UUID,
        evidence_type: str,
        title: str,
        source_reference: str,
        description: Optional[str] = None,
        evidence_data: Optional[dict[str, Any]] = None,
        provenance_set: Optional[AuthorizedProvenanceSet] = None,
    ) -> EvidenceItemDTO:
        """Validate and persist an evidence item for the active investigation.

        Performs two-tier validation:
        1. Validates canonical source reference format.
        2. Validates against provenance_set (if supplied).
        3. Queries PostgreSQL to verify record existence and relevance to active incident.
        4. Validates parent investigation remains in_progress.
        """
        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise ProvenanceValidationError(f"Invalid evidence_type: '{evidence_type}'.")

        canonical_ref = validate_canonical_source_reference(source_reference)
        prefix, ident = canonical_ref.split("/", 1)

        if provenance_set is not None and not provenance_set.contains_reference(canonical_ref):
            raise ProvenanceValidationError(
                f"Source reference '{canonical_ref}' was not retrieved in this investigation's authorized session."
            )

        with self._get_session() as session:
            try:
                # Verify investigation is in_progress and get incident context (locks Investigation row)
                inv = session.execute(
                    select(Investigation.status, Incident.incident_id, Incident.source_ip, Incident.created_at)
                    .join(Incident, Incident.incident_id == Investigation.incident_id)
                    .where(Investigation.investigation_id == investigation_id)
                    .with_for_update(of=Investigation)
                ).first()

                if inv is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

                status, incident_id, inc_source_ip, inc_created_at = inv
                if status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot record evidence: Investigation {investigation_id} is in status '{status}'."
                    )

                event_id_to_link: Optional[uuid.UUID] = None

                # Database-level provenance and relevance checks
                if prefix == "ssh_events":
                    ev_uuid = uuid.UUID(ident)
                    ev_row = session.execute(
                        select(SSHEvent.source_ip, SSHEvent.event_timestamp)
                        .where(SSHEvent.event_id == ev_uuid)
                    ).first()

                    if ev_row is None:
                        raise ProvenanceValidationError(f"SSH event {ev_uuid} does not exist in database.")

                    ev_ip, ev_time = ev_row

                    is_linked = session.execute(
                        select(IncidentEvent.event_id)
                        .where(
                            IncidentEvent.incident_id == incident_id,
                            IncidentEvent.event_id == ev_uuid,
                        )
                    ).first() is not None

                    if not is_linked:
                        window_start = inc_created_at - timedelta(hours=1)
                        window_end = inc_created_at + timedelta(hours=1)
                        if str(ev_ip) != str(inc_source_ip) or not (window_start <= ev_time <= window_end):
                            raise ProvenanceValidationError(
                                f"SSH event {ev_uuid} is neither linked to incident nor within correlation window of source IP."
                            )

                    event_id_to_link = ev_uuid

                elif prefix == "detection_results":
                    dr_uuid = uuid.UUID(ident)
                    dr_row = session.execute(
                        select(DetectionResult.incident_id)
                        .where(DetectionResult.result_id == dr_uuid)
                    ).first()

                    if dr_row is None:
                        raise ProvenanceValidationError(f"Detection result {dr_uuid} does not exist.")
                    if dr_row[0] != incident_id:
                        raise ProvenanceValidationError(
                            f"Detection result {dr_uuid} belongs to incident {dr_row[0]}, not current incident {incident_id}."
                        )

                elif prefix == "incidents":
                    hist_uuid = uuid.UUID(ident)
                    hist_row = session.execute(
                        select(Incident.source_ip, Incident.created_at)
                        .where(Incident.incident_id == hist_uuid)
                    ).first()

                    if hist_row is None:
                        raise ProvenanceValidationError(f"Historical incident {hist_uuid} does not exist.")
                    if hist_uuid == incident_id:
                        raise ProvenanceValidationError("Historical incident reference cannot be the current incident itself.")
                    if str(hist_row[0]) != str(inc_source_ip):
                        raise ProvenanceValidationError(
                            f"Historical incident {hist_uuid} source IP {hist_row[0]} does not match current incident {inc_source_ip}."
                        )
                    if hist_row[1] >= inc_created_at:
                        raise ProvenanceValidationError(
                            f"Incident {hist_uuid} created at {hist_row[1]} is not strictly historical relative to {inc_created_at}."
                        )

                elif prefix == "evidence_items":
                    prior_uuid = uuid.UUID(ident)
                    prior_row = session.execute(
                        select(EvidenceItem.investigation_id)
                        .where(EvidenceItem.evidence_id == prior_uuid)
                    ).first()

                    if prior_row is None:
                        raise ProvenanceValidationError(f"Prior evidence item {prior_uuid} does not exist.")
                    if prior_row[0] != investigation_id:
                        raise ProvenanceValidationError(
                            f"Prior evidence item {prior_uuid} belongs to investigation {prior_row[0]}, not {investigation_id}."
                        )

                # Persist EvidenceItem via shared persistence helper
                item = self._create_and_insert_evidence_item(
                    session=session,
                    investigation_id=investigation_id,
                    evidence_type=evidence_type,
                    title=title,
                    source_reference=canonical_ref,
                    description=description,
                    evidence_data=evidence_data,
                    event_id=event_id_to_link,
                )
                session.commit()

                return EvidenceItemDTO(
                    evidence_id=item.evidence_id,
                    investigation_id=item.investigation_id,
                    event_id=item.event_id,
                    evidence_type=item.evidence_type,
                    title=item.title,
                    description=item.description,
                    evidence_data=item.evidence_data,
                    source_reference=item.source_reference,
                    collected_at=item.collected_at,
                )
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _create_and_insert_evidence_item(
        session: Session,
        investigation_id: uuid.UUID,
        evidence_type: str,
        title: str,
        source_reference: str,
        description: Optional[str] = None,
        evidence_data: Optional[dict[str, Any]] = None,
        event_id: Optional[uuid.UUID] = None,
        evidence_id: Optional[uuid.UUID] = None,
        collected_at: Optional[datetime] = None,
    ) -> EvidenceItem:
        """Shared internal helper for validated EvidenceItem instantiation and insertion.

        Guarantees identical type allowlisting, canonical reference parsing, title
        bounds enforcement, and JSON payload bounding/sanitization across single
        evidence recording and batch MITRE persistence.
        """
        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise ProvenanceValidationError(f"Invalid evidence_type: '{evidence_type}'.")

        canonical_ref = validate_canonical_source_reference(source_reference)
        now = collected_at or datetime.now(timezone.utc)
        bounded_evidence_data = _sanitize_and_bound_json(evidence_data)

        item = EvidenceItem(
            evidence_id=evidence_id or uuid.uuid4(),
            investigation_id=investigation_id,
            event_id=event_id,
            evidence_type=evidence_type,
            title=str(title)[:255],
            description=description,
            evidence_data=bounded_evidence_data,
            source_reference=canonical_ref,
            collected_at=now,
        )
        session.add(item)
        return item

    # -------------------------------------------------------------------------
    # 7b. Authoritative MITRE ATT&CK Mapping Persistence (Task 8D)
    # -------------------------------------------------------------------------

    def persist_validated_mitre_mappings(
        self,
        investigation_id: uuid.UUID,
        proposals: Sequence[MitreCandidateProposal],
        provenance_set: AuthorizedProvenanceSet,
        catalogue: MitreCatalogueService,
        authorized_ssh_events: Optional[Sequence[SSHEventRecord]] = None,
        retrieval_metadata: Optional[EventRetrievalMetadata] = None,
    ) -> tuple[MitreAttackMapping, ...]:
        """Validate candidate proposals and persist them as authoritative EvidenceItem records.

        Guarantees:
        - Independent validation via MitreMappingValidator.
        - Strict lock hierarchy: Parent Incident (FOR UPDATE) -> Investigation (FOR UPDATE) -> EvidenceItem.
        - Parent investigation must remain in 'in_progress' status.
        - Idempotency / deduplication: if an EvidenceItem already exists for this investigation_id
          with evidence_type='mitre_technique' and matching mapping_id, reuses its evidence_id without duplicates.
        - Registers technique_id and evidence_id into the active AuthorizedProvenanceSet.
        - Anti-circularity: MITRE EvidenceItems are NOT inserted into the mapping's own supporting references.
        - Returns immutable tuple of MitreAttackMapping instances populated with evidence_item_id.
        """
        if not proposals:
            return ()

        # 1. Independent validation & authoritative metadata overwrite
        validator = MitreMappingValidator(catalogue=catalogue)
        validated_mappings = validator.validate_proposals(
            proposals=proposals,
            provenance_set=provenance_set,
            investigation_id=investigation_id,
            authorized_ssh_events=authorized_ssh_events,
            retrieval_metadata=retrieval_metadata,
        )

        with self._get_session() as session:
            try:
                # 2. Strict Lock Hierarchy: Resolve incident_id and lock Incident first
                inv_meta = session.execute(
                    select(Investigation.incident_id, Investigation.status)
                    .where(Investigation.investigation_id == investigation_id)
                ).first()

                if inv_meta is None:
                    raise InvestigationNotFoundError(f"Investigation {investigation_id} not found.")

                parent_incident_id, current_status = inv_meta
                if current_status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot persist MITRE mappings: Investigation {investigation_id} is in status '{current_status}'."
                    )

                # Lock parent incident
                session.execute(
                    select(Incident.incident_id)
                    .where(Incident.incident_id == parent_incident_id)
                    .with_for_update()
                ).scalar_one()

                # Lock investigation second
                inv = session.execute(
                    select(Investigation)
                    .where(Investigation.investigation_id == investigation_id)
                    .with_for_update()
                ).scalar_one()

                if inv.status != "in_progress":
                    raise InvestigationTerminatedError(
                        f"Cannot persist MITRE mappings: Investigation {investigation_id} is in status '{inv.status}'."
                    )

                # 3. Query existing mitre evidence items for deduplication
                existing_items = list(
                    session.execute(
                        select(EvidenceItem)
                        .where(
                            EvidenceItem.investigation_id == investigation_id,
                            EvidenceItem.evidence_type == "mitre_technique",
                        )
                    ).scalars().all()
                )

                now = datetime.now(timezone.utc)
                persisted_mappings: list[MitreAttackMapping] = []
                committed_registrations: list[tuple[str, uuid.UUID]] = []

                for mapping in validated_mappings:
                    mapping_id_str = str(mapping.mapping_id)
                    matching_item: Optional[EvidenceItem] = None

                    for item in existing_items:
                        if (
                            item.source_reference == f"mitre/{mapping.technique_id}"
                            and isinstance(item.evidence_data, dict)
                            and str(item.evidence_data.get("mapping_id")) == mapping_id_str
                        ):
                            matching_item = item
                            break

                    if matching_item is not None:
                        # Re-use existing evidence item
                        item_id = matching_item.evidence_id
                    else:
                        # Create and insert new EvidenceItem via shared persistence helper
                        item_id = uuid.uuid4()
                        evidence_payload = mapping.model_dump(mode="json")
                        evidence_payload["evidence_item_id"] = str(item_id)

                        new_item = self._create_and_insert_evidence_item(
                            session=session,
                            investigation_id=investigation_id,
                            evidence_type="mitre_technique",
                            title=f"MITRE ATT&CK {mapping.technique_id}: {mapping.technique_name}",
                            source_reference=f"mitre/{mapping.technique_id}",
                            description=mapping.rationale,
                            evidence_data=evidence_payload,
                            event_id=None,
                            evidence_id=item_id,
                            collected_at=now,
                        )
                        existing_items.append(new_item)

                    committed_registrations.append((mapping.technique_id, item_id))
                    persisted_mappings.append(
                        mapping.model_copy(update={"evidence_item_id": item_id})
                    )

                session.commit()

                # 4. Register in AuthorizedProvenanceSet only after successful commit
                for tech_id, ev_id in committed_registrations:
                    provenance_set.add_mitre_technique(tech_id)
                    provenance_set.add_evidence_item(ev_id)

                return tuple(persisted_mappings)
            except Exception:
                session.rollback()
                raise

    # -------------------------------------------------------------------------
    # 8. Stale and Abandoned Investigation Recovery
    # -------------------------------------------------------------------------

    def recover_stale_investigations(self) -> dict[str, list[uuid.UUID]]:
        """Recover abandoned pending and stale in-progress investigations.

        Lock Hierarchy Enforcement:
        Locks Parent Incidents first (FOR UPDATE SKIP LOCKED) before updating
        investigations and tool runs. This strictly matches the application-wide
        locking order: Incidents -> Investigations -> ToolRuns, eliminating deadlock risk.

        Also recovers running InvestigationToolRun records to failed.
        """
        recovered_inv_ids: list[uuid.UUID] = []
        recovered_inc_ids: list[uuid.UUID] = []

        with self._get_session() as session:
            try:
                # 1. Recover abandoned pending investigations (parent-incident locked first)
                pending_recovery_sql = text("""
                    WITH target_incidents AS (
                        SELECT incident_id
                        FROM incidents
                        WHERE incident_id IN (
                            SELECT incident_id
                            FROM investigations
                            WHERE status = 'pending' AND created_at < NOW() - INTERVAL '5 minutes'
                        )
                        ORDER BY incident_id
                        FOR UPDATE SKIP LOCKED
                        LIMIT :limit
                    ),
                    abandoned_invs AS (
                        UPDATE investigations
                        SET status = 'failed',
                            completed_at = NOW(),
                            updated_at = NOW(),
                            investigation_summary = '[FAILED:TIMEOUT] Abandoned pending investigation timed out after 5 minutes.'
                        WHERE incident_id IN (SELECT incident_id FROM target_incidents)
                          AND status = 'pending'
                          AND created_at < NOW() - INTERVAL '5 minutes'
                        RETURNING investigation_id, incident_id
                    )
                    SELECT investigation_id, incident_id FROM abandoned_invs;
                """)
                res_pending = session.execute(
                    pending_recovery_sql, {"limit": RECOVERY_BATCH_LIMIT}
                ).all()

                # 2. Recover stale in-progress investigations (parent-incident locked first)
                stale_recovery_sql = text("""
                    WITH target_incidents AS (
                        SELECT inc.incident_id
                        FROM incidents inc
                        WHERE inc.incident_id IN (
                            SELECT inv.incident_id
                            FROM investigations inv
                            LEFT JOIN (
                                SELECT investigation_id, MAX(COALESCE(completed_at, started_at)) AS latest_tool_at
                                FROM investigation_tool_runs
                                GROUP BY investigation_id
                            ) tr ON tr.investigation_id = inv.investigation_id
                            WHERE inv.status = 'in_progress'
                              AND (
                                  inv.started_at < NOW() - INTERVAL '30 minutes'
                                  OR (
                                      inv.updated_at < NOW() - INTERVAL '5 minutes'
                                      AND (tr.latest_tool_at IS NULL OR tr.latest_tool_at < NOW() - INTERVAL '5 minutes')
                                  )
                              )
                        )
                        ORDER BY inc.incident_id
                        FOR UPDATE SKIP LOCKED
                        LIMIT :limit
                    ),
                    stale_invs AS (
                        UPDATE investigations inv
                        SET status = 'failed',
                            completed_at = NOW(),
                            updated_at = NOW(),
                            investigation_summary = '[FAILED:STALE] Investigation timed out or abandoned by worker.'
                        FROM (
                            SELECT inv_sub.investigation_id
                            FROM investigations inv_sub
                            LEFT JOIN (
                                SELECT investigation_id, MAX(COALESCE(completed_at, started_at)) AS latest_tool_at
                                FROM investigation_tool_runs
                                GROUP BY investigation_id
                            ) tr_sub ON tr_sub.investigation_id = inv_sub.investigation_id
                            WHERE inv_sub.incident_id IN (SELECT incident_id FROM target_incidents)
                              AND inv_sub.status = 'in_progress'
                              AND (
                                  inv_sub.started_at < NOW() - INTERVAL '30 minutes'
                                  OR (
                                      inv_sub.updated_at < NOW() - INTERVAL '5 minutes'
                                      AND (tr_sub.latest_tool_at IS NULL OR tr_sub.latest_tool_at < NOW() - INTERVAL '5 minutes')
                                  )
                              )
                        ) candidates
                        WHERE inv.investigation_id = candidates.investigation_id
                        RETURNING inv.investigation_id, inv.incident_id
                    )
                    SELECT investigation_id, incident_id FROM stale_invs;
                """)
                res_inprogress = session.execute(
                    stale_recovery_sql, {"limit": RECOVERY_BATCH_LIMIT}
                ).all()

                all_recovered = res_pending + res_inprogress
                affected_incident_ids = set()

                for inv_id, inc_id in all_recovered:
                    recovered_inv_ids.append(inv_id)
                    affected_incident_ids.add(inc_id)

                # 3. Recover abandoned tool runs associated with recovered investigations
                if recovered_inv_ids:
                    session.execute(
                        text("""
                            UPDATE investigation_tool_runs
                            SET execution_status = 'failed',
                                completed_at = NOW(),
                                error_code = 'INVESTIGATION_RECOVERED',
                                duration_ms = CASE
                                    WHEN started_at IS NOT NULL THEN GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000)::INTEGER)
                                    ELSE 0
                                END
                            WHERE investigation_id = ANY(:inv_ids)
                              AND execution_status = 'running'
                        """),
                        {"inv_ids": recovered_inv_ids},
                    )

                # 4. Synchronize parent incidents where no other active investigation exists
                for inc_id in affected_incident_ids:
                    has_active = session.execute(
                        select(Investigation.investigation_id)
                        .where(
                            Investigation.incident_id == inc_id,
                            Investigation.status.in_(["pending", "in_progress"]),
                        )
                    ).first()

                    if not has_active:
                        session.execute(
                            update(Incident)
                            .where(Incident.incident_id == inc_id)
                            .values(
                                investigation_status="failed",
                                updated_at=datetime.now(timezone.utc),
                            )
                        )
                        recovered_inc_ids.append(inc_id)

                session.commit()
                return {
                    "recovered_investigations": recovered_inv_ids,
                    "recovered_incidents": recovered_inc_ids,
                }
            except Exception:
                session.rollback()
                raise
