"""Hybrid Detection Orchestrator for SentinelAgent (Task 6B).

Orchestrates multi-engine cybersecurity anomaly detection by coordinating:
1. Feature extraction from persisted SSH events.
2. Independent rule-based detection (RuleDetector).
3. Independent machine learning anomaly scoring (IsolationForestDetector).
4. Dual detection-result persistence in PostgreSQL.
5. Multi-window incident creation, correlation, and deduplication.
6. Evidence linkage associating supporting SSH events with security incidents.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional, Sequence
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.models.incident import (
    Incident,
    VALID_DETECTION_METHODS,
    VALID_INCIDENT_STATUSES,
)
from app.models.incident_event import IncidentEvent
from app.models.ssh_event import SSHEvent
from app.services.feature_extractor import (
    FeatureExtractor,
    FeatureExtractorConfig,
    WindowFeatures,
)
from app.services.isolation_forest_detector import (
    IsolationForestDetector,
    MLDetectionResult,
)
from app.services.rule_detector import (
    DetectionResult as RuleDetectionOutput,
    RULE_R001,
    RULE_R002,
    RuleDetector,
    RuleDetectorConfig,
)

logger = logging.getLogger(__name__)


class DetectionOrchestratorError(Exception):
    """Base exception for detection orchestrator failures."""


class DetectionOrchestratorConfigurationError(DetectionOrchestratorError):
    """Raised when orchestrator dependencies are unconfigured, untrained, or uncalibrated."""


@dataclass(frozen=True)
class DetectionOrchestratorConfig:
    """Configuration for hybrid detection orchestration and incident correlation."""

    correlation_window: timedelta = timedelta(minutes=5)
    """Window duration for correlating repeated suspicious activities from the same source IP into an existing open incident."""

    max_incident_lifetime: timedelta = timedelta(hours=24)
    """Maximum duration an active incident can be extended before forcing creation of a new distinct incident."""

    def __post_init__(self) -> None:
        if not isinstance(self.correlation_window, timedelta) or self.correlation_window <= timedelta(0):
            raise ValueError("correlation_window must be a positive timedelta.")
        if not isinstance(self.max_incident_lifetime, timedelta) or self.max_incident_lifetime <= timedelta(0):
            raise ValueError("max_incident_lifetime must be a positive timedelta.")


@dataclass(frozen=True)
class OrchestrationResult:
    """Summary of operations performed during a detection orchestration pass."""

    total_events_processed: int
    total_windows_evaluated: int
    rule_results_count: int
    ml_results_count: int
    incidents_created: tuple[uuid.UUID, ...]
    incidents_updated: tuple[uuid.UUID, ...]
    detection_results_persisted: tuple[uuid.UUID, ...]
    events_associated_count: int

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "total_events_processed": self.total_events_processed,
            "total_windows_evaluated": self.total_windows_evaluated,
            "rule_results_count": self.rule_results_count,
            "ml_results_count": self.ml_results_count,
            "incidents_created": [str(i) for i in self.incidents_created],
            "incidents_updated": [str(i) for i in self.incidents_updated],
            "detection_results_persisted": [str(r) for r in self.detection_results_persisted],
            "events_associated_count": self.events_associated_count,
        }


class DetectionOrchestrator:
    """Coordinates feature extraction, dual-detector evaluation, persistence, and incident management."""

    def __init__(
        self,
        *,
        ml_detector: IsolationForestDetector,
        rule_detector: Optional[RuleDetector] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        config: Optional[DetectionOrchestratorConfig] = None,
    ) -> None:
        self.config = config or DetectionOrchestratorConfig()

        # Strict dependency verification
        if ml_detector is None:
            raise DetectionOrchestratorConfigurationError(
                "IsolationForestDetector dependency cannot be None."
            )
        if not getattr(ml_detector, "is_trained", False):
            raise DetectionOrchestratorConfigurationError(
                "IsolationForestDetector must be trained prior to orchestration injection."
            )
        if not getattr(ml_detector, "is_calibrated", False) or ml_detector.calibrated_threshold is None:
            raise DetectionOrchestratorConfigurationError(
                "IsolationForestDetector must be calibrated with a valid decision threshold prior to orchestration injection."
            )

        self.ml_detector = ml_detector
        self.rule_detector = rule_detector or RuleDetector()
        self.feature_extractor = feature_extractor or FeatureExtractor()

    def process_events(
        self,
        session: Session,
        events: Sequence[SSHEvent],
        *,
        auto_commit: bool = True,
    ) -> OrchestrationResult:
        """Process a batch of persisted SSH events through hybrid detection and incident creation.

        Guarantees:
        - Atomic transaction execution: rolls back on any persistence failure.
        - Preserves independent rule and ML detection rows for every evaluated window.
        - Reuses open incidents from the same source IP within the correlation window.
        - Associates relevant supporting SSH events without duplicate key errors.
        - Never automatically classifies severity (severity remains NULL).
        """
        if not events:
            return OrchestrationResult(
                total_events_processed=0,
                total_windows_evaluated=0,
                rule_results_count=0,
                ml_results_count=0,
                incidents_created=(),
                incidents_updated=(),
                detection_results_persisted=(),
                events_associated_count=0,
            )

        try:
            # 1. Extract behavioral features across 1-minute UTC windows
            windows = self.feature_extractor.extract_features(events)
            if not windows:
                return OrchestrationResult(
                    total_events_processed=len(events),
                    total_windows_evaluated=0,
                    rule_results_count=0,
                    ml_results_count=0,
                    incidents_created=(),
                    incidents_updated=(),
                    detection_results_persisted=(),
                    events_associated_count=0,
                )

            created_incident_ids: list[uuid.UUID] = []
            updated_incident_ids: list[uuid.UUID] = []
            persisted_result_ids: list[uuid.UUID] = []
            associated_events_count: int = 0

            # In-run cache of active incidents by source IP to correlate multiple windows in the same batch
            active_batch_incidents: dict[str, Incident] = {}
            # Track associated (incident_id, event_id) pairs to avoid duplicates within this transaction
            seen_associations: set[tuple[uuid.UUID, uuid.UUID]] = set()

            for window in windows:
                # 2. Independent Detector Evaluations
                rule_out: RuleDetectionOutput = self.rule_detector.evaluate_window(window)
                ml_out: MLDetectionResult = self.ml_detector.predict_window(window)

                rule_triggered = bool(rule_out.is_suspicious)
                ml_triggered = bool(ml_out.is_anomaly)
                is_suspicious_window = rule_triggered or ml_triggered

                target_incident: Optional[Incident] = None

                # 3. Incident Creation & Deduplication (if suspicious)
                if is_suspicious_window:
                    # Determine classification method for this window
                    if rule_triggered and ml_triggered:
                        window_detection_method = "hybrid"
                    elif rule_triggered:
                        window_detection_method = "rule"
                    else:
                        window_detection_method = "ml"

                    target_incident, is_new = self._resolve_or_create_incident(
                        session=session,
                        window=window,
                        detection_method=window_detection_method,
                        rule_output=rule_out,
                        active_batch_incidents=active_batch_incidents,
                    )

                    if is_new:
                        created_incident_ids.append(target_incident.incident_id)
                        active_batch_incidents[window.source_ip] = target_incident
                    else:
                        if target_incident.incident_id not in updated_incident_ids:
                            updated_incident_ids.append(target_incident.incident_id)

                    # 4. Associate supporting events with the incident
                    newly_linked = self._associate_window_events(
                        session=session,
                        incident=target_incident,
                        window=window,
                        seen_associations=seen_associations,
                    )
                    associated_events_count += newly_linked

                # 5. Persist Separate Detection Results (Rule and ML)
                eval_now = datetime.now(timezone.utc)
                incident_id_for_results = target_incident.incident_id if target_incident else None

                # 5a. Rule Detection Result
                rule_row = DetectionResult(
                    result_id=uuid.uuid4(),
                    incident_id=incident_id_for_results,
                    source_ip=window.source_ip,
                    window_start=window.window_start,
                    window_end=window.window_end,
                    detector_type="rule",
                    is_suspicious=rule_triggered,
                    triggered_rules=list(rule_out.triggered_rules),
                    feature_snapshot=window.to_dict(),
                    normality_score=None,
                    calibrated_threshold=None,
                    model_version=None,
                    evaluated_at=eval_now,
                )
                session.add(rule_row)
                persisted_result_ids.append(rule_row.result_id)

                # 5b. Isolation Forest ML Detection Result
                ml_row = DetectionResult(
                    result_id=uuid.uuid4(),
                    incident_id=incident_id_for_results,
                    source_ip=window.source_ip,
                    window_start=window.window_start,
                    window_end=window.window_end,
                    detector_type="isolation_forest",
                    is_suspicious=ml_triggered,
                    triggered_rules=[],
                    feature_snapshot=window.to_dict(),
                    normality_score=ml_out.normality_score,
                    calibrated_threshold=ml_out.calibrated_threshold,
                    model_version=ml_out.model_version,
                    evaluated_at=eval_now,
                )
                session.add(ml_row)
                persisted_result_ids.append(ml_row.result_id)

            if auto_commit:
                session.commit()

            return OrchestrationResult(
                total_events_processed=len(events),
                total_windows_evaluated=len(windows),
                rule_results_count=len(windows),
                ml_results_count=len(windows),
                incidents_created=tuple(created_incident_ids),
                incidents_updated=tuple(updated_incident_ids),
                detection_results_persisted=tuple(persisted_result_ids),
                events_associated_count=associated_events_count,
            )

        except Exception as exc:
            if auto_commit:
                session.rollback()
            logger.error("Detection orchestration failed: %s", type(exc).__name__)
            raise

    def _resolve_or_create_incident(
        self,
        session: Session,
        window: WindowFeatures,
        detection_method: str,
        rule_output: RuleDetectionOutput,
        active_batch_incidents: dict[str, Incident],
    ) -> tuple[Incident, bool]:
        """Find an existing open incident to reuse or create a new incident.

        Returns (incident, is_new).
        """
        # 1. Acquire transaction-scoped PostgreSQL advisory lock per source IP to coordinate concurrent batches
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:ip))"),
            {"ip": str(window.source_ip)},
        )

        # 2. Check in-batch cache first for intra-batch correlation
        if window.source_ip in active_batch_incidents:
            cached_inc = active_batch_incidents[window.source_ip]
            if cached_inc.status != "closed":
                time_diff = window.window_start - cached_inc.updated_at
                total_life = window.window_start - cached_inc.created_at
                if timedelta(0) <= time_diff <= self.config.correlation_window and total_life <= self.config.max_incident_lifetime:
                    self._update_existing_incident(cached_inc, window, detection_method)
                    return cached_inc, False

        # 2. Database query with row-level locking for inter-transaction deduplication
        cutoff = window.window_start - self.config.correlation_window
        max_lifetime_cutoff = window.window_start - self.config.max_incident_lifetime

        stmt = (
            select(Incident)
            .where(
                Incident.source_ip == window.source_ip,
                Incident.status != "closed",
                Incident.updated_at >= cutoff,
                Incident.created_at >= max_lifetime_cutoff,
            )
            .order_by(Incident.updated_at.desc())
            .with_for_update()
        )
        existing = session.execute(stmt).scalars().first()

        if existing is not None:
            self._update_existing_incident(existing, window, detection_method)
            return existing, False

        # 3. Create fresh Incident
        title, incident_type = self._derive_title_and_type(window, detection_method, rule_output)
        now_utc = datetime.now(timezone.utc)

        new_incident = Incident(
            incident_id=uuid.uuid4(),
            title=title,
            incident_type=incident_type,
            source_ip=window.source_ip,
            severity=None,  # Explicitly kept NULL per policy
            detection_method=detection_method,
            status="open",
            investigation_status="pending",
            response_status="not_proposed",
            verification_status="not_started",
            created_at=window.window_start if window.window_start else now_utc,
            updated_at=window.window_end if window.window_end else now_utc,
            closed_at=None,
        )
        session.add(new_incident)
        session.flush()  # Populate incident_id in session
        return new_incident, True

    def _update_existing_incident(
        self,
        incident: Incident,
        window: WindowFeatures,
        new_window_method: str,
    ) -> None:
        """Update an existing incident with new correlation activity and method progression."""
        # Upgrade method to 'hybrid' if multiple detectors have now triggered across correlated windows
        if incident.detection_method != "hybrid":
            if incident.detection_method != new_window_method:
                incident.detection_method = "hybrid"
            elif new_window_method == "hybrid":
                incident.detection_method = "hybrid"

        # Update updated_at timestamp
        candidate_ts = window.window_end if window.window_end else datetime.now(timezone.utc)
        if incident.updated_at < candidate_ts:
            incident.updated_at = candidate_ts

    def _derive_title_and_type(
        self,
        window: WindowFeatures,
        detection_method: str,
        rule_output: RuleDetectionOutput,
    ) -> tuple[str, str]:
        """Derive consistent, descriptive title and incident_type from detection evidence."""
        rules = rule_output.triggered_rules

        if RULE_R001 in rules and RULE_R002 in rules:
            return (
                f"SSH Brute Force and Compromise Attempt from {window.source_ip}",
                "brute_force_with_compromise",
            )
        elif RULE_R001 in rules:
            return (
                f"SSH Brute Force Attack from {window.source_ip}",
                "brute_force",
            )
        elif RULE_R002 in rules:
            return (
                f"Suspicious Successful SSH Authentication from {window.source_ip}",
                "suspicious_login",
            )
        elif detection_method == "hybrid":
            return (
                f"Hybrid Suspicious SSH Activity from {window.source_ip}",
                "hybrid_anomaly",
            )
        else:
            return (
                f"Anomalous SSH Volume Activity from {window.source_ip}",
                "statistical_anomaly",
            )

    def _associate_window_events(
        self,
        session: Session,
        incident: Incident,
        window: WindowFeatures,
        seen_associations: set[tuple[uuid.UUID, uuid.UUID]],
    ) -> int:
        """Link SSH events from the suspicious window to the incident without duplicates."""
        new_links = 0
        for evt_id in window.event_ids:
            if not isinstance(evt_id, uuid.UUID):
                try:
                    evt_id = uuid.UUID(str(evt_id))
                except Exception:
                    continue

            pair = (incident.incident_id, evt_id)
            if pair in seen_associations:
                continue

            # Query existing association in database to prevent primary key conflicts
            exists = session.scalar(
                select(func.count())
                .select_from(IncidentEvent)
                .where(
                    IncidentEvent.incident_id == incident.incident_id,
                    IncidentEvent.event_id == evt_id,
                )
            )

            if exists == 0:
                assoc = IncidentEvent(
                    incident_id=incident.incident_id,
                    event_id=evt_id,
                    linked_at=datetime.now(timezone.utc),
                )
                session.add(assoc)
                seen_associations.add(pair)
                new_links += 1

        return new_links
