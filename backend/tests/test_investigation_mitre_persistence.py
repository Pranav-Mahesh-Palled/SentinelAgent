"""Integration tests for MITRE ATT&CK mapping persistence and evidence lifecycle (Task 8D).

Tests:
1. Valid proposal persistence via persist_validated_mitre_mappings into PostgreSQL.
2. Deduplication and idempotency: repeated calls reuse existing EvidenceItem.
3. Provenance set registration: technique_id in mitre_techniques, evidence_id in evidence_items.
4. Anti-circularity: EvidenceItem's own ID never in supporting references.
5. Empty proposals handling (returns empty tuple without DB writes).
6. State validation: terminated investigation rejects persistence.
7. Non-existent investigation rejection.
8. Transaction rollback on validation error: provenance set and DB remain pristine.
9. Integration with InvestigationReport: persisting report with mitre_attack_mappings.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import uuid
import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    ConfirmedFinding,
    InvestigationReport,
    Observation,
    SSHEventRecord,
)
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    InvestigationNotFoundError,
    InvestigationService,
    InvestigationTerminatedError,
)
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import (
    EventRetrievalMetadata,
    MitreMappingEngine,
    compute_mapping_uuid5,
)
from app.services.mitre_mapping_validator import MitreMappingValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOGUE_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "mitre" / "mitre_attack_enterprise_v20_1.json"


@pytest.fixture(scope="module")
def catalogue_service() -> MitreCatalogueService:
    """Provides real MitreCatalogueService backed by compiled JSON."""
    if not CATALOGUE_PATH.exists():
        pytest.skip(f"Catalogue file not found at {CATALOGUE_PATH}")
    return MitreCatalogueService.from_file(CATALOGUE_PATH)


@pytest.fixture
def db_engine():
    """Provides a live database engine."""
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    """Provides a sessionmaker bound to the live database engine."""
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def investigation_service(session_factory):
    """Provides an InvestigationService instance configured with session_factory."""
    return InvestigationService(session_factory=session_factory)


@pytest.fixture
def cleanup_tracker(db_engine):
    """Tracks created database entities and deletes them in reverse FK order upon teardown."""
    tracker = {
        "tool_runs": [],
        "evidence_items": [],
        "investigations": [],
        "incident_events": [],
        "detection_results": [],
        "incidents": [],
        "ssh_events": [],
    }
    yield tracker

    with db_engine.begin() as conn:
        if tracker["tool_runs"]:
            conn.execute(
                delete(InvestigationToolRun).where(
                    InvestigationToolRun.tool_run_id.in_(tracker["tool_runs"])
                )
            )
        if tracker["evidence_items"]:
            conn.execute(
                delete(EvidenceItem).where(
                    EvidenceItem.evidence_id.in_(tracker["evidence_items"])
                )
            )
        if tracker["investigations"]:
            conn.execute(
                delete(InvestigationToolRun).where(
                    InvestigationToolRun.investigation_id.in_(tracker["investigations"])
                )
            )
            conn.execute(
                delete(EvidenceItem).where(
                    EvidenceItem.investigation_id.in_(tracker["investigations"])
                )
            )
            conn.execute(
                delete(Investigation).where(
                    Investigation.investigation_id.in_(tracker["investigations"])
                )
            )
        if tracker["incident_events"]:
            conn.execute(
                delete(IncidentEvent).where(
                    IncidentEvent.incident_id.in_(tracker["incident_events"])
                )
            )
        if tracker["detection_results"]:
            conn.execute(
                delete(DetectionResult).where(
                    DetectionResult.result_id.in_(tracker["detection_results"])
                )
            )
        if tracker["incidents"]:
            conn.execute(
                delete(Incident).where(
                    Incident.incident_id.in_(tracker["incidents"])
                )
            )
        if tracker["ssh_events"]:
            conn.execute(
                delete(SSHEvent).where(
                    SSHEvent.event_id.in_(tracker["ssh_events"])
                )
            )


def create_test_incident(
    session: Session,
    cleanup_tracker: dict,
    source_ip: str = "192.0.2.100",
) -> Incident:
    """Helper to insert an Incident record tracked for cleanup."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        incident_id=uuid.uuid4(),
        title="MITRE Mapping Persistence Test Incident",
        incident_type="brute_force",
        source_ip=source_ip,
        severity="medium",
        detection_method="rule",
        status="open",
        investigation_status="pending",
        created_at=now,
        updated_at=now,
    )
    session.add(inc)
    session.flush()
    cleanup_tracker["incidents"].append(inc.incident_id)
    return inc


def create_test_ssh_event(
    session: Session,
    cleanup_tracker: dict,
    incident_id: uuid.UUID,
    source_ip: str = "192.0.2.100",
    result: str = "failure",
    timestamp: datetime | None = None,
) -> SSHEvent:
    """Helper to insert an SSHEvent and link it to Incident via IncidentEvent."""
    now = timestamp or datetime.now(timezone.utc)
    ev = SSHEvent(
        event_id=uuid.uuid4(),
        event_timestamp=now,
        source_ip=source_ip,
        username="admin",
        authentication_result=result,
        event_type="password",
        ingested_at=now,
    )
    session.add(ev)
    session.flush()
    cleanup_tracker["ssh_events"].append(ev.event_id)

    ie = IncidentEvent(incident_id=incident_id, event_id=ev.event_id)
    session.add(ie)
    session.flush()
    cleanup_tracker["incident_events"].append(incident_id)
    return ev


class TestInvestigationMitrePersistence:
    """Integration suite verifying MITRE mapping validation and evidence persistence."""

    def test_persist_validated_mitre_mappings_success(
        self,
        investigation_service: InvestigationService,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify successful validation and persistence of candidate proposal as EvidenceItem."""
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker, source_ip="192.0.2.77")
            ev1 = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, source_ip="192.0.2.77", timestamp=now - timedelta(minutes=2))
            ev2 = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, source_ip="192.0.2.77", timestamp=now - timedelta(minutes=1))
            session.commit()
            inc_id = inc.incident_id
            ev_id1 = ev1.event_id
            ev_id2 = ev2.event_id

        inv_id = investigation_service.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        investigation_service.start_investigation(inv_id)

        # Set up provenance set with authorized SSH events
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id1)
        prov_set.add_ssh_event(ev_id2)

        refs = [f"ssh_events/{ev_id1}", f"ssh_events/{ev_id2}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic_ids=["TA0006"],
            tactic_names=["Credential Access"],
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=sorted(refs),
            event_ids=sorted([ev_id1, ev_id2]),
            window_start=now - timedelta(minutes=2),
            window_end=now - timedelta(minutes=1),
            rationale="Observed SSH brute force failure pattern.",
            catalogue_version=catalogue_service.version,
        )

        persisted_tuple = investigation_service.persist_validated_mitre_mappings(
            investigation_id=inv_id,
            proposals=[proposal],
            provenance_set=prov_set,
            catalogue=catalogue_service,
        )

        assert len(persisted_tuple) == 1
        persisted = persisted_tuple[0]
        assert isinstance(persisted, MitreAttackMapping)
        assert persisted.mapping_id == mapping_id
        assert persisted.evidence_item_id is not None
        assert persisted.technique_id == "T1110"
        assert persisted.technique_name == "Brute Force"

        # Check provenance registration
        assert "T1110" in prov_set.mitre_techniques
        assert persisted.evidence_item_id in prov_set.evidence_items

        # Anti-circularity: evidence_item_id is NOT in supporting_references
        assert f"evidence_items/{persisted.evidence_item_id}" not in persisted.supporting_references
        assert all(r.startswith("ssh_events/") for r in persisted.supporting_references)

        # Query database directly to verify EvidenceItem row
        with session_factory() as session:
            ev_row = session.execute(
                select(EvidenceItem)
                .where(EvidenceItem.evidence_id == persisted.evidence_item_id)
            ).scalar_one()

            assert ev_row.investigation_id == inv_id
            assert ev_row.evidence_type == "mitre_technique"
            assert ev_row.source_reference == "mitre/T1110"
            assert ev_row.title == "MITRE ATT&CK T1110: Brute Force"
            assert ev_row.description == proposal.rationale
            assert ev_row.event_id is None  # Mappings ground across multiple events
            assert ev_row.evidence_data["mapping_id"] == str(mapping_id)
            assert ev_row.evidence_data["rule_id"] == "MAP-SSH-001"
            assert ev_row.evidence_data["confidence"] == "medium"
            assert ev_row.evidence_data["evidence_item_id"] == str(persisted.evidence_item_id)

    def test_idempotency_and_deduplication(
        self,
        investigation_service: InvestigationService,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify calling persist_validated_mitre_mappings multiple times reuses existing EvidenceItem."""
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker, source_ip="192.0.2.88")
            ev = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, source_ip="192.0.2.88", timestamp=now)
            session.commit()
            inc_id = inc.incident_id
            ev_id = ev.event_id

        inv_id = investigation_service.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        investigation_service.start_investigation(inv_id)

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id)

        refs = [f"ssh_events/{ev_id}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Observed SSH brute force pattern.",
            catalogue_version=catalogue_service.version,
        )

        # First call: persists and creates row
        first_tuple = investigation_service.persist_validated_mitre_mappings(
            investigation_id=inv_id,
            proposals=[proposal],
            provenance_set=prov_set,
            catalogue=catalogue_service,
        )
        assert len(first_tuple) == 1
        first_item_id = first_tuple[0].evidence_item_id

        # Second call with identical proposal: reuses row
        second_tuple = investigation_service.persist_validated_mitre_mappings(
            investigation_id=inv_id,
            proposals=[proposal],
            provenance_set=prov_set,
            catalogue=catalogue_service,
        )
        assert len(second_tuple) == 1
        second_item_id = second_tuple[0].evidence_item_id

        assert first_item_id == second_item_id

        # Verify only 1 EvidenceItem row exists in DB
        with session_factory() as session:
            count = session.execute(
                select(EvidenceItem)
                .where(
                    EvidenceItem.investigation_id == inv_id,
                    EvidenceItem.evidence_type == "mitre_technique",
                )
            ).scalars().all()
            assert len(count) == 1

    def test_empty_proposals_returns_empty_tuple(
        self,
        investigation_service: InvestigationService,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify empty proposals sequence cleanly returns empty tuple with no database queries."""
        prov_set = AuthorizedProvenanceSet()
        inv_id = uuid.uuid4()
        res = investigation_service.persist_validated_mitre_mappings(
            investigation_id=inv_id,
            proposals=[],
            provenance_set=prov_set,
            catalogue=catalogue_service,
        )
        assert res == ()

    def test_reject_persistence_on_terminated_investigation(
        self,
        investigation_service: InvestigationService,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify persistence is rejected if parent investigation is not in_progress."""
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker)
            ev = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, timestamp=now)
            session.commit()
            inc_id = inc.incident_id
            ev_id = ev.event_id

        inv_id = investigation_service.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        # Fail the investigation so it transitions to failed status
        investigation_service.start_investigation(inv_id)
        investigation_service.fail_investigation(inv_id, "TEST_ERR", "Test failure")

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id)
        refs = [f"ssh_events/{ev_id}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )
        prop = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Observed brute force attempt.",
            catalogue_version=catalogue_service.version,
        )

        with pytest.raises(InvestigationTerminatedError, match="is in status 'failed'"):
            investigation_service.persist_validated_mitre_mappings(
                investigation_id=inv_id,
                proposals=[prop],
                provenance_set=prov_set,
                catalogue=catalogue_service,
            )

    def test_reject_persistence_on_nonexistent_investigation(
        self,
        investigation_service: InvestigationService,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify non-existent investigation ID raises InvestigationNotFoundError."""
        now = datetime.now(timezone.utc)
        fake_inv_id = uuid.uuid4()
        fake_ev_id = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(fake_ev_id)
        refs = [f"ssh_events/{fake_ev_id}"]
        mapping_id = compute_mapping_uuid5(
            fake_inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )
        prop = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[fake_ev_id],
            window_start=now,
            window_end=now,
            rationale="Observed brute force attempt.",
            catalogue_version=catalogue_service.version,
        )

        with pytest.raises(InvestigationNotFoundError, match="not found"):
            investigation_service.persist_validated_mitre_mappings(
                investigation_id=fake_inv_id,
                proposals=[prop],
                provenance_set=prov_set,
                catalogue=catalogue_service,
            )

    def test_transaction_rollback_on_validation_failure(
        self,
        investigation_service: InvestigationService,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify that when any proposal fails validation, zero items are persisted and provenance set is unmutated."""
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker)
            ev = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, timestamp=now)
            session.commit()
            inc_id = inc.incident_id
            ev_id = ev.event_id

        inv_id = investigation_service.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        investigation_service.start_investigation(inv_id)

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id)

        refs = [f"ssh_events/{ev_id}"]
        valid_mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )

        # 1. Valid proposal
        valid_prop = MitreCandidateProposal(
            mapping_id=valid_mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Valid proposal rationale here.",
            catalogue_version=catalogue_service.version,
        )

        # 2. Invalid proposal (disallowed status 'supported')
        invalid_prop = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.SUPPORTED,  # Disallowed
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Invalid proposal rationale.",
            catalogue_version=catalogue_service.version,
        )

        with pytest.raises(MitreMappingValidationError):
            investigation_service.persist_validated_mitre_mappings(
                investigation_id=inv_id,
                proposals=[valid_prop, invalid_prop],
                provenance_set=prov_set,
                catalogue=catalogue_service,
            )

        # Verify database has 0 EvidenceItem records
        with session_factory() as session:
            items = session.execute(
                select(EvidenceItem).where(EvidenceItem.investigation_id == inv_id)
            ).scalars().all()
            assert len(items) == 0

        # Verify provenance set has not been mutated
        assert "T1110" not in prov_set.mitre_techniques
        assert len(prov_set.evidence_items) == 0

    def test_complete_investigation_with_mitre_attack_mappings(
        self,
        investigation_service: InvestigationService,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify full investigation completion storing InvestigationReport with mitre_attack_mappings."""
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker, source_ip="192.0.2.222")
            ev = create_test_ssh_event(session, cleanup_tracker, inc.incident_id, source_ip="192.0.2.222", timestamp=now)
            session.commit()
            inc_id = inc.incident_id
            ev_id = ev.event_id

        inv_id = investigation_service.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        investigation_service.start_investigation(inv_id)

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id)

        refs = [f"ssh_events/{ev_id}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )

        prop = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Observed brute force attempt.",
            catalogue_version=catalogue_service.version,
        )

        persisted_tuple = investigation_service.persist_validated_mitre_mappings(
            investigation_id=inv_id,
            proposals=[prop],
            provenance_set=prov_set,
            catalogue=catalogue_service,
        )

        report = InvestigationReport(
            summary="Investigation verified brute force activity.",
            sufficient_evidence=True,
            confirmed_findings=[
                ConfirmedFinding(
                    finding_id="FIND-01",
                    title="SSH Brute Force",
                    description="Multiple authentication failures observed.",
                    evidence_references=[f"ssh_events/{ev_id}"],
                    confidence="high",
                )
            ],
            observations=[
                Observation(
                    observation_id="OBS-01",
                    description="Brute force mapping confirmed.",
                    evidence_references=[f"ssh_events/{ev_id}"],
                )
            ],
            mitre_attack_mappings=list(persisted_tuple),
        )

        completed_dto = investigation_service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            provenance_set=prov_set,
        )

        assert completed_dto.status == "completed"
        assert completed_dto.investigation_report is not None
        report_data = completed_dto.investigation_report
        assert "mitre_attack_mappings" in report_data
        assert len(report_data["mitre_attack_mappings"]) == 1
        stored_mapping = report_data["mitre_attack_mappings"][0]
        assert stored_mapping["mapping_id"] == str(mapping_id)
        assert stored_mapping["technique_id"] == "T1110"
        assert stored_mapping["technique_name"] == "Brute Force"
        assert stored_mapping["evidence_item_id"] == str(persisted_tuple[0].evidence_item_id)

    def test_concurrent_mitre_mapping_persistence(
        self,
        session_factory: sessionmaker,
        cleanup_tracker: dict,
        catalogue_service: MitreCatalogueService,
    ):
        """Verify two simultaneous attempts to persist the same mapping across independent sessions.

        Expected behavior:
        - Both threads complete safely.
        - Strict parent-first locking prevents deadlocks or race conditions.
        - Exactly one logical EvidenceItem row is persisted.
        - Both workers resolve to identical mapping_id and evidence_item_id.
        - No duplicate EvidenceItem rows appear.
        - No provenance corruption occurs in either worker.
        - Investigation status remains in_progress.
        """
        now = datetime.now(timezone.utc)
        with session_factory() as session:
            inc = create_test_incident(session, cleanup_tracker, source_ip="192.0.2.199")
            ev = create_test_ssh_event(
                session, cleanup_tracker, inc.incident_id, source_ip="192.0.2.199", timestamp=now
            )
            session.commit()
            inc_id = inc.incident_id
            ev_id = ev.event_id

        init_svc = InvestigationService(session_factory=session_factory)
        inv_id = init_svc.create_investigation(inc_id)
        cleanup_tracker["investigations"].append(inv_id)
        init_svc.start_investigation(inv_id)

        refs = [f"ssh_events/{ev_id}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue_service.version, "MAP-SSH-001", "T1110", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=refs,
            event_ids=[ev_id],
            window_start=now,
            window_end=now,
            rationale="Observed SSH brute force pattern in concurrent test.",
            catalogue_version=catalogue_service.version,
        )

        barrier = threading.Barrier(2)
        results: list[tuple[MitreAttackMapping, ...]] = []
        errors: list[Exception] = []
        worker_prov_sets: list[AuthorizedProvenanceSet] = []
        lock = threading.Lock()

        def worker():
            svc = InvestigationService(session_factory=session_factory)
            prov = AuthorizedProvenanceSet()
            prov.add_ssh_event(ev_id)
            barrier.wait()
            try:
                persisted = svc.persist_validated_mitre_mappings(
                    investigation_id=inv_id,
                    proposals=[proposal],
                    provenance_set=prov,
                    catalogue=catalogue_service,
                )
                with lock:
                    results.append(persisted)
                    worker_prov_sets.append(prov)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        # Both workers must complete without error
        assert len(errors) == 0
        assert len(results) == 2

        # Both workers return exactly one mapping with identical evidence_item_id
        res1, res2 = results[0], results[1]
        assert len(res1) == 1
        assert len(res2) == 1
        assert res1[0].mapping_id == mapping_id
        assert res2[0].mapping_id == mapping_id
        assert res1[0].evidence_item_id == res2[0].evidence_item_id

        # Verify only 1 EvidenceItem row exists in PostgreSQL
        with session_factory() as session:
            rows = session.execute(
                select(EvidenceItem).where(
                    EvidenceItem.investigation_id == inv_id,
                    EvidenceItem.evidence_type == "mitre_technique",
                )
            ).scalars().all()
            assert len(rows) == 1
            assert rows[0].evidence_id == res1[0].evidence_item_id

            # Verify investigation status remains in_progress
            inv_row = session.execute(
                select(Investigation).where(Investigation.investigation_id == inv_id)
            ).scalar_one()
            assert inv_row.status == "in_progress"

        # Verify provenance set in both workers was properly registered
        for prov in worker_prov_sets:
            assert "T1110" in prov.mitre_techniques
            assert res1[0].evidence_item_id in prov.evidence_items

