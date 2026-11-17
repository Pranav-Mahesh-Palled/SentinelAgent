"""Unit tests for MitreMappingValidator (Task 8D).

Tests:
- Catalogue validation (existence, deprecation, revocation).
- Approved rule-to-technique matrix.
- Approved status and confidence matrices.
- Anti-circularity and canonical reference validation.
- Authorized provenance verification.
- Telemetry bounds and IP consistency checks.
- Complete coverage check for MAP-SSH-003.
- Deterministic UUID5 fingerprint verification and tamper rejection.
- Authoritative metadata overwrite from MitreCatalogueService.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock
import uuid
import pytest

from app.schemas.investigation import SSHEventRecord
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.investigation_service import AuthorizedProvenanceSet
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import (
    EventRetrievalMetadata,
    MitreMappingEngine,
    compute_mapping_uuid5,
)
from app.services.mitre_mapping_validator import (
    APPROVED_RULE_CONFIDENCES,
    APPROVED_RULE_STATUSES,
    APPROVED_RULE_TECHNIQUES,
    MitreMappingValidationError,
    MitreMappingValidator,
)

# Root directory of SentinelAgent
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOGUE_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "mitre" / "mitre_attack_enterprise_v20_1.json"


@pytest.fixture(scope="module")
def catalogue() -> MitreCatalogueService:
    """Fixture providing initialized real catalogue service."""
    if not CATALOGUE_PATH.exists():
        pytest.skip(f"Catalogue not found at {CATALOGUE_PATH}")
    return MitreCatalogueService.from_file(CATALOGUE_PATH)


@pytest.fixture
def validator(catalogue: MitreCatalogueService) -> MitreMappingValidator:
    """Fixture providing validator backed by real catalogue."""
    return MitreMappingValidator(catalogue=catalogue)


def make_test_event(
    event_id: uuid.UUID,
    timestamp: datetime,
    source_ip: str = "192.0.2.10",
    username: str = "admin",
    result: str = "failure",
) -> SSHEventRecord:
    """Helper to construct SSHEventRecord."""
    return SSHEventRecord(
        event_id=event_id,
        event_timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        authentication_result=result,
        event_type="password",
        ingested_at=timestamp,
    )


class TestMitreMappingValidator:
    """Suite testing MitreMappingValidator rules and boundaries."""

    def test_map_ssh_001_success(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test valid MAP-SSH-001 proposal passes validation."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ev_id1 = uuid.uuid4()
        ev_id2 = uuid.uuid4()
        refs = [f"ssh_events/{ev_id1}", f"ssh_events/{ev_id2}"]

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(ev_id1)
        prov_set.add_ssh_event(ev_id2)

        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue.version, "MAP-SSH-001", "T1110", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Untrusted Name",  # Will be overwritten
            tactic_ids=["TA0006"],
            tactic_names=["Credential Access"],
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=sorted(refs),
            event_ids=sorted([ev_id1, ev_id2]),
            window_start=now - timedelta(minutes=5),
            window_end=now,
            rationale="Observed 50 consecutive failed authentications from 192.0.2.10 within 5 minutes.",
            catalogue_version=catalogue.version,
        )

        mapping = validator.validate_proposal(
            proposal=proposal,
            provenance_set=prov_set,
            investigation_id=inv_id,
        )

        assert isinstance(mapping, MitreAttackMapping)
        assert mapping.mapping_id == mapping_id
        assert mapping.evidence_item_id is None
        assert mapping.rule_id == "MAP-SSH-001"
        assert mapping.technique_id == "T1110"
        # Authoritative name from v20.1 catalogue
        assert mapping.technique_name == "Brute Force"
        assert mapping.catalogue_version == catalogue.version
        assert mapping.confidence == MitreConfidenceLevel.HIGH
        assert mapping.mapping_status == MitreMappingStatus.CANDIDATE

    def test_map_ssh_002_success(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test valid MAP-SSH-002 proposal (hypothesis, T1110.003)."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ev_ids = [uuid.uuid4() for _ in range(3)]
        refs = [f"ssh_events/{eid}" for eid in ev_ids]

        prov_set = AuthorizedProvenanceSet()
        for eid in ev_ids:
            prov_set.add_ssh_event(eid)

        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue.version, "MAP-SSH-002", "T1110.003", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-002",
            technique_id="T1110.003",
            technique_name="Password Spraying",
            tactic_ids=["TA0006"],
            tactic_names=["Credential Access"],
            mapping_status=MitreMappingStatus.HYPOTHESIS,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=sorted(refs),
            event_ids=sorted(ev_ids),
            window_start=now - timedelta(minutes=15),
            window_end=now,
            rationale="Observed failed attempts across multiple distinct usernames from single IP.",
            catalogue_version=catalogue.version,
        )

        mapping = validator.validate_proposal(proposal=proposal, provenance_set=prov_set, investigation_id=inv_id)
        assert mapping.rule_id == "MAP-SSH-002"
        assert mapping.technique_id == "T1110.003"
        assert mapping.mapping_status == MitreMappingStatus.HYPOTHESIS

    def test_map_ssh_003_success(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test valid MAP-SSH-003 proposal (candidate, low confidence, T1078)."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ev_ids = [uuid.uuid4() for _ in range(6)]
        refs = [f"ssh_events/{eid}" for eid in ev_ids]

        prov_set = AuthorizedProvenanceSet()
        for eid in ev_ids:
            prov_set.add_ssh_event(eid)

        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue.version, "MAP-SSH-003", "T1078", refs
        )

        proposal = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-003",
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic_ids=["TA0001"],
            tactic_names=["Initial Access"],
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.LOW,
            supporting_references=sorted(refs),
            event_ids=sorted(ev_ids),
            window_start=now - timedelta(hours=1),
            window_end=now,
            rationale="Observed successful authentication following 5 failed attempts within 2 hours.",
            catalogue_version=catalogue.version,
        )

        # Passes when coverage_complete == True and window completely covers required 2-hour interval
        retrieval_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=now - timedelta(hours=3),
            window_end=now,
        )
        mapping = validator.validate_proposal(
            proposal=proposal,
            provenance_set=prov_set,
            investigation_id=inv_id,
            retrieval_metadata=retrieval_meta,
        )
        assert mapping.rule_id == "MAP-SSH-003"
        assert mapping.technique_id == "T1078"
        assert mapping.confidence == MitreConfidenceLevel.LOW

    def test_reject_unknown_rule_id(self, validator: MitreMappingValidator):
        """Test rejection of unknown rule identifier."""
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        proposal = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-999",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )

        with pytest.raises(MitreMappingValidationError, match="Unknown or unapproved mapping rule"):
            validator.validate_proposal(proposal=proposal, provenance_set=prov_set)

    def test_reject_mismatched_technique_id(self, validator: MitreMappingValidator):
        """Test rejection when rule does not match approved technique (e.g. MAP-SSH-001 with T1078)."""
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        proposal = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1078",  # MAP-SSH-001 is restricted to T1110
            technique_name="Valid Accounts",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )

        with pytest.raises(MitreMappingValidationError, match="restricted to technique 'T1110'"):
            validator.validate_proposal(proposal=proposal, provenance_set=prov_set)

    def test_reject_disallowed_status_supported(self, validator: MitreMappingValidator):
        """Test rejection of status 'supported' across all rules."""
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        proposal = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.SUPPORTED,  # Strictly forbidden
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )

        with pytest.raises(MitreMappingValidationError, match="does not allow status 'supported'"):
            validator.validate_proposal(proposal=proposal, provenance_set=prov_set)

    def test_reject_disallowed_confidence(self, validator: MitreMappingValidator):
        """Test rejection of invalid confidence levels per rule."""
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        # 1. MAP-SSH-001 requires medium or high; test low
        p1 = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.LOW,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )
        with pytest.raises(MitreMappingValidationError, match="does not allow confidence 'low'"):
            validator.validate_proposal(proposal=p1, provenance_set=prov_set)

        # 2. MAP-SSH-003 requires low only; test medium
        p3 = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-003",
            technique_id="T1078",
            technique_name="Valid Accounts",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )
        with pytest.raises(MitreMappingValidationError, match="does not allow confidence 'medium'"):
            validator.validate_proposal(proposal=p3, provenance_set=prov_set)

    def test_reject_nonexistent_or_deprecated_technique(self):
        """Test rejection when technique is not in catalogue or is marked deprecated/revoked."""
        mock_catalogue = MagicMock()
        mock_catalogue.version = "20.1"
        mock_catalogue.get_technique.return_value = None

        validator = MitreMappingValidator(catalogue=mock_catalogue)
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        p = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )

        with pytest.raises(MitreMappingValidationError, match="was not found in MITRE ATT&CK catalogue"):
            validator.validate_proposal(proposal=p, provenance_set=prov_set)

        # Deprecated technique test
        mock_tech = MagicMock()
        mock_tech.deprecated = True
        mock_tech.revoked = False
        mock_catalogue.get_technique.return_value = mock_tech

        with pytest.raises(MitreMappingValidationError, match="marked as deprecated"):
            validator.validate_proposal(proposal=p, provenance_set=prov_set)

        # Revoked technique test
        mock_tech.deprecated = False
        mock_tech.revoked = True
        with pytest.raises(MitreMappingValidationError, match="marked as revoked"):
            validator.validate_proposal(proposal=p, provenance_set=prov_set)

    def test_anti_circularity_rejected(self, validator: MitreMappingValidator):
        """Test anti-circularity: references with prefix other than 'ssh_events' are rejected."""
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()

        # Try grounding MITRE mapping in another mitre technique
        p_mitre = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=["mitre/T1110"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )
        with pytest.raises(MitreMappingValidationError, match="Anti-circularity violation"):
            validator.validate_proposal(proposal=p_mitre, provenance_set=prov_set)

        # Try grounding in prior evidence_items
        p_ev = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"evidence_items/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )
        with pytest.raises(MitreMappingValidationError, match="Anti-circularity violation"):
            validator.validate_proposal(proposal=p_ev, provenance_set=prov_set)

    def test_reject_unauthorized_provenance(self, validator: MitreMappingValidator):
        """Test rejection when referenced SSH event UUID is not in AuthorizedProvenanceSet."""
        now = datetime.now(timezone.utc)
        authorized_eid = uuid.uuid4()
        unauthorized_eid = uuid.uuid4()

        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(authorized_eid)
        # unauthorized_eid is NOT added to prov_set

        p = MitreCandidateProposal(
            mapping_id=uuid.uuid4(),
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"ssh_events/{unauthorized_eid}"],
            event_ids=[unauthorized_eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version="20.1",
        )

        with pytest.raises(MitreMappingValidationError, match="Unauthorized supporting reference"):
            validator.validate_proposal(proposal=p, provenance_set=prov_set)

    def test_reject_tampered_mapping_id(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test deterministic UUID5 fingerprint verification catches altered mapping_id."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        # Intentionally wrong mapping_id
        wrong_id = uuid.uuid4()

        p = MitreCandidateProposal(
            mapping_id=wrong_id,
            rule_id="MAP-SSH-001",
            technique_id="T1110",
            technique_name="Brute Force",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.HIGH,
            supporting_references=[f"ssh_events/{eid}"],
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Some behavioral description here.",
            catalogue_version=catalogue.version,
        )

        with pytest.raises(MitreMappingValidationError, match="Deterministic UUID5 fingerprint mismatch"):
            validator.validate_proposal(proposal=p, provenance_set=prov_set, investigation_id=inv_id)

    def test_map_ssh_003_incomplete_coverage_safeguard(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test MAP-SSH-003 fails validation when retrieval_metadata.coverage_complete is False."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        refs = [f"ssh_events/{eid}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue.version, "MAP-SSH-003", "T1078", refs
        )

        p = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-003",
            technique_id="T1078",
            technique_name="Valid Accounts",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.LOW,
            supporting_references=refs,
            event_ids=[eid],
            window_start=now,
            window_end=now,
            rationale="Observed valid account access after failures.",
            catalogue_version=catalogue.version,
        )

        # Incomplete coverage
        incomplete_meta = EventRetrievalMetadata(coverage_complete=False)
        with pytest.raises(MitreMappingValidationError, match="requires complete 2-hour preceding coverage"):
            validator.validate_proposal(
                proposal=p,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=incomplete_meta,
            )

    def test_end_to_end_behavioral_regeneration_validation(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test full behavioral regeneration with MitreMappingEngine and telemetry."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        # Generate 35 brute-force failure events from 192.0.2.55 within 5 minutes (>= 30 qualifies for HIGH confidence)
        events = [
            make_test_event(
                event_id=uuid.uuid4(),
                timestamp=now - timedelta(seconds=200 - i * 5),
                source_ip="192.0.2.55",
                username="root",
                result="failure",
            )
            for i in range(35)
        ]

        engine = MitreMappingEngine(catalogue=catalogue)
        proposals = engine.evaluate(investigation_id=inv_id, authorized_ssh_events=events)
        assert len(proposals) == 1
        prop = proposals[0]
        assert prop.rule_id == "MAP-SSH-001"
        assert prop.confidence == MitreConfidenceLevel.HIGH

        prov_set = AuthorizedProvenanceSet()
        for ev in events:
            prov_set.add_ssh_event(ev.event_id)

        # 1. Valid proposal with authorized_ssh_events and investigation_id passes
        mapping = validator.validate_proposal(
            proposal=prop,
            provenance_set=prov_set,
            investigation_id=inv_id,
            authorized_ssh_events=events,
        )
        assert mapping.technique_id == "T1110"

        # 2. Tampered confidence (e.g. downgraded to medium when engine evaluated high) fails
        tampered_prop = prop.model_copy(update={"confidence": MitreConfidenceLevel.MEDIUM})
        with pytest.raises(MitreMappingValidationError, match="Behavioral confidence mismatch"):
            validator.validate_proposal(
                proposal=tampered_prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

    def test_complete_proposal_tampering_protections(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test exhaustive proposal tampering detection across all 11 fields."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        events = [
            make_test_event(
                event_id=uuid.uuid4(),
                timestamp=now - timedelta(seconds=200 - i * 5),
                source_ip="192.0.2.55",
                username="root",
                result="failure",
            )
            for i in range(35)
        ]

        engine = MitreMappingEngine(catalogue=catalogue)
        prop = engine.evaluate(investigation_id=inv_id, authorized_ssh_events=events)[0]

        prov_set = AuthorizedProvenanceSet()
        for ev in events:
            prov_set.add_ssh_event(ev.event_id)

        # 1. Altered rule ID
        with pytest.raises(MitreMappingValidationError, match="Unknown or unapproved mapping rule"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"rule_id": "MAP-SSH-099"}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 2. Altered technique ID
        with pytest.raises(MitreMappingValidationError, match="restricted to technique"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"technique_id": "T1078"}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 3. Altered supporting references
        foreign_id = uuid.uuid4()
        prov_set.add_ssh_event(foreign_id)
        with pytest.raises(MitreMappingValidationError, match="Mismatch between supporting_references UUIDs and event_ids|Supporting references mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"supporting_references": [f"ssh_events/{foreign_id}"]}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 4. Altered event UUIDs
        with pytest.raises(MitreMappingValidationError, match="Mismatch between supporting_references UUIDs and event_ids"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"event_ids": [foreign_id]}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 5. Altered mapping status
        with pytest.raises(MitreMappingValidationError, match="does not allow status 'hypothesis'|Behavioral status mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"mapping_status": MitreMappingStatus.HYPOTHESIS}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 6. Altered window start
        with pytest.raises(MitreMappingValidationError, match="Window start mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"window_start": now - timedelta(hours=5)}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 7. Altered window end
        with pytest.raises(MitreMappingValidationError, match="Window end mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"window_end": now + timedelta(hours=1)}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 8. Altered UUID5 mapping identifier
        fake_uuid = uuid.uuid4()
        with pytest.raises(MitreMappingValidationError, match="Deterministic UUID5 fingerprint mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"mapping_id": fake_uuid}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 9. Altered rationale
        with pytest.raises(MitreMappingValidationError, match="Behavioral rationale tampering detected"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"rationale": "Tampered rationale text for this proposal."}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 10. Altered catalogue version
        with pytest.raises(MitreMappingValidationError, match="Catalogue version mismatch"):
            validator.validate_proposal(
                proposal=prop.model_copy(update={"catalogue_version": "99.9"}),
                provenance_set=prov_set,
                investigation_id=inv_id,
                authorized_ssh_events=events,
            )

        # 11. Fabricated technique names and tactics are safely overwritten
        spoofed_prop = prop.model_copy(update={
            "technique_name": "SPOOFED_NAME",
            "tactic_ids": ["TA9999"],
            "tactic_names": ["Fake Tactic"],
        })
        repaired_mapping = validator.validate_proposal(
            proposal=spoofed_prop,
            provenance_set=prov_set,
            investigation_id=inv_id,
            authorized_ssh_events=events,
        )
        assert repaired_mapping.technique_name == "Brute Force"
        assert "TA9999" not in repaired_mapping.tactic_ids
        assert "Fake Tactic" not in repaired_mapping.tactic_names
        assert "TA0006" in repaired_mapping.tactic_ids

    def test_map_ssh_003_detailed_coverage_safeguards(
        self, validator: MitreMappingValidator, catalogue: MitreCatalogueService
    ):
        """Test exhaustive MAP-SSH-003 coverage safeguards (missing, truncated, boundaries, timezone)."""
        inv_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        eid = uuid.uuid4()
        prov_set = AuthorizedProvenanceSet()
        prov_set.add_ssh_event(eid)

        refs = [f"ssh_events/{eid}"]
        mapping_id = compute_mapping_uuid5(
            inv_id, catalogue.version, "MAP-SSH-003", "T1078", refs
        )
        prop = MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id="MAP-SSH-003",
            technique_id="T1078",
            technique_name="Valid Accounts",
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=MitreConfidenceLevel.LOW,
            supporting_references=refs,
            event_ids=[eid],
            window_start=now - timedelta(hours=1),
            window_end=now,
            rationale="Observed valid account access after failures.",
            catalogue_version=catalogue.version,
        )

        # 1. Missing retrieval metadata entirely
        with pytest.raises(MitreMappingValidationError, match="requires retrieval metadata"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=None,
            )

        # 2. Truncated retrieval
        trunc_meta = EventRetrievalMetadata(
            truncated=True,
            coverage_complete=True,
            window_start=now - timedelta(hours=3),
            window_end=now,
        )
        with pytest.raises(MitreMappingValidationError, match="retrieval was truncated"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=trunc_meta,
            )

        # 3. Missing window boundaries
        no_bounds_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=None,
            window_end=None,
        )
        with pytest.raises(MitreMappingValidationError, match="window boundaries are missing"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=no_bounds_meta,
            )

        # 4. Naive window boundaries
        naive_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=datetime.now(),  # naive
            window_end=now,
        )
        with pytest.raises(MitreMappingValidationError, match="must be timezone-aware"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=naive_meta,
            )

        # 5. Query window start too late (starts 1 hour before success, needs 2 hours)
        late_start_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=now - timedelta(hours=1),  # too late!
            window_end=now,
        )
        with pytest.raises(MitreMappingValidationError, match="does not cover the full required 2-hour preceding window"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=late_start_meta,
            )

        # 6. Query window end too early (ends before success time)
        early_end_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=now - timedelta(hours=3),
            window_end=now - timedelta(minutes=5),  # ends before success!
        )
        with pytest.raises(MitreMappingValidationError, match="ends before the authentication event"):
            validator.validate_proposal(
                proposal=prop,
                provenance_set=prov_set,
                investigation_id=inv_id,
                retrieval_metadata=early_end_meta,
            )

        # 7. Complete coverage satisfying all conditions
        valid_meta = EventRetrievalMetadata(
            truncated=False,
            coverage_complete=True,
            window_start=now - timedelta(hours=2, minutes=5),
            window_end=now + timedelta(minutes=5),
        )
        res = validator.validate_proposal(
            proposal=prop,
            provenance_set=prov_set,
            investigation_id=inv_id,
            retrieval_metadata=valid_meta,
        )
        assert res.technique_id == "T1078"
