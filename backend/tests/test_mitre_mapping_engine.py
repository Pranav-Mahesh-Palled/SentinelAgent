"""Unit and integration tests for Task 8C: Deterministic MITRE ATT&CK Behavioral Mapping Engine.

Verifies:
1. MAP-SSH-001 (Brute Force Candidate -> T1110):
   - Under-threshold failures (3 attempts, 9 attempts): No candidate generated.
   - Baseline qualifying burst (10 failures in 15 mins): Candidate, Medium confidence.
   - Upper boundary burst (29 failures in 15 mins): Candidate, Medium confidence.
   - High-density burst (>= 30 failures within 10 mins): Candidate, High confidence.
   - Spread burst (30 failures spread over > 10 mins): Candidate, Medium confidence (no auto-high).
   - > 2 distinct usernames: Excluded from MAP-SSH-001.
   - Multi-IP isolation: Cross-IP failure aggregation strictly prevented.
   - Successful auth events excluded from failed failure counts.
   - T1110 assigned as most defensible technique; T1110.001 not asserted without auth method.
   - Supported status strictly unavailable.

2. MAP-SSH-002 (Horizontal Spraying Hypothesis -> T1110.003):
   - Under-threshold user count (4 usernames): No hypothesis generated.
   - Baseline qualifying pattern (5 usernames, <= 3 fails each): Hypothesis, Medium confidence.
   - Spread user pattern (6 usernames, 1 fail each): Hypothesis, Medium confidence.
   - Exceeding attempt boundary (one user with 4 fails): Filtered safely.
   - Cross-IP isolation enforced.
   - Confidence never exceeds Medium; status can never become Supported.
   - Mandatory rationale text includes password reuse limitation statement.

3. MAP-SSH-003 (Valid Accounts Candidate -> T1078):
   - Complete two-hour coverage permits evaluation: Candidate, Low confidence.
   - Incomplete two-hour coverage (coverage_complete=False or window_start too late): Rejected / produces None.
   - Truncated retrieval (truncated=True): Never claims complete coverage; produces None.
   - Five failures outside the preceding two-hour interval do not count.
   - Failures occurring after the successful event do not count as preceding failures.
   - Thirty qualifying failures do NOT elevate confidence to Medium (remains strictly Low).
   - Never High confidence; never Supported status.

4. Deferred Rules:
   - T1078.001 (Default Accounts) and T1021.004 (Lateral SSH) are never generated.

5. Input Validation, Integrity & UUID5 Idempotency:
   - Invalid or malformed IP addresses are safely rejected without emitting fabricated references.
   - Naive datetimes are strictly rejected.
   - Out-of-order events produce deterministic sorted output.
   - Duplicate event UUIDs are deduplicated.
   - RFC 4122 UUID5 deterministic fingerprinting idempotency:
     * Identical inputs -> identical mapping IDs.
     * Different investigation ID -> different mapping IDs.
     * Different catalogue version -> different mapping IDs.
     * Different evidence set -> different mapping IDs.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from typing import List
import uuid

from app.schemas.investigation import SSHEventRecord
from app.schemas.mitre import (
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import (
    RULE_MAP_SSH_001,
    RULE_MAP_SSH_002,
    RULE_MAP_SSH_003,
    SENTINEL_MITRE_NAMESPACE,
    EventRetrievalMetadata,
    MitreMappingEngine,
    compute_mapping_uuid5,
)

# Root directory of SentinelAgent
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOGUE_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "mitre" / "mitre_attack_enterprise_v20_1.json"


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="module")
def catalogue_service() -> MitreCatalogueService:
    """Instantiated MitreCatalogueService backed by real compiled data."""
    if not CATALOGUE_PATH.exists():
        pytest.skip(f"Catalogue not found at {CATALOGUE_PATH}")
    return MitreCatalogueService.from_file(CATALOGUE_PATH)


@pytest.fixture
def mapping_engine(catalogue_service: MitreCatalogueService) -> MitreMappingEngine:
    """Instantiated MitreMappingEngine."""
    return MitreMappingEngine(catalogue=catalogue_service)


@pytest.fixture
def test_investigation_id() -> uuid.UUID:
    """Fixed investigation UUID for test consistency."""
    return uuid.UUID("11111111-2222-3333-4444-555555555555")


def make_event(
    event_timestamp: datetime,
    source_ip: str = "192.168.1.100",
    username: str = "ubuntu",
    auth_result: str = "failure",
    event_id: uuid.UUID = None,
) -> SSHEventRecord:
    """Helper to generate valid SSHEventRecord instances."""
    return SSHEventRecord(
        event_id=event_id or uuid.uuid4(),
        event_timestamp=event_timestamp,
        source_ip=source_ip,
        username=username,
        authentication_result=auth_result,
        event_type="auth_attempt" if auth_result == "failure" else "auth_success",
        ingested_at=event_timestamp,
    )


# =============================================================================
# 1. MAP-SSH-001 (Brute Force Candidate -> T1110)
# =============================================================================

class TestMapSsh001BruteForce:
    """Test suite for MAP-SSH-001 candidate generation."""

    def test_under_threshold_failures_generate_no_candidate(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 3 and 9 failed attempts do not generate a candidate."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)

        # 3 failures
        events_3 = [make_event(base_time + timedelta(seconds=i * 10)) for i in range(3)]
        res_3 = mapping_engine.evaluate(test_investigation_id, events_3)
        assert len([p for p in res_3 if p.rule_id == RULE_MAP_SSH_001]) == 0

        # 9 failures
        events_9 = [make_event(base_time + timedelta(seconds=i * 10)) for i in range(9)]
        res_9 = mapping_engine.evaluate(test_investigation_id, events_9)
        assert len([p for p in res_9 if p.rule_id == RULE_MAP_SSH_001]) == 0

    def test_baseline_qualifying_burst_generates_medium_candidate(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 10 failed attempts within 15 minutes generates T1110 with Medium confidence."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_10 = [
            make_event(base_time + timedelta(seconds=i * 30), username="root")
            for i in range(10)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_10)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1

        prop = p1[0]
        assert prop.technique_id == "T1110"
        assert prop.technique_name == "Brute Force"
        assert prop.mapping_status == MitreMappingStatus.CANDIDATE
        assert prop.confidence == MitreConfidenceLevel.MEDIUM
        assert len(prop.event_ids) == 10
        assert len(prop.supporting_references) == 10
        assert "TA0006" in prop.tactic_ids
        assert "Credential Access" in prop.tactic_names
        assert isinstance(prop.window_start, datetime)
        assert isinstance(prop.window_end, datetime)
        assert prop.window_start.tzinfo is not None
        assert "supported status remains unavailable" in prop.rationale

    def test_upper_boundary_burst_generates_medium_candidate(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 29 failed attempts generates Medium confidence."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_29 = [
            make_event(base_time + timedelta(seconds=i * 20), username="admin")
            for i in range(29)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_29)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].confidence == MitreConfidenceLevel.MEDIUM
        assert len(p1[0].event_ids) == 29

    def test_high_density_burst_generates_high_candidate(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify >= 30 failed attempts within 10 minutes generates High confidence candidate."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_35 = [
            make_event(base_time + timedelta(seconds=i * 10), username="root")
            for i in range(35)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_35)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].confidence == MitreConfidenceLevel.HIGH
        assert p1[0].mapping_status == MitreMappingStatus.CANDIDATE  # Never Supported!
        assert len(p1[0].event_ids) == 35

    def test_spread_burst_over_ten_minutes_calibrated_to_medium(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 30 failures spread across > 10 minutes is calibrated to Medium confidence."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_30_spread = [
            make_event(base_time + timedelta(seconds=i * 25), username="root")
            for i in range(30)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_30_spread)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].confidence == MitreConfidenceLevel.MEDIUM  # Not auto-High!

    def test_more_than_two_distinct_usernames_rejected(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 10 failures spread across 3 usernames violates <= 2 distinct targets rule."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        users = ["user1", "user2", "user3"]
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username=users[i % 3])
            for i in range(12)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 0

    def test_different_source_ips_not_aggregated(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify failures on different IPs are strictly isolated."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_ip_a = [
            make_event(base_time + timedelta(seconds=i * 10), source_ip="10.0.0.1", username="root")
            for i in range(6)
        ]
        events_ip_b = [
            make_event(base_time + timedelta(seconds=i * 10), source_ip="10.0.0.2", username="root")
            for i in range(6)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_ip_a + events_ip_b)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 0

    def test_successful_events_excluded_from_failure_count(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify successful logins do not count towards the 10 failed logins requirement."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username="root", auth_result="failure")
            for i in range(8)
        ] + [
            make_event(base_time + timedelta(seconds=(8 + i) * 10), username="root", auth_result="success")
            for i in range(4)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 0

    def test_exact_threshold_boundary_nine_vs_ten_failures(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify strict threshold boundary: 9 failures yields None, 10 yields Candidate Medium."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)

        # 9 failures within 15 mins -> 0 proposals
        events_9 = [make_event(base_time + timedelta(seconds=i * 60), username="admin") for i in range(9)]
        res_9 = mapping_engine.evaluate(test_investigation_id, events_9)
        assert len([p for p in res_9 if p.rule_id == RULE_MAP_SSH_001]) == 0

        # 10 failures within 15 mins -> 1 proposal, candidate, medium
        events_10 = [make_event(base_time + timedelta(seconds=i * 60), username="admin") for i in range(10)]
        res_10 = mapping_engine.evaluate(test_investigation_id, events_10)
        p1_10 = [p for p in res_10 if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1_10) == 1
        assert p1_10[0].mapping_status == MitreMappingStatus.CANDIDATE
        assert p1_10[0].confidence == MitreConfidenceLevel.MEDIUM

    def test_exact_high_confidence_boundary_thirty_failures_within_ten_minutes(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify exactly 30 failures within 10 minutes (600s) generates High confidence."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        # 30 failures over 580 seconds (< 600s)
        events_30 = [
            make_event(base_time + timedelta(seconds=i * 20), username="root")
            for i in range(30)
        ]
        proposals = mapping_engine.evaluate(test_investigation_id, events_30)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].confidence == MitreConfidenceLevel.HIGH
        assert p1[0].mapping_status == MitreMappingStatus.CANDIDATE

    def test_thirty_failures_spread_over_twelve_minutes_calibrated_to_medium(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 30 failures over 12 minutes (720s, > 600s, <= 900s) remains Medium confidence."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_30_12m = [
            make_event(base_time + timedelta(seconds=i * 24), username="root")
            for i in range(30)
        ]
        # 29 * 24 = 696s (> 600s, <= 900s)
        proposals = mapping_engine.evaluate(test_investigation_id, events_30_12m)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].confidence == MitreConfidenceLevel.MEDIUM

    def test_supported_status_strictly_unavailable_even_with_overwhelming_failures(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that mapping_status is never SUPPORTED, even with massive burst volume."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_100 = [
            make_event(base_time + timedelta(seconds=i * 2), username="root")
            for i in range(100)
        ]
        proposals = mapping_engine.evaluate(test_investigation_id, events_100)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].mapping_status == MitreMappingStatus.CANDIDATE
        assert p1[0].mapping_status != MitreMappingStatus.SUPPORTED


# =============================================================================
# 2. MAP-SSH-002 (Horizontal Spraying Hypothesis -> T1110.003)
# =============================================================================

class TestMapSsh002PasswordSpraying:
    """Test suite for MAP-SSH-002 horizontal guessing hypothesis."""

    def test_under_threshold_user_count_generates_no_hypothesis(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 4 distinct usernames does not trigger T1110.003 (requires >= 5)."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username=f"user_{i}")
            for i in range(4)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 0

    def test_qualifying_horizontal_pattern_generates_hypothesis(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 5 distinct usernames with <= 3 failures each generates Hypothesis."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 20), username=f"user_{i}")
            for i in range(5)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 1

        prop = p2[0]
        assert prop.technique_id == "T1110.003"
        assert prop.technique_name == "Password Spraying"
        assert prop.mapping_status == MitreMappingStatus.HYPOTHESIS
        assert prop.confidence == MitreConfidenceLevel.MEDIUM
        assert len(prop.event_ids) == 5
        assert isinstance(prop.window_start, datetime)
        assert isinstance(prop.window_end, datetime)

        mandatory_text = "Observed horizontal multi-user authentication failures are consistent with password spraying; password reuse cannot be verified from available telemetry."
        assert mandatory_text in prop.rationale

    def test_username_exceeding_three_attempts_is_filtered(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that attempts beyond 3 per user are not added to MAP-SSH-002."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username=f"user_{i}")
            for i in range(4)
        ] + [
            make_event(base_time + timedelta(seconds=(4 + i) * 10), username="heavy_user")
            for i in range(5)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 1
        assert len(p2[0].event_ids) == 4 + 3  # 7 events total

    def test_five_usernames_with_three_failures_each_qualifies_hypothesis_medium(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify 5 usernames with 3 failures each generates Hypothesis with 15 supporting events."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = []
        for u in range(5):
            for attempt in range(3):
                events.append(
                    make_event(
                        base_time + timedelta(seconds=u * 60 + attempt * 10),
                        username=f"target_user_{u}",
                    )
                )

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 1
        prop = p2[0]
        assert prop.technique_id == "T1110.003"
        assert prop.mapping_status == MitreMappingStatus.HYPOTHESIS
        assert prop.confidence == MitreConfidenceLevel.MEDIUM
        assert len(prop.event_ids) == 15

    def test_different_source_ips_isolated_for_map_ssh_002(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify cross-IP username targets are not combined for horizontal spray."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_ip_a = [
            make_event(base_time + timedelta(seconds=i * 10), source_ip="192.168.1.10", username=f"user_a_{i}")
            for i in range(3)
        ]
        events_ip_b = [
            make_event(base_time + timedelta(seconds=i * 10), source_ip="192.168.1.20", username=f"user_b_{i}")
            for i in range(3)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events_ip_a + events_ip_b)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 0

    def test_hypothesis_confidence_never_high_and_status_never_supported(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that massive horizontal volume cannot elevate confidence to HIGH or status to SUPPORTED."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events_20_users = []
        for i in range(20):
            events_20_users.append(make_event(base_time + timedelta(seconds=i * 10), username=f"user_{i}"))

        proposals = mapping_engine.evaluate(test_investigation_id, events_20_users)
        p2 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_002]
        assert len(p2) == 1
        assert p2[0].confidence == MitreConfidenceLevel.MEDIUM
        assert p2[0].confidence != MitreConfidenceLevel.HIGH
        assert p2[0].mapping_status == MitreMappingStatus.HYPOTHESIS
        assert p2[0].mapping_status != MitreMappingStatus.SUPPORTED


# =============================================================================
# 3. MAP-SSH-003 (Valid Accounts Candidate -> T1078 & Two-Hour Coverage)
# =============================================================================

class TestMapSsh003ValidAccountsCoverageAndConfidence:
    """Test suite for MAP-SSH-003 two-hour coverage verification and confidence calibration."""

    def test_complete_two_hour_coverage_permits_candidate(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify complete two-hour coverage generates MAP-SSH-003 candidate with Low confidence."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        # 6 failures preceding success within the 2-hour window
        events = [
            make_event(req_start + timedelta(minutes=10 * (i + 1)), username="admin", auth_result="failure")
            for i in range(6)
        ] + [
            make_event(success_time, username="admin", auth_result="success")
        ]

        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=req_start - timedelta(minutes=15),
            window_end=success_time + timedelta(minutes=15),
            coverage_complete=True,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 1

        prop = p3[0]
        assert prop.technique_id == "T1078"
        assert prop.technique_name == "Valid Accounts"
        assert prop.mapping_status == MitreMappingStatus.CANDIDATE
        assert prop.confidence == MitreConfidenceLevel.LOW
        assert len(prop.event_ids) == 7

    def test_coverage_not_complete_rejects_evaluation(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that when coverage_complete is False, MAP-SSH-003 is rejected."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        events = [
            make_event(req_start + timedelta(minutes=10 * (i + 1)), username="admin", auth_result="failure")
            for i in range(6)
        ] + [
            make_event(success_time, username="admin", auth_result="success")
        ]

        # coverage_complete=False (e.g. unknown coverage boundary)
        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=req_start,
            window_end=success_time,
            coverage_complete=False,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 0

    def test_coverage_beginning_after_required_interval_rejects_evaluation(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that if window_start is after (success_time - 2h), complete coverage is not established."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        events = [
            make_event(req_start + timedelta(minutes=70 + i * 5), username="admin", auth_result="failure")
            for i in range(6)
        ] + [
            make_event(success_time, username="admin", auth_result="success")
        ]

        # Retrieval only started 1 hour before success instead of 2 hours
        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=success_time - timedelta(hours=1),  # Starts after required_start!
            window_end=success_time,
            coverage_complete=True,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 0

    def test_truncated_retrieval_rejects_evaluation(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify that truncated=True prevents claiming complete coverage."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        events = [
            make_event(req_start + timedelta(minutes=10 * (i + 1)), username="admin", auth_result="failure")
            for i in range(6)
        ] + [
            make_event(success_time, username="admin", auth_result="success")
        ]

        # Tool was truncated (e.g. limit reached)
        meta = EventRetrievalMetadata(
            truncated=True,
            window_start=req_start - timedelta(hours=1),
            window_end=success_time,
            coverage_complete=True,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 0

    def test_thirty_qualifying_failures_does_not_elevate_confidence(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify >= 30 preceding failures does NOT elevate confidence; remains strictly LOW."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        events = [
            make_event(req_start + timedelta(seconds=i * 100), username="admin", auth_result="failure")
            for i in range(35)
        ] + [
            make_event(success_time, username="admin", auth_result="success")
        ]

        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=req_start - timedelta(minutes=10),
            window_end=success_time + timedelta(minutes=10),
            coverage_complete=True,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 1
        assert p3[0].confidence == MitreConfidenceLevel.LOW  # Strictly LOW! Never Medium!
        assert p3[0].mapping_status == MitreMappingStatus.CANDIDATE

    def test_failures_outside_two_hour_interval_excluded(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify failures occurring > 2 hours prior to success do not count towards the 5 threshold."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        # 4 failures within window, 4 failures outside window (> 2h prior)
        failures_outside = [
            make_event(req_start - timedelta(minutes=(i + 1) * 10), username="admin", auth_result="failure")
            for i in range(4)
        ]
        failures_inside = [
            make_event(req_start + timedelta(minutes=(i + 1) * 10), username="admin", auth_result="failure")
            for i in range(4)
        ]

        events = failures_outside + failures_inside + [make_event(success_time, username="admin", auth_result="success")]

        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=req_start - timedelta(hours=1),
            window_end=success_time,
            coverage_complete=True,
        )

        # Only 4 failures inside window (< 5)
        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 0

    def test_failures_after_success_not_counted_as_preceding(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify failures occurring after success are excluded."""
        success_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
        req_start = success_time - timedelta(hours=2)

        # 3 failures before, 10 failures after success
        failures_before = [
            make_event(req_start + timedelta(minutes=10 * (i + 1)), username="admin", auth_result="failure")
            for i in range(3)
        ]
        failures_after = [
            make_event(success_time + timedelta(minutes=5 * (i + 1)), username="admin", auth_result="failure")
            for i in range(10)
        ]

        events = failures_before + [make_event(success_time, username="admin", auth_result="success")] + failures_after

        meta = EventRetrievalMetadata(
            truncated=False,
            window_start=req_start,
            window_end=success_time + timedelta(hours=1),
            coverage_complete=True,
        )

        proposals = mapping_engine.evaluate(test_investigation_id, events, retrieval_metadata=meta)
        p3 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_003]
        assert len(p3) == 0


# =============================================================================
# 4. Input Validation & Resilience Tests
# =============================================================================

class TestInputValidationAndResilience:
    """Test suite for IP validation, naive timestamp rejection, and deduplication."""

    def test_invalid_source_ip_safely_excluded(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify invalid or non-IP strings are excluded without raising unhandled errors or emitting references."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), source_ip="not_an_ip", username="root")
            for i in range(15)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        assert len(proposals) == 0

    def test_naive_timestamp_safely_rejected(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify naive datetimes (tzinfo=None) are safely rejected per SentinelAgent standards."""
        from unittest.mock import Mock

        # Create mock event records with naive datetime to test engine's defensive filtering
        naive_time = datetime(2026, 11, 8, 12, 0, 0)
        events = [
            Mock(
                spec=SSHEventRecord,
                event_id=uuid.uuid4(),
                event_timestamp=naive_time + timedelta(seconds=i * 10),
                source_ip="192.168.1.100",
                username="root",
                authentication_result="failure",
                event_type="auth_attempt",
                ingested_at=naive_time,
            )
            for i in range(15)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        assert len(proposals) == 0

    def test_utc_normalization_consistent(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify non-UTC aware timestamps (e.g. EST/EDT) are normalized cleanly to UTC."""
        est_tz = timezone(timedelta(hours=-5))
        base_time_est = datetime(2026, 11, 8, 7, 0, 0, tzinfo=est_tz)  # 12:00:00 UTC
        events = [
            make_event(base_time_est + timedelta(seconds=i * 10), username="root")
            for i in range(10)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].window_start.tzinfo == timezone.utc
        assert p1[0].window_start.hour == 12

    def test_technique_specificity_preserves_t1110_not_subtechnique(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify MAP-SSH-001 always emits T1110 and never T1110.001 under 6-field telemetry."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username="root")
            for i in range(15)
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 1
        assert p1[0].technique_id == "T1110"
        assert p1[0].technique_id != "T1110.001"


# =============================================================================
# 5. Deferred Rules Verification
# =============================================================================

class TestDeferredRulesNotGenerated:
    """Verify deferred techniques are never emitted by the mapping engine."""

    def test_deferred_techniques_never_emitted(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify T1078.001 (Default Accounts) and T1021.004 (Lateral SSH) are never generated."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username="root", auth_result="failure")
            for i in range(15)
        ] + [
            make_event(base_time + timedelta(seconds=200), username="root", auth_result="success")
        ]

        proposals = mapping_engine.evaluate(test_investigation_id, events)
        emitted_tech_ids = {p.technique_id for p in proposals}

        assert "T1078.001" not in emitted_tech_ids
        assert "T1021.004" not in emitted_tech_ids


# =============================================================================
# 6. General Integrity, Deduplication & UUID5 Fingerprinting
# =============================================================================

class TestGeneralIntegrityAndUuid5:
    """Test suite for deduplication, determinism, and UUID5 idempotency."""

    def test_duplicate_event_uuids_deduplicated(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify identical event records passed multiple times are counted exactly once."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        shared_id = uuid.uuid4()
        events_repeated = [
            make_event(base_time + timedelta(seconds=i * 10), username="root", event_id=uuid.uuid5(shared_id, str(i)))
            for i in range(5)
        ] * 2

        proposals = mapping_engine.evaluate(test_investigation_id, events_repeated)
        p1 = [p for p in proposals if p.rule_id == RULE_MAP_SSH_001]
        assert len(p1) == 0

    def test_out_of_order_events_produce_deterministic_output(
        self, mapping_engine: MitreMappingEngine, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify passing events out-of-order produces identical output to chronologically sorted input."""
        base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(base_time + timedelta(seconds=i * 10), username="root", event_id=uuid.uuid4())
            for i in range(12)
        ]
        events_reversed = list(reversed(events))

        res_forward = mapping_engine.evaluate(test_investigation_id, events)
        res_reversed = mapping_engine.evaluate(test_investigation_id, events_reversed)

        assert len(res_forward) == len(res_reversed)
        assert res_forward[0].mapping_id == res_reversed[0].mapping_id
        assert res_forward[0].event_ids == res_reversed[0].event_ids

    def test_uuid5_fingerprint_idempotency_and_sensitivity(
        self, test_investigation_id: uuid.UUID
    ) -> None:
        """Verify UUID5 fingerprint is identical for identical inputs, but sensitive to each component."""
        refs_a = ["ssh_events/11111111-0000-0000-0000-000000000001", "ssh_events/11111111-0000-0000-0000-000000000002"]
        refs_a_unsorted = ["ssh_events/11111111-0000-0000-0000-000000000002", "ssh_events/11111111-0000-0000-0000-000000000001"]

        id_1 = compute_mapping_uuid5(test_investigation_id, "20.1", RULE_MAP_SSH_001, "T1110", refs_a)
        id_2 = compute_mapping_uuid5(test_investigation_id, "20.1", RULE_MAP_SSH_001, "T1110", refs_a_unsorted)

        assert id_1 == id_2

        other_inv = uuid.uuid4()
        id_diff_inv = compute_mapping_uuid5(other_inv, "20.1", RULE_MAP_SSH_001, "T1110", refs_a)
        assert id_1 != id_diff_inv

        id_diff_ver = compute_mapping_uuid5(test_investigation_id, "19.0", RULE_MAP_SSH_001, "T1110", refs_a)
        assert id_1 != id_diff_ver

        id_diff_rule = compute_mapping_uuid5(test_investigation_id, "20.1", RULE_MAP_SSH_002, "T1110", refs_a)
        assert id_1 != id_diff_rule

        id_diff_tech = compute_mapping_uuid5(test_investigation_id, "20.1", RULE_MAP_SSH_001, "T1110.001", refs_a)
        assert id_1 != id_diff_tech

        refs_b = refs_a + ["ssh_events/11111111-0000-0000-0000-000000000003"]
        id_diff_refs = compute_mapping_uuid5(test_investigation_id, "20.1", RULE_MAP_SSH_001, "T1110", refs_b)
        assert id_1 != id_diff_refs
