"""Automated tests for the synthetic SSH authentication event generator.

Verifies:
- Scenario generation (normal success, normal failure, repeated failure, brute force, suspicious success).
- RFC 5737 documentation IP constraints.
- Timezone awareness and chronological ordering.
- Deterministic reproducibility when using a fixed random seed.
- Input validation and exception handling.
- Compatibility with the existing SQLAlchemy SSHEvent model.
- Strictly read-only in-memory execution (no PostgreSQL writes).
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import uuid
import pytest

from app.models.ssh_event import SSHEvent
from app.services.ssh_event_generator import (
    DOC_NETWORKS,
    SSHEventGenerator,
    SyntheticSSHEvent,
    generate_brute_force_events,
    generate_event_batch,
    generate_failed_events,
    generate_normal_events,
    generate_suspicious_success_events,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_valid_doc_ip(ip_str: str) -> bool:
    """Check if ip_str is a valid IPv4 address in RFC 5737 documentation ranges."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in DOC_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Scenario Tests
# ---------------------------------------------------------------------------

def test_normal_successful_login_generation():
    """Scenario A: Normal logins with failure_rate=0.0 are all successful."""
    events = generate_normal_events(count=15, failure_rate=0.0, seed=101)
    assert len(events) == 15
    for ev in events:
        assert ev.authentication_result == "success"
        assert is_valid_doc_ip(ev.source_ip)
        assert len(ev.username) > 0
        assert ev.event_timestamp.tzinfo is not None


def test_normal_failed_login_generation():
    """Scenario B: Normal logins with positive failure_rate produce occasional failures."""
    events = generate_normal_events(count=50, failure_rate=0.3, seed=202)
    assert len(events) == 50
    results = {ev.authentication_result for ev in events}
    # Should include both success and failure with count=50 and failure_rate=0.3
    assert "success" in results
    assert "failure" in results
    assert results.issubset({"success", "failure"})


def test_repeated_failed_login_generation():
    """Scenario C: Repeated failed logins originate from a common source IP."""
    events = generate_failed_events(count=6, seed=303)
    assert len(events) == 6
    common_ip = events[0].source_ip
    for ev in events:
        assert ev.authentication_result == "failure"
        assert ev.source_ip == common_ip
        assert is_valid_doc_ip(ev.source_ip)


def test_brute_force_scenario_count_and_time_window():
    """Scenario D: Generate approximately 50 failed login attempts within a 60s window."""
    base_time = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
    events = generate_brute_force_events(
        count=50,
        base_timestamp=base_time,
        duration_seconds=60.0,
        seed=404,
    )
    assert len(events) == 50

    common_ip = events[0].source_ip
    for ev in events:
        assert ev.authentication_result == "failure"
        assert ev.source_ip == common_ip
        assert is_valid_doc_ip(ev.source_ip)
        assert base_time <= ev.event_timestamp <= base_time + timedelta(seconds=60.0)

    # Time span between first and last attempt must be <= 60 seconds
    time_span = (events[-1].event_timestamp - events[0].event_timestamp).total_seconds()
    assert 0 <= time_span <= 60.0


def test_brute_force_multiple_usernames():
    """Scenario D: Brute-force attacks must cycle across multiple target usernames."""
    events = generate_brute_force_events(count=50, seed=505)
    usernames_seen = {ev.username for ev in events}
    # With 50 attempts against a dictionary of usernames, multiple distinct names should appear
    assert len(usernames_seen) >= 3


def test_suspicious_success_after_failures():
    """Scenario E: Repeated failures followed by a single successful login."""
    base_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
    events = generate_suspicious_success_events(
        failure_count=7,
        base_timestamp=base_time,
        target_username="admin",
        duration_seconds=40.0,
        seed=606,
    )
    # 7 failures + 1 final success = 8 events
    assert len(events) == 8

    failures = events[:-1]
    success_event = events[-1]

    common_ip = events[0].source_ip
    for f in failures:
        assert f.authentication_result == "failure"
        assert f.source_ip == common_ip
        assert f.username == "admin"
        assert f.event_timestamp < success_event.event_timestamp

    assert success_event.authentication_result == "success"
    assert success_event.source_ip == common_ip
    assert success_event.username == "admin"


# ---------------------------------------------------------------------------
# Ordering, Timezone & Field Validations
# ---------------------------------------------------------------------------

def test_chronological_ordering_across_scenarios():
    """Verify that generated event sequences are strictly non-decreasing in time."""
    # Test brute force
    bf_events = generate_brute_force_events(count=30, seed=701)
    for i in range(len(bf_events) - 1):
        assert bf_events[i].event_timestamp <= bf_events[i + 1].event_timestamp

    # Test suspicious success
    ss_events = generate_suspicious_success_events(failure_count=10, seed=702)
    for i in range(len(ss_events) - 1):
        assert ss_events[i].event_timestamp <= ss_events[i + 1].event_timestamp

    # Test batch
    batch = generate_event_batch(scenario="mixed", normal_count=10, include_brute_force=True, seed=703)
    for i in range(len(batch) - 1):
        assert batch[i].event_timestamp <= batch[i + 1].event_timestamp


def test_timezone_awareness_enforced():
    """All event timestamps must be timezone-aware (tzinfo is not None)."""
    events = generate_normal_events(count=5, seed=801)
    for ev in events:
        assert ev.event_timestamp.tzinfo is not None
        assert ev.event_timestamp.utcoffset() is not None


def test_valid_uuid_generation():
    """Verify generated UUIDs are valid version-4 UUID instances."""
    events = generate_normal_events(count=10, seed=901)
    seen_ids = set()
    for ev in events:
        assert isinstance(ev.event_id, uuid.UUID)
        assert ev.event_id.version == 4
        seen_ids.add(ev.event_id)
    # All IDs within a generated sequence must be unique
    assert len(seen_ids) == len(events)


def test_valid_source_ip_rfc5737_ranges():
    """Verify source IPs always reside in RFC 5737 documentation ranges."""
    events = generate_normal_events(count=30, seed=1001)
    for ev in events:
        assert is_valid_doc_ip(ev.source_ip)


def test_valid_authentication_results_domain():
    """Verify authentication_result is strictly 'success' or 'failure'."""
    events = generate_event_batch(scenario="mixed", normal_count=20, include_brute_force=True, seed=1101)
    for ev in events:
        assert ev.authentication_result in ("success", "failure")


# ---------------------------------------------------------------------------
# Determinism & Reproducibility
# ---------------------------------------------------------------------------

def test_reproducibility_with_fixed_seed():
    """Two generators initialized with the exact same seed must produce identical events."""
    base_time = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)

    gen1 = SSHEventGenerator(seed=12345)
    events1 = gen1.generate_brute_force_events(count=25, base_timestamp=base_time)

    gen2 = SSHEventGenerator(seed=12345)
    events2 = gen2.generate_brute_force_events(count=25, base_timestamp=base_time)

    assert len(events1) == len(events2)
    for e1, e2 in zip(events1, events2):
        assert e1.event_id == e2.event_id
        assert e1.event_timestamp == e2.event_timestamp
        assert e1.source_ip == e2.source_ip
        assert e1.username == e2.username
        assert e1.authentication_result == e2.authentication_result
        assert e1.event_type == e2.event_type


def test_different_seeds_produce_different_sequences():
    """Different seeds must yield distinct event sequences."""
    events_a = generate_normal_events(count=5, seed=111)
    events_b = generate_normal_events(count=5, seed=222)

    ids_a = [e.event_id for e in events_a]
    ids_b = [e.event_id for e in events_b]
    assert ids_a != ids_b


# ---------------------------------------------------------------------------
# Input Validation & Error Handling
# ---------------------------------------------------------------------------

def test_invalid_count_rejected():
    """Negative or zero count raises ValueError."""
    with pytest.raises(ValueError, match="count must be a positive integer"):
        generate_normal_events(count=0)

    with pytest.raises(ValueError, match="count must be a positive integer"):
        generate_brute_force_events(count=-5)


def test_invalid_failure_rate_rejected():
    """Failure rate outside [0.0, 1.0] raises ValueError."""
    with pytest.raises(ValueError, match="failure_rate must be between 0.0 and 1.0"):
        generate_normal_events(failure_rate=1.5)

    with pytest.raises(ValueError, match="failure_rate must be between 0.0 and 1.0"):
        generate_normal_events(failure_rate=-0.1)


def test_invalid_duration_rejected():
    """Non-positive duration raises ValueError."""
    with pytest.raises(ValueError, match="duration_seconds must be positive"):
        generate_brute_force_events(duration_seconds=0)

    with pytest.raises(ValueError, match="duration_seconds must be positive"):
        generate_failed_events(duration_seconds=-10)


def test_naive_base_timestamp_rejected():
    """Naive base_timestamp (no tzinfo) raises ValueError."""
    naive_dt = datetime(2026, 11, 8, 10, 0, 0)
    with pytest.raises(ValueError, match="base_timestamp must be timezone-aware"):
        generate_normal_events(base_timestamp=naive_dt)


def test_external_ip_rejected():
    """IPs outside RFC 5737 documentation ranges are rejected."""
    with pytest.raises(ValueError, match="outside reserved documentation blocks"):
        generate_normal_events(source_ip="8.8.8.8")

    with pytest.raises(ValueError, match="outside reserved documentation blocks"):
        generate_brute_force_events(source_ip="1.1.1.1")


def test_invalid_ip_format_rejected():
    """Malformed IP address strings raise ValueError."""
    with pytest.raises(ValueError, match="Invalid IPv4 address"):
        generate_normal_events(source_ip="not_an_ip")


def test_synthetic_ssh_event_validation():
    """SyntheticSSHEvent __post_init__ catches schema rule violations."""
    valid_id = uuid.uuid4()
    valid_time = datetime.now(timezone.utc)
    valid_ip = "192.0.2.1"

    # Non-UUID event_id
    with pytest.raises(ValueError, match="event_id must be a UUID instance"):
        SyntheticSSHEvent("bad_uuid", valid_time, valid_ip, "user", "success", "password")

    # Naive timestamp
    with pytest.raises(ValueError, match="event_timestamp must be timezone-aware"):
        SyntheticSSHEvent(valid_id, datetime.now(), valid_ip, "user", "success", "password")

    # Empty username
    with pytest.raises(ValueError, match="username must be a non-empty string"):
        SyntheticSSHEvent(valid_id, valid_time, valid_ip, "", "success", "password")

    # Oversized username (> 128 chars)
    with pytest.raises(ValueError, match="username must be a non-empty string"):
        SyntheticSSHEvent(valid_id, valid_time, valid_ip, "a" * 129, "success", "password")

    # Invalid authentication_result
    with pytest.raises(ValueError, match="authentication_result must be 'success' or 'failure'"):
        SyntheticSSHEvent(valid_id, valid_time, valid_ip, "user", "pending", "password")

    # Empty event_type
    with pytest.raises(ValueError, match="event_type must be a non-empty string"):
        SyntheticSSHEvent(valid_id, valid_time, valid_ip, "user", "success", "")


# ---------------------------------------------------------------------------
# SSHEvent Schema Compatibility (In-Memory, No DB Writes)
# ---------------------------------------------------------------------------

def test_synthetic_event_to_dict_matches_columns():
    """to_dict produces dictionary keys aligned with SSHEvent table columns."""
    event = generate_normal_events(count=1, seed=1201)[0]
    data = event.to_dict()

    expected_keys = {
        "event_id",
        "event_timestamp",
        "source_ip",
        "username",
        "authentication_result",
        "event_type",
    }
    assert expected_keys.issubset(set(data.keys()))
    assert isinstance(data["event_id"], uuid.UUID)
    assert isinstance(data["event_timestamp"], datetime)


def test_synthetic_event_to_model_instantiation():
    """to_model produces an uncommitted SSHEvent instance without writing to DB."""
    event = generate_normal_events(count=1, seed=1301)[0]
    model_instance = event.to_model()

    assert isinstance(model_instance, SSHEvent)
    assert model_instance.event_id == event.event_id
    assert model_instance.event_timestamp == event.event_timestamp
    assert model_instance.source_ip == event.source_ip
    assert model_instance.username == event.username
    assert model_instance.authentication_result == event.authentication_result
    assert model_instance.event_type == event.event_type

