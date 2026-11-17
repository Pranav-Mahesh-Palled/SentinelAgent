"""Tests for the behavioral feature extraction module (Task 5A).

Verifies grouping by (source_ip, 1-min UTC window), feature calculations,
ordering guarantees, timezone normalization, and error handling.
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.services.feature_extractor import (
    FeatureExtractor,
    FeatureExtractorConfig,
    WindowFeatures,
    extract_window_features,
)
from app.services.ssh_event_generator import SyntheticSSHEvent


def make_test_event(
    event_id: uuid.UUID = None,
    timestamp: datetime = None,
    source_ip: str = "192.0.2.1",
    username: str = "admin",
    authentication_result: str = "success",
    event_type: str = "password",
) -> dict:
    """Construct a validated event dictionary for feature extraction tests."""
    return {
        "event_id": event_id or uuid.uuid4(),
        "event_timestamp": timestamp or datetime(2026, 11, 8, 12, 0, 15, tzinfo=timezone.utc),
        "source_ip": source_ip,
        "username": username,
        "authentication_result": authentication_result,
        "event_type": event_type,
    }


# ---------------------------------------------------------------------------
# Test 1: Normal Successful Logins
# ---------------------------------------------------------------------------

def test_normal_successful_logins():
    """All events in window are successful; verify count, zero failures, zero ratio."""
    base_t = datetime(2026, 11, 8, 10, 0, 10, tzinfo=timezone.utc)
    events = [
        make_test_event(timestamp=base_t + timedelta(seconds=i * 5), authentication_result="success")
        for i in range(5)
    ]
    features = extract_window_features(events)
    assert len(features) == 1
    wf = features[0]
    assert wf.total_attempts == 5
    assert wf.successful_login_count == 5
    assert wf.failed_login_count == 0
    assert wf.failure_ratio == 0.0
    assert wf.success_after_failures is False


# ---------------------------------------------------------------------------
# Test 2: Normal Failed Logins
# ---------------------------------------------------------------------------

def test_normal_failed_logins():
    """Window contains mix of successes and occasional failures."""
    base_t = datetime(2026, 11, 8, 10, 0, 5, tzinfo=timezone.utc)
    events = [
        make_test_event(timestamp=base_t, authentication_result="failure"),
        make_test_event(timestamp=base_t + timedelta(seconds=10), authentication_result="success"),
        make_test_event(timestamp=base_t + timedelta(seconds=20), authentication_result="failure"),
    ]
    features = extract_window_features(events)
    assert len(features) == 1
    wf = features[0]
    assert wf.total_attempts == 3
    assert wf.failed_login_count == 2
    assert wf.successful_login_count == 1
    assert wf.failure_ratio == round(2 / 3, 4)


# ---------------------------------------------------------------------------
# Test 3: Multiple Usernames
# ---------------------------------------------------------------------------

def test_multiple_usernames():
    """Window contains attempts targeting multiple distinct usernames."""
    base_t = datetime(2026, 11, 8, 10, 0, 10, tzinfo=timezone.utc)
    events = [
        make_test_event(timestamp=base_t, username="root"),
        make_test_event(timestamp=base_t + timedelta(seconds=5), username="admin"),
        make_test_event(timestamp=base_t + timedelta(seconds=10), username="root"),
        make_test_event(timestamp=base_t + timedelta(seconds=15), username="guest"),
    ]
    features = extract_window_features(events)
    assert len(features) == 1
    assert features[0].distinct_usernames == 3
    assert features[0].total_attempts == 4


# ---------------------------------------------------------------------------
# Test 4: Multiple Source IPs
# ---------------------------------------------------------------------------

def test_multiple_source_ips():
    """Events from distinct source IPs are bucketed into separate WindowFeatures records."""
    base_t = datetime(2026, 11, 8, 10, 0, 10, tzinfo=timezone.utc)
    events = [
        make_test_event(source_ip="192.0.2.1", timestamp=base_t),
        make_test_event(source_ip="198.51.100.2", timestamp=base_t + timedelta(seconds=5)),
        make_test_event(source_ip="192.0.2.1", timestamp=base_t + timedelta(seconds=10)),
    ]
    features = extract_window_features(events)
    assert len(features) == 2
    ip_map = {wf.source_ip: wf for wf in features}
    assert "192.0.2.1" in ip_map
    assert "198.51.100.2" in ip_map
    assert ip_map["192.0.2.1"].total_attempts == 2
    assert ip_map["198.51.100.2"].total_attempts == 1


# ---------------------------------------------------------------------------
# Test 5: Multiple One-Minute Windows
# ---------------------------------------------------------------------------

def test_multiple_one_minute_windows():
    """Events spanning across minute boundaries are partitioned into distinct windows."""
    events = [
        make_test_event(timestamp=datetime(2026, 11, 8, 10, 0, 15, tzinfo=timezone.utc)),
        make_test_event(timestamp=datetime(2026, 11, 8, 10, 0, 45, tzinfo=timezone.utc)),
        make_test_event(timestamp=datetime(2026, 11, 8, 10, 1, 10, tzinfo=timezone.utc)),
        make_test_event(timestamp=datetime(2026, 11, 8, 10, 2, 5, tzinfo=timezone.utc)),
    ]
    features = extract_window_features(events)
    assert len(features) == 3

    w0 = features[0]
    assert w0.window_start == datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
    assert w0.window_end == datetime(2026, 11, 8, 10, 1, 0, tzinfo=timezone.utc)
    assert w0.total_attempts == 2

    w1 = features[1]
    assert w1.window_start == datetime(2026, 11, 8, 10, 1, 0, tzinfo=timezone.utc)
    assert w1.total_attempts == 1

    w2 = features[2]
    assert w2.window_start == datetime(2026, 11, 8, 10, 2, 0, tzinfo=timezone.utc)
    assert w2.total_attempts == 1


# ---------------------------------------------------------------------------
# Test 6: Chronological Ordering
# ---------------------------------------------------------------------------

def test_chronological_ordering():
    """Event order within each window is sorted chronologically for feature calculation."""
    base_t = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
    t1 = base_t + timedelta(seconds=10)
    t2 = base_t + timedelta(seconds=20)
    t3 = base_t + timedelta(seconds=30)

    events = [
        make_test_event(timestamp=t1, username="user_1"),
        make_test_event(timestamp=t2, username="user_2"),
        make_test_event(timestamp=t3, username="user_3"),
    ]
    features = extract_window_features(events)
    assert len(features) == 1
    assert features[0].total_attempts == 3


# ---------------------------------------------------------------------------
# Test 7: Out-of-Order Input Handled Correctly
# ---------------------------------------------------------------------------

def test_out_of_order_input():
    """Events arriving in scrambled or reverse order are sorted before sequential evaluation."""
    base_t = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)

    # 5 failures chronologically first, then 1 success
    events_in_order = [
        make_test_event(timestamp=base_t + timedelta(seconds=5 * i), authentication_result="failure")
        for i in range(5)
    ] + [make_test_event(timestamp=base_t + timedelta(seconds=35), authentication_result="success")]

    # Reverse the arrival order completely
    scrambled_events = list(reversed(events_in_order))

    # Without sorting, success appears first (0 preceding failures).
    # With sorting, success appears after 5 failures -> success_after_failures should be True!
    features = extract_window_features(scrambled_events)
    assert len(features) == 1
    assert features[0].success_after_failures is True


# ---------------------------------------------------------------------------
# Test 8: Correct Failure Ratio Calculation & Zero Division Prevention
# ---------------------------------------------------------------------------

def test_correct_failure_ratio():
    """Failure ratio calculates accurately; empty attempts avoid ZeroDivisionError."""
    base_t = datetime(2026, 11, 8, 10, 0, 10, tzinfo=timezone.utc)

    # 3 failures out of 4 total attempts = 0.75
    events = [
        make_test_event(timestamp=base_t, authentication_result="failure"),
        make_test_event(timestamp=base_t + timedelta(seconds=5), authentication_result="failure"),
        make_test_event(timestamp=base_t + timedelta(seconds=10), authentication_result="failure"),
        make_test_event(timestamp=base_t + timedelta(seconds=15), authentication_result="success"),
    ]
    wf = extract_window_features(events)[0]
    assert wf.failure_ratio == 0.75

    # 1 success out of 4 attempts = 0.75 failure ratio
    events_all_success = [
        make_test_event(timestamp=base_t, authentication_result="success")
    ]
    wf_success = extract_window_features(events_all_success)[0]
    assert wf_success.failure_ratio == 0.0


# ---------------------------------------------------------------------------
# Test 9: Success Following Repeated Failures
# ---------------------------------------------------------------------------

def test_success_following_repeated_failures():
    """Verify success_after_failures flags when preceding failures >= threshold."""
    base_t = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)

    # 5 failures + 1 success with threshold=5 -> True
    events_5_fail = [
        make_test_event(timestamp=base_t + timedelta(seconds=i * 5), authentication_result="failure")
        for i in range(5)
    ] + [make_test_event(timestamp=base_t + timedelta(seconds=30), authentication_result="success")]

    wf_5 = extract_window_features(events_5_fail, min_preceding_failures=5)[0]
    assert wf_5.success_after_failures is True

    # 4 failures + 1 success with threshold=5 -> False
    events_4_fail = [
        make_test_event(timestamp=base_t + timedelta(seconds=i * 5), authentication_result="failure")
        for i in range(4)
    ] + [make_test_event(timestamp=base_t + timedelta(seconds=25), authentication_result="success")]

    wf_4 = extract_window_features(events_4_fail, min_preceding_failures=5)[0]
    assert wf_4.success_after_failures is False


# ---------------------------------------------------------------------------
# Test 10: Timezone Handling & UTC Normalization
# ---------------------------------------------------------------------------

def test_timezone_handling():
    """Events in non-UTC timezones are normalized to UTC for consistent window assignment."""
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    # 15:30:20 IST corresponds to 10:00:20 UTC
    dt_ist = datetime(2026, 11, 8, 15, 30, 20, tzinfo=tz_ist)

    # 10:00:40 UTC
    dt_utc = datetime(2026, 11, 8, 10, 0, 40, tzinfo=timezone.utc)

    events = [
        make_test_event(timestamp=dt_ist),
        make_test_event(timestamp=dt_utc),
    ]
    features = extract_window_features(events)
    # Both events fall into the same 10:00:00 UTC window!
    assert len(features) == 1
    assert features[0].window_start == datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
    assert features[0].total_attempts == 2


# ---------------------------------------------------------------------------
# Test 11: Empty Event Collection
# ---------------------------------------------------------------------------

def test_empty_event_collection():
    """Passing an empty event sequence returns an empty list without error."""
    assert extract_window_features([]) == []


# ---------------------------------------------------------------------------
# Test 12: Invalid Input Handling
# ---------------------------------------------------------------------------

def test_invalid_input_handling():
    """Verify validation exceptions for invalid timestamps, IPs, and configurations."""
    # 1. Naive timestamp rejected
    naive_event = make_test_event(timestamp=datetime(2026, 11, 8, 10, 0, 0))
    with pytest.raises(ValueError, match="timezone-aware"):
        extract_window_features([naive_event])

    # 2. Empty source IP rejected
    empty_ip_event = make_test_event(source_ip="")
    with pytest.raises(ValueError, match="source_ip cannot be empty"):
        extract_window_features([empty_ip_event])

    # 3. Empty username rejected
    empty_user_event = make_test_event(username="")
    with pytest.raises(ValueError, match="username must be a non-empty string"):
        extract_window_features([empty_user_event])

    # 4. Invalid auth result rejected
    bad_auth_event = make_test_event(authentication_result="pending")
    with pytest.raises(ValueError, match="authentication_result must be 'success' or 'failure'"):
        extract_window_features([bad_auth_event])

    # 5. Non-positive config threshold rejected
    with pytest.raises(ValueError, match="min_preceding_failures must be a positive integer"):
        FeatureExtractorConfig(min_preceding_failures=0)


# ---------------------------------------------------------------------------
# Extra: SyntheticSSHEvent Model Compatibility
# ---------------------------------------------------------------------------

def test_synthetic_ssh_event_compatibility():
    """Ensure extract_window_features accepts SyntheticSSHEvent dataclass instances."""
    ev = SyntheticSSHEvent(
        event_id=uuid.uuid4(),
        event_timestamp=datetime(2026, 11, 8, 10, 0, 15, tzinfo=timezone.utc),
        source_ip="192.0.2.10",
        username="operator",
        authentication_result="success",
        event_type="password",
    )
    features = extract_window_features([ev])
    assert len(features) == 1
    assert features[0].source_ip == "192.0.2.10"
    assert features[0].total_attempts == 1
    assert features[0].event_ids == (ev.event_id,)

