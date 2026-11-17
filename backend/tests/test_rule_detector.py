"""Tests for the rule-based suspicious activity detection module (Task 5A).

Verifies:
- Rule R001: SSH Brute Force (boundary condition at > 10 failures).
- Rule R002: Success After Repeated Failures.
- Independent multi-rule triggering.
- Absence of false positives on normal traffic.
- Custom threshold configuration.
- Rich evidence and detection reasons in output.
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.services.feature_extractor import WindowFeatures
from app.services.rule_detector import (
    RULE_R001,
    RULE_R002,
    DetectionResult,
    RuleDetector,
    RuleDetectorConfig,
    detect_suspicious_activity,
)
from app.services.ssh_event_generator import (
    generate_brute_force_events,
    generate_normal_events,
    generate_suspicious_success_events,
)


def make_window_features(
    source_ip: str = "192.0.2.1",
    total_attempts: int = 1,
    failed_login_count: int = 0,
    successful_login_count: int = 1,
    distinct_usernames: int = 1,
    failure_ratio: float = 0.0,
    success_after_failures: bool = False,
    window_start: datetime = None,
) -> WindowFeatures:
    """Construct a mock WindowFeatures object for testing rule evaluation."""
    start = window_start or datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
    return WindowFeatures(
        source_ip=source_ip,
        window_start=start,
        window_end=start + timedelta(minutes=1),
        total_attempts=total_attempts,
        failed_login_count=failed_login_count,
        successful_login_count=successful_login_count,
        distinct_usernames=distinct_usernames,
        failure_ratio=failure_ratio,
        success_after_failures=success_after_failures,
        event_ids=(),
    )


# ---------------------------------------------------------------------------
# Test 13: More Than 10 Failed Attempts Triggers R001
# ---------------------------------------------------------------------------

def test_more_than_10_failed_attempts_triggers_r001():
    """11 failed attempts strictly exceeds threshold 10 and triggers R001."""
    wf = make_window_features(total_attempts=11, failed_login_count=11, successful_login_count=0, failure_ratio=1.0)
    detector = RuleDetector()
    result = detector.evaluate_window(wf)

    assert result.is_suspicious is True
    assert RULE_R001 in result.triggered_rules
    assert any("R001" in r and "11" in r for r in result.detection_reasons)


# ---------------------------------------------------------------------------
# Test 14: Exactly 10 Failed Attempts Does Not Trigger R001
# ---------------------------------------------------------------------------

def test_exactly_10_failed_attempts_does_not_trigger_r001():
    """Strict boundary condition: failed_login_count == 10 does not trigger R001 (> 10 required)."""
    wf = make_window_features(total_attempts=10, failed_login_count=10, successful_login_count=0, failure_ratio=1.0)
    detector = RuleDetector()
    result = detector.evaluate_window(wf)

    assert result.is_suspicious is False
    assert RULE_R001 not in result.triggered_rules
    assert len(result.triggered_rules) == 0


# ---------------------------------------------------------------------------
# Test 15: Successful Login Following Configured Failure Threshold Triggers R002
# ---------------------------------------------------------------------------

def test_success_following_failure_threshold_triggers_r002():
    """success_after_failures == True triggers R002."""
    wf = make_window_features(
        total_attempts=6,
        failed_login_count=5,
        successful_login_count=1,
        failure_ratio=round(5 / 6, 4),
        success_after_failures=True,
    )
    detector = RuleDetector()
    result = detector.evaluate_window(wf)

    assert result.is_suspicious is True
    assert RULE_R002 in result.triggered_rules
    assert any("R002" in r for r in result.detection_reasons)


# ---------------------------------------------------------------------------
# Test 16: Successful Login Without Sufficient Preceding Failures Does Not Trigger R002
# ---------------------------------------------------------------------------

def test_success_without_sufficient_preceding_failures_does_not_trigger_r002():
    """success_after_failures == False does not trigger R002."""
    wf = make_window_features(
        total_attempts=3,
        failed_login_count=2,
        successful_login_count=1,
        failure_ratio=round(2 / 3, 4),
        success_after_failures=False,
    )
    detector = RuleDetector()
    result = detector.evaluate_window(wf)

    assert result.is_suspicious is False
    assert RULE_R002 not in result.triggered_rules


# ---------------------------------------------------------------------------
# Test 17: Multiple Rules Can Trigger Independently
# ---------------------------------------------------------------------------

def test_multiple_rules_trigger_independently():
    """Both R001 and R002 trigger simultaneously when both conditions are satisfied."""
    # 15 failures (> 10) AND a successful login following them
    wf = make_window_features(
        total_attempts=16,
        failed_login_count=15,
        successful_login_count=1,
        failure_ratio=round(15 / 16, 4),
        success_after_failures=True,
    )
    detector = RuleDetector()
    result = detector.evaluate_window(wf)

    assert result.is_suspicious is True
    assert set(result.triggered_rules) == {RULE_R001, RULE_R002}
    assert len(result.detection_reasons) == 2


# ---------------------------------------------------------------------------
# Test 18: Normal Activity Does Not Generate False Rule Alerts
# ---------------------------------------------------------------------------

def test_normal_activity_does_not_generate_false_alerts():
    """Normal logins (low volume, few/zero failures) do not trigger any rules."""
    normal_events = generate_normal_events(count=5, seed=42)
    results = detect_suspicious_activity(normal_events)

    for r in results:
        assert r.is_suspicious is False
        assert len(r.triggered_rules) == 0
        assert len(r.detection_reasons) == 0


# ---------------------------------------------------------------------------
# Test 19: Threshold Configuration Changes Behaviour Correctly
# ---------------------------------------------------------------------------

def test_threshold_configuration_changes_behaviour():
    """Custom RuleDetectorConfig thresholds alter detection sensitivity as expected."""
    # Default threshold (10) would not trigger on 8 failures
    wf_8 = make_window_features(total_attempts=8, failed_login_count=8, successful_login_count=0)

    default_detector = RuleDetector()
    assert default_detector.evaluate_window(wf_8).is_suspicious is False

    # Custom sensitive threshold: brute_force_failure_threshold=5
    custom_cfg = RuleDetectorConfig(
        brute_force_failure_threshold=5,
        min_preceding_failures_for_suspicious_success=3,
    )
    custom_detector = RuleDetector(config=custom_cfg)
    custom_res = custom_detector.evaluate_window(wf_8)

    assert custom_res.is_suspicious is True
    assert RULE_R001 in custom_res.triggered_rules

    # Test invalid config values rejected
    with pytest.raises(ValueError, match="brute_force_failure_threshold must be a positive integer"):
        RuleDetectorConfig(brute_force_failure_threshold=0)

    with pytest.raises(ValueError, match="min_preceding_failures_for_suspicious_success must be a positive integer"):
        RuleDetectorConfig(min_preceding_failures_for_suspicious_success=-1)


# ---------------------------------------------------------------------------
# Test 20: Detection Output Contains Supporting Evidence and Reasons
# ---------------------------------------------------------------------------

def test_detection_output_contains_supporting_evidence_and_reasons():
    """DetectionResult contains all required metadata, human-readable reasons, and features."""
    start_time = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
    brute_force_events = generate_brute_force_events(
        count=50,
        base_timestamp=start_time,
        duration_seconds=50.0,
        seed=123,
    )

    results = detect_suspicious_activity(brute_force_events)
    assert len(results) >= 1

    r = results[0]
    assert r.is_suspicious is True
    assert RULE_R001 in r.triggered_rules
    assert len(r.detection_reasons) >= 1
    assert r.source_ip == brute_force_events[0].source_ip
    assert r.window_start == start_time
    assert r.window_end == start_time + timedelta(minutes=1)

    # Check extracted features attached
    assert r.features.total_attempts == 50
    assert r.features.failed_login_count == 50
    assert r.features.failure_ratio == 1.0

    # Verify dictionary serialization
    d = r.to_dict()
    assert d["is_suspicious"] is True
    assert "R001" in d["triggered_rules"]
    assert "features" in d
    assert d["features"]["failed_login_count"] == 50

