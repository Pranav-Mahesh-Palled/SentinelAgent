"""Rule-based suspicious activity detection for SentinelAgent.

Evaluates behavioral window features against heuristic detection rules independently of ML:
- Rule R001: SSH Brute Force (failed_login_count > 10 in a 1-minute window).
- Rule R002: Success After Repeated Failures (success_after_failures == True).

All thresholds are fully configurable through RuleDetectorConfig with documented rationales.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Sequence

from app.services.feature_extractor import (
    FeatureExtractor,
    FeatureExtractorConfig,
    WindowFeatures,
)

# Rule Identifiers
RULE_R001 = "R001"
RULE_R002 = "R002"


@dataclass(frozen=True)
class RuleDetectorConfig:
    """Configurable thresholds for rule-based suspicious activity detection."""

    brute_force_failure_threshold: int = 10
    """Threshold for R001: Triggered when failed_login_count strictly exceeds this count within 1 minute (default: 10).
    Rationale: Legitimate interactive users rarely fail authentication more than 3-5 times consecutively. Exceeding 10
    failures within 60 seconds indicates high-velocity automated credential stuffing or dictionary attacks."""

    min_preceding_failures_for_suspicious_success: int = 5
    """Threshold for R002: Preceding failures required before a success is flagged (default: 5).
    Rationale: A successful login immediately preceded by multiple failed attempts is a classic indicator of a successful
    password guess or account compromise following brute force."""

    def __post_init__(self) -> None:
        if not isinstance(self.brute_force_failure_threshold, int) or self.brute_force_failure_threshold <= 0:
            raise ValueError(
                f"brute_force_failure_threshold must be a positive integer, got {self.brute_force_failure_threshold}"
            )
        if (
            not isinstance(self.min_preceding_failures_for_suspicious_success, int)
            or self.min_preceding_failures_for_suspicious_success <= 0
        ):
            raise ValueError(
                "min_preceding_failures_for_suspicious_success must be a positive integer, "
                f"got {self.min_preceding_failures_for_suspicious_success}"
            )


@dataclass(frozen=True)
class DetectionResult:
    """Result of rule-based suspicious activity evaluation for a single time window."""

    is_suspicious: bool
    triggered_rules: tuple[str, ...]
    detection_reasons: tuple[str, ...]
    source_ip: str
    window_start: datetime
    window_end: datetime
    features: WindowFeatures

    def to_dict(self) -> dict[str, Any]:
        """Convert detection result to dictionary representation."""
        return {
            "is_suspicious": self.is_suspicious,
            "triggered_rules": list(self.triggered_rules),
            "detection_reasons": list(self.detection_reasons),
            "source_ip": self.source_ip,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "features": self.features.to_dict(),
        }


class RuleDetector:
    """Evaluates behavioral window features against configured cybersecurity rules."""

    def __init__(self, config: Optional[RuleDetectorConfig] = None) -> None:
        self.config = config or RuleDetectorConfig()
        self.extractor = FeatureExtractor(
            config=FeatureExtractorConfig(
                min_preceding_failures=self.config.min_preceding_failures_for_suspicious_success
            )
        )

    def evaluate_window(self, features: WindowFeatures) -> DetectionResult:
        """Evaluate a single WindowFeatures record against all detection rules."""
        triggered: list[str] = []
        reasons: list[str] = []

        # RULE R001: SSH Brute Force
        if features.failed_login_count > self.config.brute_force_failure_threshold:
            triggered.append(RULE_R001)
            reasons.append(
                f"R001 (SSH Brute Force): {features.failed_login_count} failed logins in 1-minute window "
                f"exceeds threshold of {self.config.brute_force_failure_threshold}."
            )

        # RULE R002: Success After Repeated Failures
        if features.success_after_failures:
            triggered.append(RULE_R002)
            reasons.append(
                f"R002 (Success After Repeated Failures): Successful login detected following "
                f"{self.config.min_preceding_failures_for_suspicious_success}+ preceding failures."
            )

        return DetectionResult(
            is_suspicious=len(triggered) > 0,
            triggered_rules=tuple(triggered),
            detection_reasons=tuple(reasons),
            source_ip=features.source_ip,
            window_start=features.window_start,
            window_end=features.window_end,
            features=features,
        )

    def evaluate_windows(self, windows: Sequence[WindowFeatures]) -> list[DetectionResult]:
        """Evaluate a sequence of pre-computed WindowFeatures records."""
        return [self.evaluate_window(w) for w in windows]

    def evaluate_events(self, events: Sequence[Any]) -> list[DetectionResult]:
        """Extract features from raw events and evaluate them against all rules."""
        windows = self.extractor.extract_features(events)
        return self.evaluate_windows(windows)


def detect_suspicious_activity(
    events: Sequence[Any],
    *,
    config: Optional[RuleDetectorConfig] = None,
) -> list[DetectionResult]:
    """Convenience function to extract features and detect suspicious activity directly from events."""
    detector = RuleDetector(config=config)
    return detector.evaluate_events(events)

