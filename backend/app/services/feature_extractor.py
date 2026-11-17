"""Feature extraction module for SentinelAgent.

Extracts typed, behavioral security features grouped by source IP and fixed
one-minute UTC time windows from raw or synthetic SSH authentication events.

Features extracted:
1. total_attempts
2. failed_login_count
3. successful_login_count
4. distinct_usernames
5. failure_ratio
6. success_after_failures
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence
import uuid


@dataclass(frozen=True)
class FeatureExtractorConfig:
    """Configuration for feature extraction rules."""

    min_preceding_failures: int = 5
    """Number of preceding failed logins required within the window to flag success_after_failures (default: 5)."""

    def __post_init__(self) -> None:
        if not isinstance(self.min_preceding_failures, int) or self.min_preceding_failures <= 0:
            raise ValueError(
                f"min_preceding_failures must be a positive integer, got {self.min_preceding_failures}"
            )


@dataclass(frozen=True)
class WindowFeatures:
    """Extracted behavioral features for a source IP within a fixed UTC time window."""

    source_ip: str
    window_start: datetime
    window_end: datetime
    total_attempts: int
    failed_login_count: int
    successful_login_count: int
    distinct_usernames: int
    failure_ratio: float
    success_after_failures: bool
    event_ids: tuple[uuid.UUID, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Convert extracted features to dictionary representation."""
        return {
            "source_ip": self.source_ip,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "total_attempts": self.total_attempts,
            "failed_login_count": self.failed_login_count,
            "successful_login_count": self.successful_login_count,
            "distinct_usernames": self.distinct_usernames,
            "failure_ratio": self.failure_ratio,
            "success_after_failures": self.success_after_failures,
            "event_ids": [str(eid) for eid in self.event_ids],
        }


def _extract_event_fields(event: Any) -> tuple[Optional[uuid.UUID], datetime, str, str, str, str]:
    """Safely extract and validate required fields from SSHEvent, SyntheticSSHEvent, or dict."""
    if isinstance(event, dict):
        event_id = event.get("event_id")
        ts = event.get("event_timestamp")
        source_ip = event.get("source_ip")
        username = event.get("username")
        auth_result = event.get("authentication_result")
        event_type = event.get("event_type", "password")
    else:
        event_id = getattr(event, "event_id", None)
        ts = getattr(event, "event_timestamp", None)
        source_ip = getattr(event, "source_ip", None)
        username = getattr(event, "username", None)
        auth_result = getattr(event, "authentication_result", None)
        event_type = getattr(event, "event_type", "password")

    if not isinstance(ts, datetime):
        raise ValueError(f"event_timestamp must be a datetime instance, got {type(ts).__name__}")
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("event_timestamp must be timezone-aware (tzinfo cannot be None)")

    if source_ip is None or not str(source_ip).strip():
        raise ValueError("source_ip cannot be empty")
    source_ip_str = str(source_ip).strip()

    if not isinstance(username, str) or len(username) == 0:
        raise ValueError("username must be a non-empty string")

    if auth_result not in ("success", "failure"):
        raise ValueError(f"authentication_result must be 'success' or 'failure', got '{auth_result}'")

    parsed_id: Optional[uuid.UUID] = None
    if event_id is not None:
        if isinstance(event_id, uuid.UUID):
            parsed_id = event_id
        elif isinstance(event_id, str):
            parsed_id = uuid.UUID(event_id)

    # Normalize timestamp to UTC for consistent window bucketing
    ts_utc = ts.astimezone(timezone.utc)
    return parsed_id, ts_utc, source_ip_str, username, auth_result, str(event_type)


class FeatureExtractor:
    """Extracts security features across fixed one-minute UTC windows per source IP."""

    def __init__(self, config: Optional[FeatureExtractorConfig] = None) -> None:
        self.config = config or FeatureExtractorConfig()

    def extract_features(self, events: Sequence[Any]) -> list[WindowFeatures]:
        """Group events by (source_ip, 1-min UTC window) and extract security features.

        Guarantees:
        - Out-of-order events are sorted chronologically before sequential feature evaluation.
        - Division by zero is avoided (failure_ratio = 0.0 when total_attempts = 0).
        - Results are deterministic and input events are never mutated.
        """
        if not events:
            return []

        # 1. Validate, normalize, and bucket events into (source_ip, window_start) groups
        buckets: dict[tuple[str, datetime], list[tuple[Optional[uuid.UUID], datetime, str, str, str, str]]] = (
            defaultdict(list)
        )

        for ev in events:
            ev_id, ts_utc, ip_str, user, auth, ev_type = _extract_event_fields(ev)
            # Fixed 1-minute UTC window boundary
            window_start = ts_utc.replace(second=0, microsecond=0)
            buckets[(ip_str, window_start)].append((ev_id, ts_utc, ip_str, user, auth, ev_type))

        # 2. Extract features per window
        results: list[WindowFeatures] = []

        # Sort bucket keys for deterministic output ordering
        for (source_ip, window_start) in sorted(buckets.keys(), key=lambda k: (k[1], k[0])):
            group_events = buckets[(source_ip, window_start)]

            # Sort chronologically within the window
            group_events.sort(key=lambda item: item[1])

            window_end = window_start + timedelta(minutes=1)
            total_attempts = len(group_events)
            failed_login_count = sum(1 for e in group_events if e[4] == "failure")
            successful_login_count = sum(1 for e in group_events if e[4] == "success")
            distinct_usernames = len(set(e[3] for e in group_events))

            failure_ratio = (
                round(failed_login_count / total_attempts, 4)
                if total_attempts > 0
                else 0.0
            )

            # Evaluate success_after_failures:
            # Did a success occur after at least min_preceding_failures in this window?
            consecutive_failures = 0
            success_after_failures = False
            for e in group_events:
                auth = e[4]
                if auth == "failure":
                    consecutive_failures += 1
                elif auth == "success":
                    if consecutive_failures >= self.config.min_preceding_failures:
                        success_after_failures = True
                    consecutive_failures = 0

            event_ids = tuple(e[0] for e in group_events if e[0] is not None)

            results.append(
                WindowFeatures(
                    source_ip=source_ip,
                    window_start=window_start,
                    window_end=window_end,
                    total_attempts=total_attempts,
                    failed_login_count=failed_login_count,
                    successful_login_count=successful_login_count,
                    distinct_usernames=distinct_usernames,
                    failure_ratio=failure_ratio,
                    success_after_failures=success_after_failures,
                    event_ids=event_ids,
                )
            )

        return results


def extract_window_features(
    events: Sequence[Any],
    *,
    config: Optional[FeatureExtractorConfig] = None,
    min_preceding_failures: Optional[int] = None,
) -> list[WindowFeatures]:
    """Functional convenience wrapper for extracting windowed features."""
    if min_preceding_failures is not None:
        cfg = FeatureExtractorConfig(min_preceding_failures=min_preceding_failures)
    else:
        cfg = config or FeatureExtractorConfig()
    return FeatureExtractor(config=cfg).extract_features(events)

