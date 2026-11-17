"""Synthetic SSH authentication event generator for SentinelAgent.

Generates realistic, reproducible synthetic SSH authentication events compatible
with the existing PostgreSQL SSHEvent model schema.

Architectural Rule:
This module solely produces event data representations in memory.
It does NOT write to or interact directly with the database.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import random
from typing import Any, Optional, Sequence
import uuid

from app.models.ssh_event import SSHEvent

# Reserved RFC 5737 documentation IPv4 blocks.
# Ensures synthetic events never target or simulate real external systems.
DOC_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),    # TEST-NET-3
)

DEFAULT_NORMAL_USERNAMES: tuple[str, ...] = (
    "secops_admin",
    "developer",
    "deploy_bot",
    "ubuntu",
    "sysadmin",
    "analyst",
    "backup_svc",
)

DEFAULT_BRUTE_FORCE_USERNAMES: tuple[str, ...] = (
    "root",
    "admin",
    "test",
    "guest",
    "oracle",
    "postgres",
    "user",
    "service",
    "ftpuser",
    "git",
    "support",
)

DEFAULT_EVENT_TYPES: tuple[str, ...] = (
    "password",
    "publickey",
    "keyboard-interactive",
)


@dataclass(frozen=True)
class SyntheticSSHEvent:
    """Immutable, strongly-typed representation of a synthetic SSH event.

    Strictly satisfies the constraints of the PostgreSQL ssh_events schema:
    - Valid RFC 4122 UUID primary key.
    - Timezone-aware UTC event timestamp.
    - Valid IPv4 address from reserved documentation blocks (RFC 5737).
    - Non-empty username up to 128 characters.
    - Authentication result strictly 'success' or 'failure'.
    - Event type up to 32 characters.
    """

    event_id: uuid.UUID
    event_timestamp: datetime
    source_ip: str
    username: str
    authentication_result: str
    event_type: str

    def __post_init__(self) -> None:
        """Validate all fields against schema rules upon instantiation."""
        if not isinstance(self.event_id, uuid.UUID):
            raise ValueError(f"event_id must be a UUID instance, got {type(self.event_id).__name__}")

        if not isinstance(self.event_timestamp, datetime):
            raise ValueError(f"event_timestamp must be a datetime instance, got {type(self.event_timestamp).__name__}")
        if self.event_timestamp.tzinfo is None:
            raise ValueError("event_timestamp must be timezone-aware (tzinfo cannot be None)")

        # Validate IPv4 address and RFC 5737 documentation block constraint
        try:
            addr = ipaddress.IPv4Address(self.source_ip)
            if not any(addr in net for net in DOC_NETWORKS):
                raise ValueError(
                    f"source_ip '{self.source_ip}' is outside reserved documentation blocks (RFC 5737)"
                )
        except ipaddress.AddressValueError as err:
            raise ValueError(f"Invalid IPv4 address '{self.source_ip}'") from err

        # Validate username
        if not isinstance(self.username, str) or len(self.username) == 0 or len(self.username) > 128:
            raise ValueError("username must be a non-empty string with maximum length of 128 characters")

        # Validate authentication_result
        if self.authentication_result not in ("success", "failure"):
            raise ValueError(
                f"authentication_result must be 'success' or 'failure', got '{self.authentication_result}'"
            )

        # Validate event_type
        if not isinstance(self.event_type, str) or len(self.event_type) == 0 or len(self.event_type) > 32:
            raise ValueError("event_type must be a non-empty string with maximum length of 32 characters")

    def to_dict(self) -> dict[str, Any]:
        """Return event dictionary matching SSHEvent column definitions."""
        return {
            "event_id": self.event_id,
            "event_timestamp": self.event_timestamp,
            "source_ip": self.source_ip,
            "username": self.username,
            "authentication_result": self.authentication_result,
            "event_type": self.event_type,
        }

    def to_model(self) -> SSHEvent:
        """Instantiate an uncommitted SQLAlchemy SSHEvent model instance.

        Does not persist or write to the database.
        """
        return SSHEvent(
            event_id=self.event_id,
            event_timestamp=self.event_timestamp,
            source_ip=self.source_ip,
            username=self.username,
            authentication_result=self.authentication_result,
            event_type=self.event_type,
        )


def _validate_source_ip(ip_str: Optional[str]) -> Optional[str]:
    """Validate that custom source_ip is a valid documentation IPv4 address."""
    if ip_str is None:
        return None
    try:
        addr = ipaddress.IPv4Address(ip_str)
        if not any(addr in net for net in DOC_NETWORKS):
            raise ValueError(
                f"source_ip '{ip_str}' is outside reserved documentation blocks (RFC 5737)"
            )
        return str(addr)
    except ipaddress.AddressValueError as err:
        raise ValueError(f"Invalid IPv4 address '{ip_str}'") from err


def _validate_timestamp(ts: Optional[datetime]) -> datetime:
    """Ensure timestamp is valid and timezone-aware."""
    if ts is None:
        return datetime.now(timezone.utc)
    if not isinstance(ts, datetime):
        raise ValueError(f"base_timestamp must be a datetime instance, got {type(ts).__name__}")
    if ts.tzinfo is None:
        raise ValueError("base_timestamp must be timezone-aware (tzinfo cannot be None)")
    return ts


def _validate_positive_int(val: int, name: str) -> None:
    """Ensure integer argument is strictly positive."""
    if not isinstance(val, int) or val <= 0:
        raise ValueError(f"{name} must be a positive integer, got {val}")


class SSHEventGenerator:
    """Reproducible generator for synthetic SSH authentication events.

    Uses an isolated random.Random instance for all operations to ensure
    deterministic, reproducible test scenarios without mutating global state.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        """Initialize generator with an optional integer seed."""
        self._rng = random.Random(seed)

    def random_synthetic_ip(self) -> str:
        """Generate a random IPv4 address within RFC 5737 documentation ranges."""
        net = self._rng.choice(DOC_NETWORKS)
        host = self._rng.randint(1, 254)
        return str(net.network_address + host)

    def random_uuid(self) -> uuid.UUID:
        """Generate a deterministic version-4 UUID backed by this generator's RNG."""
        return uuid.UUID(int=self._rng.getrandbits(128), version=4)

    def generate_normal_events(
        self,
        count: int = 10,
        *,
        base_timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        failure_rate: float = 0.0,
        usernames: Optional[Sequence[str]] = None,
        event_types: Optional[Sequence[str]] = None,
    ) -> list[SyntheticSSHEvent]:
        """Generate normal authentication events.

        Scenarios covered:
        - A: Normal successful logins (when failure_rate == 0.0).
        - B: Occasional failed logins (when failure_rate > 0.0).
        """
        _validate_positive_int(count, "count")
        if not (0.0 <= failure_rate <= 1.0):
            raise ValueError(f"failure_rate must be between 0.0 and 1.0, got {failure_rate}")

        valid_ip = _validate_source_ip(source_ip)
        current_time = _validate_timestamp(base_timestamp)
        user_pool = tuple(usernames) if usernames else DEFAULT_NORMAL_USERNAMES
        type_pool = tuple(event_types) if event_types else DEFAULT_EVENT_TYPES

        events: list[SyntheticSSHEvent] = []
        for _ in range(count):
            # Advance time chronologically (10 to 60 seconds interval)
            current_time = current_time + timedelta(seconds=self._rng.uniform(10.0, 60.0))
            ip = valid_ip if valid_ip is not None else self.random_synthetic_ip()
            username = self._rng.choice(user_pool)
            event_type = self._rng.choice(type_pool)

            auth_result = (
                "failure"
                if failure_rate > 0.0 and self._rng.random() < failure_rate
                else "success"
            )

            events.append(
                SyntheticSSHEvent(
                    event_id=self.random_uuid(),
                    event_timestamp=current_time,
                    source_ip=ip,
                    username=username,
                    authentication_result=auth_result,
                    event_type=event_type,
                )
            )

        return events

    def generate_failed_events(
        self,
        count: int = 5,
        *,
        base_timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        duration_seconds: float = 30.0,
    ) -> list[SyntheticSSHEvent]:
        """Generate repeated failed logins from a common source IP (Scenario C)."""
        _validate_positive_int(count, "count")
        if duration_seconds <= 0:
            raise ValueError(f"duration_seconds must be positive, got {duration_seconds}")

        common_ip = _validate_source_ip(source_ip) or self.random_synthetic_ip()
        start_time = _validate_timestamp(base_timestamp)
        target_user = username if username else self._rng.choice(DEFAULT_NORMAL_USERNAMES)

        # Generate strictly chronological timestamp offsets
        offsets = sorted(self._rng.uniform(0.0, duration_seconds) for _ in range(count))

        events: list[SyntheticSSHEvent] = []
        for offset in offsets:
            events.append(
                SyntheticSSHEvent(
                    event_id=self.random_uuid(),
                    event_timestamp=start_time + timedelta(seconds=offset),
                    source_ip=common_ip,
                    username=target_user,
                    authentication_result="failure",
                    event_type="password",
                )
            )

        return events

    def generate_brute_force_events(
        self,
        count: int = 50,
        *,
        base_timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        target_usernames: Optional[Sequence[str]] = None,
        duration_seconds: float = 60.0,
    ) -> list[SyntheticSSHEvent]:
        """Generate rapid failed login attempts from a single source IP (Scenario D).

        Defaults to approximately 50 events in a 60-second window across multiple usernames.
        """
        _validate_positive_int(count, "count")
        if duration_seconds <= 0:
            raise ValueError(f"duration_seconds must be positive, got {duration_seconds}")

        common_ip = _validate_source_ip(source_ip) or self.random_synthetic_ip()
        start_time = _validate_timestamp(base_timestamp)
        user_pool = tuple(target_usernames) if target_usernames else DEFAULT_BRUTE_FORCE_USERNAMES

        # Generate chronological timestamp offsets within the window
        offsets = sorted(self._rng.uniform(0.0, duration_seconds) for _ in range(count))

        events: list[SyntheticSSHEvent] = []
        for offset in offsets:
            events.append(
                SyntheticSSHEvent(
                    event_id=self.random_uuid(),
                    event_timestamp=start_time + timedelta(seconds=offset),
                    source_ip=common_ip,
                    username=self._rng.choice(user_pool),
                    authentication_result="failure",
                    event_type="password",
                )
            )

        return events

    def generate_suspicious_success_events(
        self,
        failure_count: int = 8,
        *,
        base_timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        target_username: str = "admin",
        duration_seconds: float = 45.0,
    ) -> list[SyntheticSSHEvent]:
        """Generate repeated authentication failures followed by a successful login (Scenario E).

        Chronologically orders failures prior to the success event from a common source IP.
        """
        _validate_positive_int(failure_count, "failure_count")
        if duration_seconds <= 0:
            raise ValueError(f"duration_seconds must be positive, got {duration_seconds}")
        if not target_username or len(target_username) > 128:
            raise ValueError("target_username must be non-empty and <= 128 characters")

        common_ip = _validate_source_ip(source_ip) or self.random_synthetic_ip()
        start_time = _validate_timestamp(base_timestamp)

        # Distribute failures over 80% of the window
        failure_window = duration_seconds * 0.8
        offsets = sorted(self._rng.uniform(0.0, failure_window) for _ in range(failure_count))

        events: list[SyntheticSSHEvent] = []
        for offset in offsets:
            events.append(
                SyntheticSSHEvent(
                    event_id=self.random_uuid(),
                    event_timestamp=start_time + timedelta(seconds=offset),
                    source_ip=common_ip,
                    username=target_username,
                    authentication_result="failure",
                    event_type="password",
                )
            )

        # Final event: successful authentication after the failures
        events.append(
            SyntheticSSHEvent(
                event_id=self.random_uuid(),
                event_timestamp=start_time + timedelta(seconds=duration_seconds),
                source_ip=common_ip,
                username=target_username,
                authentication_result="success",
                event_type="password",
            )
        )

        return events

    def generate_event_batch(
        self,
        *,
        scenario: str = "mixed",
        normal_count: int = 20,
        include_brute_force: bool = False,
        include_suspicious_success: bool = False,
        base_timestamp: Optional[datetime] = None,
    ) -> list[SyntheticSSHEvent]:
        """Generate an aggregated batch of events sorted in chronological order."""
        start_time = _validate_timestamp(base_timestamp)
        all_events: list[SyntheticSSHEvent] = []

        if scenario in ("normal", "mixed"):
            all_events.extend(
                self.generate_normal_events(
                    count=normal_count,
                    base_timestamp=start_time,
                    failure_rate=0.05 if scenario == "mixed" else 0.0,
                )
            )

        if include_brute_force or scenario == "brute_force":
            all_events.extend(
                self.generate_brute_force_events(
                    count=50,
                    base_timestamp=start_time + timedelta(seconds=15.0),
                )
            )

        if include_suspicious_success or scenario == "suspicious_success":
            all_events.extend(
                self.generate_suspicious_success_events(
                    failure_count=10,
                    base_timestamp=start_time + timedelta(seconds=80.0),
                )
            )

        # Ensure all events in the aggregated batch are chronologically sorted
        all_events.sort(key=lambda ev: ev.event_timestamp)
        return all_events


# ---------------------------------------------------------------------------
# Module-level convenience functions with optional random seed
# ---------------------------------------------------------------------------

def generate_normal_events(
    count: int = 10,
    *,
    base_timestamp: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    failure_rate: float = 0.0,
    usernames: Optional[Sequence[str]] = None,
    event_types: Optional[Sequence[str]] = None,
    seed: Optional[int] = None,
) -> list[SyntheticSSHEvent]:
    """Generate normal authentication events with optional random seed."""
    generator = SSHEventGenerator(seed=seed)
    return generator.generate_normal_events(
        count=count,
        base_timestamp=base_timestamp,
        source_ip=source_ip,
        failure_rate=failure_rate,
        usernames=usernames,
        event_types=event_types,
    )


def generate_failed_events(
    count: int = 5,
    *,
    base_timestamp: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    duration_seconds: float = 30.0,
    seed: Optional[int] = None,
) -> list[SyntheticSSHEvent]:
    """Generate repeated failed events from a common source IP with optional seed."""
    generator = SSHEventGenerator(seed=seed)
    return generator.generate_failed_events(
        count=count,
        base_timestamp=base_timestamp,
        source_ip=source_ip,
        username=username,
        duration_seconds=duration_seconds,
    )


def generate_brute_force_events(
    count: int = 50,
    *,
    base_timestamp: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    target_usernames: Optional[Sequence[str]] = None,
    duration_seconds: float = 60.0,
    seed: Optional[int] = None,
) -> list[SyntheticSSHEvent]:
    """Generate brute-force failed events within a time window with optional seed."""
    generator = SSHEventGenerator(seed=seed)
    return generator.generate_brute_force_events(
        count=count,
        base_timestamp=base_timestamp,
        source_ip=source_ip,
        target_usernames=target_usernames,
        duration_seconds=duration_seconds,
    )


def generate_suspicious_success_events(
    failure_count: int = 8,
    *,
    base_timestamp: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    target_username: str = "admin",
    duration_seconds: float = 45.0,
    seed: Optional[int] = None,
) -> list[SyntheticSSHEvent]:
    """Generate repeated failures followed by a success with optional seed."""
    generator = SSHEventGenerator(seed=seed)
    return generator.generate_suspicious_success_events(
        failure_count=failure_count,
        base_timestamp=base_timestamp,
        source_ip=source_ip,
        target_username=target_username,
        duration_seconds=duration_seconds,
    )


def generate_event_batch(
    *,
    scenario: str = "mixed",
    normal_count: int = 20,
    include_brute_force: bool = False,
    include_suspicious_success: bool = False,
    base_timestamp: Optional[datetime] = None,
    seed: Optional[int] = None,
) -> list[SyntheticSSHEvent]:
    """Generate an aggregated batch of synthetic events with optional seed."""
    generator = SSHEventGenerator(seed=seed)
    return generator.generate_event_batch(
        scenario=scenario,
        normal_count=normal_count,
        include_brute_force=include_brute_force,
        include_suspicious_success=include_suspicious_success,
        base_timestamp=base_timestamp,
    )

