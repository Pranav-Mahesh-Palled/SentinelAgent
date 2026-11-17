"""Deterministic MITRE ATT&CK Behavioral Mapping Engine for SentinelAgent.

Implements Task 8C (Audited & Hardened):
- Pure evaluation function operating on already-retrieved, authorized SSH events.
- Evaluates deterministic mapping rules MAP-SSH-001, MAP-SSH-002, and MAP-SSH-003.
- Enforces strict telemetry boundaries:
    * Zero password synthesis or credential reuse assumptions.
    * Strict source IP isolation (zero cross-IP failure leakage).
    * MAP-SSH-003 requires verified complete two-hour coverage; rejects evaluation if coverage is incomplete.
    * MAP-SSH-003 confidence remains strictly LOW (never elevated by failure count alone).
- Uses MitreCatalogueService for authoritative taxonomy metadata and active eligibility.
- RFC 4122 UUID5 deterministic fingerprinting for mapping proposals.
- Zero database sessions, zero external network requests, zero persistent side effects.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import uuid

from app.schemas.investigation import SSHEventRecord
from app.schemas.mitre import (
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.mitre_catalogue_service import MitreCatalogueService

logger = logging.getLogger(__name__)

# RFC 4122 UUID namespace for SentinelAgent MITRE ATT&CK mapping fingerprints
SENTINEL_MITRE_NAMESPACE = uuid.UUID("a2b3c4d5-e6f7-4a5b-8c9d-0e1f2a3b4c5d")

# Behavioral mapping rule identifiers
RULE_MAP_SSH_001 = "MAP-SSH-001"
RULE_MAP_SSH_002 = "MAP-SSH-002"
RULE_MAP_SSH_003 = "MAP-SSH-003"


@dataclass(frozen=True)
class EventRetrievalMetadata:
    """Metadata describing the boundaries, completeness, and truncation of the retrieved event set.

    Attributes:
        truncated: True if additional records existed beyond the tool limit.
        window_start: The earliest timestamp included in the authorized query interval.
        window_end: The latest timestamp included in the authorized query interval.
        coverage_complete: Explicit flag indicating whether the query scope completely covered
                           the target analysis interval without truncation or query bounds clipping.
        incident_id: Authoritative incident identifier for the retrieval.
        source_ip: Authoritative source IP for the retrieval.
    """

    truncated: bool = False
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    coverage_complete: bool = False
    incident_id: Optional[uuid.UUID] = None
    source_ip: Optional[str] = None


def compute_mapping_uuid5(
    investigation_id: uuid.UUID,
    catalogue_version: str,
    rule_id: str,
    technique_id: str,
    supporting_references: Sequence[str],
) -> uuid.UUID:
    """Generate a deterministic RFC 4122 UUID5 fingerprint for a candidate mapping.

    Args:
        investigation_id: UUID of the active investigation.
        catalogue_version: ATT&CK catalogue version string, e.g. '20.1'.
        rule_id: Mapping rule ID, e.g. 'MAP-SSH-001'.
        technique_id: Canonical ATT&CK technique ID, e.g. 'T1110'.
        supporting_references: Sequence of canonical source references ('ssh_events/<uuid>').

    Returns:
        Deterministic UUID5 instance.
    """
    sorted_refs = ",".join(sorted(supporting_references))
    seed = f"{investigation_id}:{catalogue_version}:{rule_id}:{technique_id}:{sorted_refs}"
    return uuid.uuid5(SENTINEL_MITRE_NAMESPACE, seed)


def _to_utc_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Validate and normalize datetime to UTC-aware datetime.

    Strict validation: Rejects naive datetimes (dt.tzinfo is None) to prevent
    subtle timezone bugs or implicit local offset conversions.
    """
    if dt is None:
        return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        # Naive datetime is strictly rejected per project datetime standards
        return None
    return dt.astimezone(timezone.utc)


def _validate_source_ip(ip_str: str) -> Optional[str]:
    """Validate IPv4 or IPv6 address string. Returns canonical IP string or None if invalid."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    trimmed = ip_str.strip()
    if not trimmed:
        return None
    try:
        parsed = ipaddress.ip_address(trimmed)
        return str(parsed)
    except ValueError:
        return None


class MitreMappingEngine:
    """Evaluates authorized SSH telemetry against MITRE ATT&CK behavioral mapping rules.

    Instantiable, pure evaluation engine:
    - Depends strictly on MitreCatalogueService.
    - Operates without database or network I/O.
    """

    def __init__(self, catalogue: MitreCatalogueService) -> None:
        """Initialize the mapping engine with an active MitreCatalogueService."""
        self._catalogue = catalogue
        self._catalogue_version = catalogue.version

    def evaluate(
        self,
        investigation_id: uuid.UUID,
        authorized_ssh_events: Sequence[SSHEventRecord],
        retrieval_metadata: Optional[EventRetrievalMetadata] = None,
    ) -> Tuple[MitreCandidateProposal, ...]:
        """Evaluate authorized SSH events and generate deterministic candidate proposals.

        Args:
            investigation_id: Active investigation identifier.
            authorized_ssh_events: Sequence of validated SSHEventRecord instances.
            retrieval_metadata: Optional retrieval bounding and truncation metadata.

        Returns:
            Deterministic tuple of MitreCandidateProposal records, sorted by rule_id and technique_id.
        """
        metadata = retrieval_metadata or EventRetrievalMetadata()

        # 1. Deduplicate events by event_id to prevent double counting
        unique_events_by_id: Dict[uuid.UUID, SSHEventRecord] = {}
        for ev in authorized_ssh_events:
            if not isinstance(ev.event_id, uuid.UUID):
                continue
            unique_events_by_id[ev.event_id] = ev

        # 2. Validate, normalize and group events by canonical source IP
        events_by_ip: Dict[str, List[SSHEventRecord]] = defaultdict(list)
        for ev in unique_events_by_id.values():
            canonical_ip = _validate_source_ip(ev.source_ip)
            if canonical_ip is None:
                # Reject invalid source IP safely without emitting fabricated evidence
                continue

            dt_utc = _to_utc_aware(ev.event_timestamp)
            if dt_utc is None:
                # Reject naive or malformed timestamps safely
                continue

            events_by_ip[canonical_ip].append(ev)

        proposals: List[MitreCandidateProposal] = []

        # 3. Evaluate each source IP independently (zero cross-IP aggregation)
        for ip, ip_events in events_by_ip.items():
            # Sort events deterministically by event_timestamp ASC, event_id ASC
            sorted_events = sorted(
                ip_events,
                key=lambda e: (_to_utc_aware(e.event_timestamp), str(e.event_id)),
            )

            # Evaluate MAP-SSH-001 (Brute Force Candidate -> T1110)
            p1 = self._evaluate_map_ssh_001(investigation_id, ip, sorted_events)
            if p1 is not None:
                proposals.append(p1)

            # Evaluate MAP-SSH-002 (Horizontal Spraying Hypothesis -> T1110.003)
            p2 = self._evaluate_map_ssh_002(investigation_id, ip, sorted_events)
            if p2 is not None:
                proposals.append(p2)

            # Evaluate MAP-SSH-003 (Valid Accounts Candidate -> T1078)
            p3 = self._evaluate_map_ssh_003(investigation_id, ip, sorted_events, metadata)
            if p3 is not None:
                proposals.append(p3)

        # Return deterministically sorted proposals
        return tuple(sorted(proposals, key=lambda p: (p.rule_id, p.technique_id, str(p.mapping_id))))

    # -------------------------------------------------------------------------
    # Rule Evaluation Methods
    # -------------------------------------------------------------------------

    def _evaluate_map_ssh_001(
        self,
        investigation_id: uuid.UUID,
        source_ip: str,
        events: List[SSHEventRecord],
    ) -> Optional[MitreCandidateProposal]:
        """MAP-SSH-001: Brute Force Candidate (T1110).

        Conditions:
        - Within a 15-minute sliding window (900 seconds):
          * >= 10 failed SSH authentication attempts from the same source IP.
          * <= 2 distinct targeted usernames.
        - Confidence:
          * 10-29 failures: MEDIUM.
          * >= 30 failures within 10 minutes: HIGH.
          * Supported status is strictly UNAVAILABLE under current telemetry.
        """
        # Filter strictly failed attempts
        failed_events = [e for e in events if e.authentication_result == "failure"]
        if len(failed_events) < 10:
            return None

        # Verify active technique eligibility in catalogue
        tech_id = "T1110"
        tech_record = self._catalogue.get_active_technique(tech_id)
        if not tech_record:
            return None

        tactic_names = self._resolve_tactic_names(tech_record.tactics)

        # Sliding window evaluation (15 minutes = 900 seconds)
        best_window_events: List[SSHEventRecord] = []
        n = len(failed_events)

        for i in range(n):
            current_window: List[SSHEventRecord] = []
            distinct_users: Set[str] = set()
            start_time = _to_utc_aware(failed_events[i].event_timestamp)

            for j in range(i, n):
                ev = failed_events[j]
                ev_time = _to_utc_aware(ev.event_timestamp)
                if (ev_time - start_time).total_seconds() > 900:
                    break

                distinct_users.add(ev.username)
                if len(distinct_users) <= 2:
                    current_window.append(ev)
                else:
                    # More than 2 usernames violates MAP-SSH-001 boundary
                    break

            if len(current_window) >= 10 and len(current_window) > len(best_window_events):
                best_window_events = current_window

        if len(best_window_events) < 10:
            return None

        # Determine confidence calibration:
        # Check if >= 30 failures occurred within a 10-minute window (600 seconds)
        calibrated_confidence = MitreConfidenceLevel.MEDIUM
        num_failures = len(best_window_events)

        if num_failures >= 30:
            first_time = _to_utc_aware(best_window_events[0].event_timestamp)
            last_time = _to_utc_aware(best_window_events[-1].event_timestamp)
            if (last_time - first_time).total_seconds() <= 600:
                calibrated_confidence = MitreConfidenceLevel.HIGH
            else:
                for k in range(len(best_window_events) - 29):
                    slice_start = _to_utc_aware(best_window_events[k].event_timestamp)
                    slice_end = _to_utc_aware(best_window_events[k + 29].event_timestamp)
                    if (slice_end - slice_start).total_seconds() <= 600:
                        calibrated_confidence = MitreConfidenceLevel.HIGH
                        break

        event_ids = [e.event_id for e in best_window_events]
        supporting_refs = [f"ssh_events/{eid}" for eid in event_ids]

        window_start = _to_utc_aware(best_window_events[0].event_timestamp)
        window_end = _to_utc_aware(best_window_events[-1].event_timestamp)

        distinct_targets = sorted(list({e.username for e in best_window_events}))
        rationale = (
            f"Observed {num_failures} failed SSH authentication attempts from source IP {source_ip} "
            f"within a 15-minute window targeting {len(distinct_targets)} username(s) ({', '.join(distinct_targets)}). "
            f"Pattern satisfies MAP-SSH-001 candidate criteria for T1110 (Brute Force). "
            f"Under 6-field SSH telemetry, authentication method is not captured, so specific password-guessing "
            f"sub-technique (T1110.001) is not asserted, and supported status remains unavailable."
        )

        mapping_id = compute_mapping_uuid5(
            investigation_id=investigation_id,
            catalogue_version=self._catalogue_version,
            rule_id=RULE_MAP_SSH_001,
            technique_id=tech_id,
            supporting_references=supporting_refs,
        )

        return MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id=RULE_MAP_SSH_001,
            technique_id=tech_id,
            technique_name=tech_record.name,
            tactic_ids=tech_record.tactics,
            tactic_names=tactic_names,
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=calibrated_confidence,
            supporting_references=supporting_refs,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
            rationale=rationale,
            catalogue_version=self._catalogue_version,
        )

    def _evaluate_map_ssh_002(
        self,
        investigation_id: uuid.UUID,
        source_ip: str,
        events: List[SSHEventRecord],
    ) -> Optional[MitreCandidateProposal]:
        """MAP-SSH-002: Horizontal Authentication Hypothesis (T1110.003).

        Conditions:
        - Within a 30-minute sliding window (1800 seconds):
          * >= 5 distinct usernames targeted from the same source IP.
          * <= 3 failed attempts per targeted username.
        - Classification:
          * Mapping status: strictly HYPOTHESIS.
          * Confidence: strictly MEDIUM (never High, never Supported).
          * Mandatory disclosure: password reuse cannot be verified from available telemetry.
        """
        failed_events = [e for e in events if e.authentication_result == "failure"]
        if len(failed_events) < 5:
            return None

        tech_id = "T1110.003"
        tech_record = self._catalogue.get_active_technique(tech_id)
        if not tech_record:
            return None

        tactic_names = self._resolve_tactic_names(tech_record.tactics)

        # Sliding window evaluation (30 minutes = 1800 seconds)
        n = len(failed_events)
        best_window_events: List[SSHEventRecord] = []
        best_user_count = 0

        for i in range(n):
            current_window: List[SSHEventRecord] = []
            user_counts: Dict[str, int] = defaultdict(int)
            start_time = _to_utc_aware(failed_events[i].event_timestamp)

            for j in range(i, n):
                ev = failed_events[j]
                ev_time = _to_utc_aware(ev.event_timestamp)
                if (ev_time - start_time).total_seconds() > 1800:
                    break

                if user_counts[ev.username] + 1 > 3:
                    continue

                user_counts[ev.username] += 1
                current_window.append(ev)

            distinct_users = len(user_counts)
            if distinct_users >= 5 and distinct_users > best_user_count:
                best_user_count = distinct_users
                best_window_events = current_window

        if best_user_count < 5:
            return None

        event_ids = [e.event_id for e in best_window_events]
        supporting_refs = [f"ssh_events/{eid}" for eid in event_ids]

        window_start = _to_utc_aware(best_window_events[0].event_timestamp)
        window_end = _to_utc_aware(best_window_events[-1].event_timestamp)

        distinct_targets = sorted(list({e.username for e in best_window_events}))
        rationale = (
            f"Observed horizontal multi-user authentication failures from source IP {source_ip} "
            f"targeting {best_user_count} distinct usernames ({', '.join(distinct_targets[:8])}) "
            f"with at most 3 failed attempts per user within 30 minutes. "
            f"Observed horizontal multi-user authentication failures are consistent with password spraying; "
            f"password reuse cannot be verified from available telemetry."
        )

        mapping_id = compute_mapping_uuid5(
            investigation_id=investigation_id,
            catalogue_version=self._catalogue_version,
            rule_id=RULE_MAP_SSH_002,
            technique_id=tech_id,
            supporting_references=supporting_refs,
        )

        return MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id=RULE_MAP_SSH_002,
            technique_id=tech_id,
            technique_name=tech_record.name,
            tactic_ids=tech_record.tactics,
            tactic_names=tactic_names,
            mapping_status=MitreMappingStatus.HYPOTHESIS,
            confidence=MitreConfidenceLevel.MEDIUM,
            supporting_references=supporting_refs,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
            rationale=rationale,
            catalogue_version=self._catalogue_version,
        )

    def _evaluate_map_ssh_003(
        self,
        investigation_id: uuid.UUID,
        source_ip: str,
        events: List[SSHEventRecord],
        metadata: EventRetrievalMetadata,
    ) -> Optional[MitreCandidateProposal]:
        """MAP-SSH-003: Valid Accounts Candidate (T1078).

        Conditions:
        - A successful SSH authentication (authentication_result == "success").
        - Preceded by >= 5 failed authentication attempts from the same source IP.
        - Failures must strictly precede the successful event.
        - Complete Two-Hour Coverage Verification:
            The authorized retrieval interval MUST be verified to completely cover the required
            preceding 2-hour interval [success_time - 2h, success_time].
            If metadata.truncated is True, or if retrieval bounds do not start <= (success_time - 2h),
            or if coverage_complete is False, the rule CANNOT be safely evaluated and produces None.
        - Confidence:
            Strictly LOW.
            Thirty failed attempts alone do not establish valid-account abuse.
            In the absence of multi-source corroborating detection evidence or host command telemetry,
            confidence remains strictly LOW (never elevated by event volume alone, never High, never Supported).
        """
        # Find successful authentication events
        success_indices = [i for i, e in enumerate(events) if e.authentication_result == "success"]
        if not success_indices:
            return None

        tech_id = "T1078"
        tech_record = self._catalogue.get_active_technique(tech_id)
        if not tech_record:
            return None

        tactic_names = self._resolve_tactic_names(tech_record.tactics)

        # For each success event, verify complete two-hour preceding interval coverage
        # and gather qualifying preceding failures
        best_candidate: Optional[Tuple[SSHEventRecord, List[SSHEventRecord]]] = None
        max_preceding_failures = 0

        for s_idx in success_indices:
            success_ev = events[s_idx]
            success_time = _to_utc_aware(success_ev.event_timestamp)
            required_start_time = success_time - timedelta(hours=2)

            # 1. Verification of Complete Two-Hour Coverage
            # Truncated retrieval means events were dropped at tool limit; coverage is incomplete
            if metadata.truncated:
                continue

            # Must have explicit coverage metadata
            if not metadata.coverage_complete:
                continue

            # Verification of interval boundaries
            if metadata.window_start is None or metadata.window_end is None:
                continue

            meta_start = _to_utc_aware(metadata.window_start)
            meta_end = _to_utc_aware(metadata.window_end)

            # Query window must begin on or before required_start_time, and end on or after success_time
            if meta_start > required_start_time or meta_end < success_time:
                continue

            # 2. Gather preceding failed events within [required_start_time, success_time)
            preceding_failures: List[SSHEventRecord] = []
            for j in range(s_idx - 1, -1, -1):
                ev = events[j]
                if ev.authentication_result == "failure":
                    ev_time = _to_utc_aware(ev.event_timestamp)
                    if ev_time >= required_start_time and ev_time < success_time:
                        preceding_failures.append(ev)

            if len(preceding_failures) >= 5 and len(preceding_failures) > max_preceding_failures:
                max_preceding_failures = len(preceding_failures)
                best_candidate = (success_ev, list(reversed(preceding_failures)))

        if not best_candidate or max_preceding_failures < 5:
            return None

        success_ev, qualifying_failures = best_candidate
        contributing_events = qualifying_failures + [success_ev]

        event_ids = [e.event_id for e in contributing_events]
        supporting_refs = [f"ssh_events/{eid}" for eid in event_ids]

        # Confidence remains strictly LOW per approved architectural criteria:
        # Event count alone does not elevate confidence without host command or multi-source corroboration.
        calibrated_confidence = MitreConfidenceLevel.LOW

        window_start = _to_utc_aware(contributing_events[0].event_timestamp)
        window_end = _to_utc_aware(contributing_events[-1].event_timestamp)

        rationale = (
            f"Observed successful SSH authentication for username '{success_ev.username}' from source IP {source_ip} "
            f"preceded by {max_preceding_failures} failed authentication attempts within the verified 2-hour preceding window. "
            f"Pattern satisfies MAP-SSH-003 candidate criteria for T1078 (Valid Accounts). "
            f"Successful authentication following repeated failures is consistent with credential guessing, "
            f"but may also represent legitimate authentication recovery; compromise cannot be confirmed without host session telemetry."
        )

        mapping_id = compute_mapping_uuid5(
            investigation_id=investigation_id,
            catalogue_version=self._catalogue_version,
            rule_id=RULE_MAP_SSH_003,
            technique_id=tech_id,
            supporting_references=supporting_refs,
        )

        return MitreCandidateProposal(
            mapping_id=mapping_id,
            rule_id=RULE_MAP_SSH_003,
            technique_id=tech_id,
            technique_name=tech_record.name,
            tactic_ids=tech_record.tactics,
            tactic_names=tactic_names,
            mapping_status=MitreMappingStatus.CANDIDATE,
            confidence=calibrated_confidence,
            supporting_references=supporting_refs,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
            rationale=rationale,
            catalogue_version=self._catalogue_version,
        )

    def _resolve_tactic_names(self, tactic_ids: Sequence[str]) -> List[str]:
        """Lookup authoritative tactic names from MitreCatalogueService."""
        names: List[str] = []
        for tac_id in sorted(tactic_ids):
            rec = self._catalogue.get_tactic(tac_id)
            if rec:
                names.append(rec.name)
        return names
