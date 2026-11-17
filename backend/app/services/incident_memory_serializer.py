"""Allowlisted Incident Memory Serializer and Data Minimization Engine for SentinelAgent.

Adheres strictly to Task 9A and Task 9C.2 specifications:
1. Receives authoritative server-side context (`ActiveInvestigationContext`, `Incident`, `SSHEvent`).
2. Extracts memories across the seven approved categories using an explicit allowlist.
3. Does NOT dump arbitrary InvestigationReport JSON or raw SSH logs.
4. Pseudonymizes all IP addresses and usernames using `HmacPseudonymizer`.
5. Performs multi-pass regex and token-based free-text scrubbing for IPv4, IPv6, and usernames.
6. Re-scans the final canonical JSON payload to guarantee that no raw sensitive identifiers leaked.
7. Generates approved tags strictly matching the tag taxonomy:
    * ip:<version>:<32-hex-pseudonym>
    * user:<version>:<32-hex-pseudonym>
    * mitre:<technique_id>
    * category:<category_name>
8. Fails closed with `RedactionVerificationError` if sensitive data is detected post-redaction.
"""

from collections.abc import Sequence
from datetime import datetime
import ipaddress
import json
import logging
import re
from typing import Any, Optional, Set
import uuid

from app.models.detection_result import DetectionResult
from app.models.incident import Incident
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import InvestigationReport
from app.schemas.memory_payload import (
    MAX_ITEMS_PER_CATEGORY,
    MemoryConfirmedFinding,
    MemoryDetectionResult,
    MemoryEvidenceGap,
    MemoryHypothesis,
    MemoryInvestigationOutcome,
    MemoryMitreMapping,
    MemoryObservedFact,
    SCHEMA_VERSION_V1,
    SerializedIncidentMemoryPayload,
)
from app.schemas.mitre import MitreAttackMapping
from app.services.hmac_pseudonymizer import (
    HmacPseudonymizer,
    PseudonymizationError,
    RedactionVerificationError,
    normalize_ip,
    normalize_username,
)
from app.services.investigation_tools import ActiveInvestigationContext

logger = logging.getLogger(__name__)

# Strict IPv4 regex bounded by non-numeric boundaries
IPV4_REGEX = re.compile(
    r"(?<![0-9])"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?![0-9])"
)

# Comprehensive IPv6 address patterns with strict hex/colon boundary checks
IPV6_REGEX = re.compile(
    r"(?<![0-9a-fA-F:])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|"
    r"::"
    r")(?![0-9a-fA-F:])",
    re.IGNORECASE,
)

# Conservative credential, secret, and token detection patterns
SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # 1. Private key PEM blocks (entire block or broken headers)
    (
        re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"-----(?:BEGIN|END) (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE),
        "[REDACTED_SECRET]",
    ),

    # 2. Database connection strings & Basic Auth URLs containing credentials
    # Redacts the complete user-information component (both username and password,
    # including percent-encoded characters and special punctuation).
    (
        re.compile(r"((?:postgres|postgresql|mysql|mssql|mongodb(?:\+srv)?|redis|https?)://)(?:[^@\s/]+)@", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]@",
    ),

    # 3. Bearer authorization tokens
    (
        re.compile(r"\b(Bearer\s+)[A-Za-z0-9_\-\.\~+/=]{16,}\b", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]",
    ),

    # 4. JWT-like tokens (three dot-separated base64url segments)
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-+/=]{8,}\b"),
        "[REDACTED_SECRET]",
    ),

    # 5. Common cloud access keys and known high-entropy vendor tokens
    (
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z\-_]{20,50}\b"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\bsk-[a-zA-Z0-9_\-]{20,}\b"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b"),
        "[REDACTED_SECRET]",
    ),

    # 6. Explicit password/passwd assignments
    (
        re.compile(r"\b((?:password|passwd|pwd)\s*[:=]\s*['\"]?)([^\s'\";,]+)(['\"]?)", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]\g<3>",
    ),
    (
        re.compile(r"\b(password\s+(?:is|was)\s+['\"]?)([^\s'\";,]+)(['\"]?)", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]\g<3>",
    ),

    # 7. Common environment-secret assignments
    (
        re.compile(r"\b([A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|AUTH|CREDENTIAL)[A-Z0-9_]*\s*=\s*['\"]?)([^\s'\";,\r\n]+)(['\"]?)"),
        r"\g<1>[REDACTED_SECRET]\g<3>",
    ),
    (
        re.compile(r"\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?)([A-Za-z0-9_\-\.]{8,})(['\"]?)", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]\g<3>",
    ),
]


class IncidentMemorySerializer:
    """Allowlisted incident memory extraction and pseudonymization serializer."""

    def __init__(self, pseudonymizer: HmacPseudonymizer) -> None:
        if not isinstance(pseudonymizer, HmacPseudonymizer):
            raise TypeError(f"pseudonymizer must be an HmacPseudonymizer, got {type(pseudonymizer).__name__}")
        self._pseudonymizer = pseudonymizer

    @property
    def pseudonymizer(self) -> HmacPseudonymizer:
        return self._pseudonymizer

    def serialize_memory_payload(
        self,
        investigation_id: uuid.UUID,
        incident: Incident,
        report: InvestigationReport,
        distinct_ssh_events: Sequence[SSHEvent],
        distinct_usernames: Optional[Sequence[str]] = None,
        detection_results: Optional[Sequence[DetectionResult]] = None,
    ) -> dict[str, Any]:
        """Extract, pseudonymize, and return the allowlisted memory payload dictionary.

        Fails closed: if any raw sensitive identifier appears in the final serialized JSON,
        raises RedactionVerificationError.
        """
        # 1. Collect authoritative server-side sensitive identifiers
        raw_ips: set[str] = set()
        raw_usernames: set[str] = set()

        if incident.source_ip:
            raw_ips.add(normalize_ip(str(incident.source_ip)))

        for ev in distinct_ssh_events:
            if ev.source_ip:
                try:
                    raw_ips.add(normalize_ip(str(ev.source_ip)))
                except ValueError:
                    pass
            if ev.username:
                try:
                    raw_usernames.add(normalize_username(str(ev.username)))
                except ValueError:
                    pass

        if distinct_usernames:
            for u in distinct_usernames:
                if u and isinstance(u, str):
                    try:
                        raw_usernames.add(normalize_username(u))
                    except ValueError:
                        pass

        # Build IP and username pseudonym lookup tables
        ip_replacements: dict[str, str] = {}
        for ip in sorted(raw_ips):
            ip_replacements[ip] = self._pseudonymizer.pseudonymize_ip(ip)

        user_replacements: dict[str, str] = {}
        for u in sorted(raw_usernames, key=lambda x: -len(x)):  # Replace longer usernames first
            user_replacements[u] = self._pseudonymizer.pseudonymize_username(u)

        # 2. Text scrubbing helper
        def scrub_text(text: Optional[str]) -> str:
            if not text:
                return ""
            scrubbed = str(text)

            # Pass 1: Conservative Credential & Secret Sanitization
            for pattern, replacement in SECRET_PATTERNS:
                scrubbed = pattern.sub(replacement, scrubbed)

            # Pass 2: Word-bounded, case-preserving Username Replacement
            for raw_u, tag in user_replacements.items():
                pattern = re.compile(rf"(?<![\w\-]){re.escape(raw_u)}(?![\w\-])(?!\.[\w])")
                scrubbed = pattern.sub(tag, scrubbed)

            # Pass 3: Exact Known IP Replacements
            for raw_ip_str, tag in ip_replacements.items():
                if ":" in raw_ip_str:
                    pattern = re.compile(rf"(?<![0-9a-fA-F:]){re.escape(raw_ip_str)}(?![0-9a-fA-F:])", re.IGNORECASE)
                else:
                    pattern = re.compile(rf"(?<![0-9]){re.escape(raw_ip_str)}(?![0-9])")
                scrubbed = pattern.sub(tag, scrubbed)

            # Pass 4: Generic IPv4 Dynamic Replacement
            def replace_ipv4(match: re.Match) -> str:
                matched_ip = match.group(0)
                try:
                    norm = normalize_ip(matched_ip)
                    return self._pseudonymizer.pseudonymize_ip(norm)
                except Exception:
                    return "[REDACTED_IP]"

            scrubbed = IPV4_REGEX.sub(replace_ipv4, scrubbed)

            # Pass 5: Generic IPv6 Dynamic Replacement
            def replace_ipv6(match: re.Match) -> str:
                matched_ip = match.group(0)
                try:
                    norm = normalize_ip(matched_ip)
                    return self._pseudonymizer.pseudonymize_ip(norm)
                except Exception:
                    return "[REDACTED_IP]"

            scrubbed = IPV6_REGEX.sub(replace_ipv6, scrubbed)

            return scrubbed

        # 3. Assemble tags
        tags: list[str] = []
        for tag in ip_replacements.values():
            tags.append(tag)
        for tag in user_replacements.values():
            tags.append(tag)

        # 4. Extract Category 1: Observed Facts (authoritative ssh_events aggregation)
        observed_facts: list[MemoryObservedFact] = []
        if distinct_ssh_events:
            total_events = len(distinct_ssh_events)
            success_count = sum(1 for e in distinct_ssh_events if str(getattr(e, "authentication_result", "")).lower() == "success")
            failure_count = total_events - success_count
            earliest = min(e.event_timestamp for e in distinct_ssh_events)
            latest = max(e.event_timestamp for e in distinct_ssh_events)
            primary_ip_tag = ip_replacements.get(
                normalize_ip(str(incident.source_ip)), "[UNKNOWN_IP]"
            ) if incident.source_ip else "[UNKNOWN_IP]"

            fact_summary = (
                f"Observed {total_events} SSH authentication attempts from {primary_ip_tag}: "
                f"{failure_count} failures, {success_count} successes "
                f"between {earliest.isoformat()} and {latest.isoformat()}."
            )

            observed_facts.append(
                MemoryObservedFact(
                    fact_id="FACT-001",
                    fact_type="ssh_authentication_summary",
                    summary=fact_summary,
                    event_count=total_events,
                    success_count=success_count,
                    failure_count=failure_count,
                    source_reference=f"incidents/{incident.incident_id}",
                )
            )
            tags.append("category:fact")

        # 5. Extract Category 2: Detection Results
        detection_results_list: list[MemoryDetectionResult] = []
        if detection_results:
            for i, dr in enumerate(detection_results[:10]):
                triggered = getattr(dr, "triggered_rules", []) or []
                rule_desc = ", ".join(str(r) for r in triggered) if triggered else "Suspicious anomaly detected"
                det_summary = scrub_text(f"{dr.detector_type} alert: {rule_desc}")
                detection_results_list.append(
                    MemoryDetectionResult(
                        result_id=str(dr.result_id),
                        detector_type=str(dr.detector_type),
                        severity="high" if getattr(dr, "is_suspicious", False) else "medium",
                        summary=det_summary,
                        source_reference=f"detection_results/{dr.result_id}",
                    )
                )
            if detection_results_list:
                tags.append("category:detection")

        # 6. Extract Category 3: Investigation Findings (confirmed findings only)
        investigation_findings: list[MemoryConfirmedFinding] = []
        for finding in report.confirmed_findings:
            investigation_findings.append(
                MemoryConfirmedFinding(
                    finding_id=finding.finding_id,
                    title=scrub_text(finding.title),
                    description=scrub_text(finding.description),
                    confidence=finding.confidence,
                    source_references=finding.evidence_references[:MAX_ITEMS_PER_CATEGORY],
                )
            )
        if investigation_findings:
            tags.append("category:confirmed_finding")

        # 7. Extract Category 4: Hypotheses
        hypotheses: list[MemoryHypothesis] = []
        for hyp in report.hypotheses:
            hypotheses.append(
                MemoryHypothesis(
                    hypothesis_id=hyp.hypothesis_id,
                    description=scrub_text(hyp.description),
                    likelihood=hyp.likelihood,
                )
            )
        if hypotheses:
            tags.append("category:hypothesis")

        # 8. Extract Category 5: MITRE Mappings (authoritative server-validated records)
        mitre_mappings: list[MemoryMitreMapping] = []
        for mapping in report.mitre_attack_mappings:
            mitre_mappings.append(
                MemoryMitreMapping(
                    technique_id=mapping.technique_id,
                    technique_name=mapping.technique_name,
                    tactic_ids=mapping.tactic_ids,
                    confidence=mapping.confidence.value if hasattr(mapping.confidence, "value") else str(mapping.confidence),
                    mapping_status=mapping.mapping_status.value if hasattr(mapping.mapping_status, "value") else str(mapping.mapping_status),
                )
            )
            tags.append(f"mitre:{mapping.technique_id}")
        if mitre_mappings:
            tags.append("category:mitre_mapping")

        # 9. Extract Category 6: Evidence Gaps
        evidence_gaps: list[MemoryEvidenceGap] = []
        for gap in report.evidence_gaps:
            evidence_gaps.append(
                MemoryEvidenceGap(
                    gap_id=gap.gap_id,
                    description=scrub_text(gap.description),
                )
            )
        if evidence_gaps:
            tags.append("category:evidence_gap")

        # 10. Extract Category 7: Investigation Outcomes
        investigation_outcomes: list[MemoryInvestigationOutcome] = [
            MemoryInvestigationOutcome(
                status="completed",
                sufficient_evidence=report.sufficient_evidence,
                root_cause_assessment=scrub_text(report.root_cause_assessment) if report.root_cause_assessment else None,
            )
        ]
        tags.append("category:outcome")

        # Assemble the root payload container
        payload_container = SerializedIncidentMemoryPayload(
            schema_version=SCHEMA_VERSION_V1,
            investigation_id=str(investigation_id),
            incident_id=str(incident.incident_id),
            title=scrub_text(getattr(incident, "title", "Incident Investigation")),
            summary=scrub_text(report.summary),
            tags=tags,
            observed_facts=observed_facts,
            detection_results=detection_results_list,
            investigation_findings=investigation_findings,
            hypotheses=hypotheses,
            mitre_mappings=mitre_mappings,
            evidence_gaps=evidence_gaps,
            investigation_outcomes=investigation_outcomes,
        )

        raw_dict = payload_container.model_dump(mode="json")
        canonical_json_str = json.dumps(raw_dict, ensure_ascii=False, sort_keys=True)

        # 11. Final Fail-Closed Verification Scan
        # A. Ensure none of the collected raw IPs appear anywhere in the final JSON string
        for raw_ip_item in raw_ips:
            if raw_ip_item in canonical_json_str:
                raise RedactionVerificationError(
                    "Post-serialization redaction verification failed: raw IP address detected in payload."
                )

        # B. Ensure none of the collected raw usernames appear word-bounded in the final JSON string
        for raw_user_item in raw_usernames:
            pattern = re.compile(rf"(?<![\w\-]){re.escape(raw_user_item)}(?![\w\-])(?!\.[\w])")
            if pattern.search(canonical_json_str):
                raise RedactionVerificationError(
                    "Post-serialization redaction verification failed: raw username detected in payload."
                )

        # C. Ensure no raw secret or token patterns remain unredacted
        # Offending secret and source text are NEVER included in error messages or logs.
        SECRET_VERIFICATION_PATTERNS = [
            re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE),
            re.compile(r"\bBearer\s+(?!\[REDACTED_SECRET\])[A-Za-z0-9_\-\.\~+/=]{16,}\b", re.IGNORECASE),
            re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-+/=]{8,}\b"),
            re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
            re.compile(r"\bAIza[0-9A-Za-z\-_]{20,50}\b"),
            re.compile(r"(?:postgres|postgresql|mysql|mssql|mongodb(?:\+srv)?|redis|https?)://(?!\[REDACTED_SECRET\]@)[^@\s/]+@", re.IGNORECASE),
            re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?!\[REDACTED_SECRET\])([^'\";\s]{4,})", re.IGNORECASE),
        ]
        for vpat in SECRET_VERIFICATION_PATTERNS:
            if vpat.search(canonical_json_str):
                raise RedactionVerificationError(
                    "Post-serialization redaction verification failed: raw secret pattern detected in payload."
                )

        return raw_dict
