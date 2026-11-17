"""Comprehensive unit, privacy, and redaction verification tests for IncidentMemorySerializer.

Verifies Task 9C.2 requirements:
- Each of the seven approved categories is populated from authoritative sources.
- No fabricated claims or hallucinations.
- Confirmed findings remain distinct from hypotheses and observations.
- Only validated MITRE mappings are serialized.
- Payload schema version is explicitly 'v1'.
- Compact deterministic structure with bounded item counts and text lengths.
- No raw SSH event payloads or credentials dumped.
- Privacy verification: intentionally seeded raw IPv4, IPv6, realistic usernames,
  and credential strings NEVER appear anywhere in the serialized payload or tags.
- Post-serialization verification scan fails closed with RedactionVerificationError
  if residual raw identifiers leak.
"""

from datetime import datetime, timezone
import json
import uuid
import pytest
from pydantic import SecretStr

from app.models.detection_result import DetectionResult
from app.models.incident import Incident
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    ConfirmedFinding,
    EvidenceGap,
    Hypothesis,
    InvestigationReport,
    Observation,
)
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.hmac_pseudonymizer import (
    HmacPseudonymizer,
    RedactionVerificationError,
)
from app.services.incident_memory_serializer import IncidentMemorySerializer

VALID_HMAC_KEY = SecretStr("0123456789abcdef0123456789abcdef")


@pytest.fixture
def pseudonymizer():
    return HmacPseudonymizer(active_key=VALID_HMAC_KEY, active_version="v1")


@pytest.fixture
def serializer(pseudonymizer):
    return IncidentMemorySerializer(pseudonymizer=pseudonymizer)


def _build_test_entities():
    inc_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    ev1_id = uuid.uuid4()
    ev2_id = uuid.uuid4()
    dr_id = uuid.uuid4()

    incident = Incident(
        incident_id=inc_id,
        title="Unauthorized SSH access from 198.51.100.25",
        incident_type="brute_force",
        source_ip="198.51.100.25",
        severity="high",
        detection_method="hybrid",
        status="open",
        investigation_status="in_progress",
        created_at=datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc),
    )

    ssh_events = [
        SSHEvent(
            event_id=ev1_id,
            event_timestamp=datetime(2026, 11, 9, 11, 55, 0, tzinfo=timezone.utc),
            source_ip="198.51.100.25",
            username="administrator",
            authentication_result="FAILURE",
            event_type="failed_login",
        ),
        SSHEvent(
            event_id=ev2_id,
            event_timestamp=datetime(2026, 11, 9, 11, 56, 0, tzinfo=timezone.utc),
            source_ip="198.51.100.25",
            username="root",
            authentication_result="SUCCESS",
            event_type="successful_login",
        ),
    ]

    detection_results = [
        DetectionResult(
            result_id=dr_id,
            incident_id=inc_id,
            source_ip="198.51.100.25",
            window_start=datetime(2026, 11, 9, 11, 55, 0, tzinfo=timezone.utc),
            window_end=datetime(2026, 11, 9, 11, 56, 0, tzinfo=timezone.utc),
            detector_type="rule",
            is_suspicious=True,
            triggered_rules=["SSH Brute Force Velocity Detector"],
            feature_snapshot={"failed_attempts": 10},
            evaluated_at=datetime(2026, 11, 9, 11, 56, 0, tzinfo=timezone.utc),
        )
    ]

    mitre_mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        evidence_item_id=uuid.uuid4(),
        rule_id="MAP-SSH-001",
        technique_id="T1110.001",
        technique_name="Password Guessing",
        tactic_ids=["TA0001", "TA0006"],
        tactic_names=["Initial Access", "Credential Access"],
        mapping_status=MitreMappingStatus.SUPPORTED,
        confidence=MitreConfidenceLevel.HIGH,
        supporting_references=[f"ssh_events/{ev1_id}", f"ssh_events/{ev2_id}"],
        event_ids=[ev1_id, ev2_id],
        rationale="Repeated credential guessing attempts against administrator followed by root success.",
        catalogue_version="v20.1",
        window_start=datetime(2026, 11, 9, 11, 50, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc),
    )

    report = InvestigationReport(
        summary="Attacker at 198.51.100.25 attempted credential stuffing against administrator and root.",
        sufficient_evidence=True,
        confirmed_findings=[
            ConfirmedFinding(
                finding_id="FND-1",
                title="Credential brute force from 198.51.100.25 against root",
                description="Failed attempts against administrator followed by root compromise.",
                evidence_references=[f"ssh_events/{ev1_id}", f"ssh_events/{ev2_id}"],
                confidence="high",
            )
        ],
        observations=[
            Observation(
                observation_id="OBS-1",
                description="Login burst from 198.51.100.25 targeting svc_backup.",
                evidence_references=[f"ssh_events/{ev1_id}"],
            )
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="HYP-1",
                description="Attacker obtained valid password hash for root offline.",
                likelihood="medium",
                required_verification="Check shadow file access logs.",
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_id="GAP-1",
                description="Missing pam audit logs for session persistence.",
                potential_sources=["/var/log/audit/audit.log"],
            )
        ],
        root_cause_assessment="Weak root credentials susceptible to dictionary attacks.",
        mitre_attack_mappings=[mitre_mapping],
    )

    return inv_id, incident, report, ssh_events, detection_results


# =============================================================================
# 1. Structure & Category Integrity Tests
# =============================================================================

def test_serializer_extracts_all_seven_categories(serializer):
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=["administrator", "root", "svc_backup"],
        detection_results=detection_results,
    )

    assert payload["schema_version"] == "v1"
    assert payload["investigation_id"] == str(inv_id)
    assert payload["incident_id"] == str(incident.incident_id)

    # 1. Observed facts
    assert len(payload["observed_facts"]) == 1
    assert payload["observed_facts"][0]["fact_id"] == "FACT-001"
    assert payload["observed_facts"][0]["event_count"] == 2
    assert payload["observed_facts"][0]["failure_count"] == 1
    assert payload["observed_facts"][0]["success_count"] == 1

    # 2. Detection results
    assert len(payload["detection_results"]) == 1
    assert payload["detection_results"][0]["detector_type"] == "rule"

    # 3. Investigation findings
    assert len(payload["investigation_findings"]) == 1
    assert payload["investigation_findings"][0]["finding_id"] == "FND-1"
    assert payload["investigation_findings"][0]["confidence"] == "high"

    # 4. Hypotheses
    assert len(payload["hypotheses"]) == 1
    assert payload["hypotheses"][0]["hypothesis_id"] == "HYP-1"

    # 5. MITRE mappings
    assert len(payload["mitre_mappings"]) == 1
    assert payload["mitre_mappings"][0]["technique_id"] == "T1110.001"
    assert payload["mitre_mappings"][0]["mapping_status"] == "supported"

    # 6. Evidence gaps
    assert len(payload["evidence_gaps"]) == 1
    assert payload["evidence_gaps"][0]["gap_id"] == "GAP-1"

    # 7. Outcomes
    assert len(payload["investigation_outcomes"]) == 1
    assert payload["investigation_outcomes"][0]["status"] == "completed"
    assert payload["investigation_outcomes"][0]["sufficient_evidence"] is True


# =============================================================================
# 2. Privacy & Redaction Verification Tests
# =============================================================================

def test_seeded_raw_identifiers_never_appear_in_payload_or_tags(serializer, pseudonymizer):
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Seed sensitive identifiers across title, summary, findings, and hypotheses
    sensitive_ips = ["198.51.100.25", "203.0.113.199", "2001:db8::1"]
    sensitive_users = ["administrator", "root", "svc_backup", "finance_admin"]

    # Inject into report fields
    report.summary += " Also saw 203.0.113.199 trying finance_admin."
    report.confirmed_findings[0].description += " Secondary connection from 2001:db8::1."

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=sensitive_users,
        detection_results=detection_results,
    )

    serialized_json = json.dumps(payload, ensure_ascii=False)

    # 1. Assert NONE of the raw sensitive IPs appear anywhere in JSON
    for ip in sensitive_ips:
        assert ip not in serialized_json

    # 2. Assert NONE of the raw sensitive usernames appear anywhere in JSON
    for u in sensitive_users:
        # Check as whole word
        assert f'"{u}"' not in serialized_json
        assert f" {u} " not in serialized_json
        assert f" {u}." not in serialized_json

    # 3. Assert tags contain approved pseudonymized tags only
    assert len(payload["tags"]) > 0
    for t in payload["tags"]:
        assert any(t.startswith(prefix) for prefix in ("ip:v1:", "user:v1:", "mitre:", "category:"))
        # Ensure raw IP is never in tag
        for ip in sensitive_ips:
            assert ip not in t
        for u in sensitive_users:
            assert u not in t

    # 4. Assert specific pseudonym tags match expected digests
    expected_ip_tag = pseudonymizer.pseudonymize_ip("198.51.100.25")
    expected_admin_tag = pseudonymizer.pseudonymize_username("administrator")
    expected_root_tag = pseudonymizer.pseudonymize_username("root")

    assert expected_ip_tag in payload["tags"]
    assert expected_admin_tag in payload["tags"]
    assert expected_root_tag in payload["tags"]
    assert expected_ip_tag in payload["summary"]


def test_post_serialization_scan_fails_closed_if_raw_ip_leaks(serializer):
    """If a sensitive identifier escapes scrubbing, serializer raises RedactionVerificationError."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Leak raw IP inside a formatted tag prefix to pass schema tag validation but trigger the final scanner
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            serializer._pseudonymizer,
            "pseudonymize_ip",
            lambda ip, key_version=None: f"ip:v1:{ip}",  # Raw IP leaks in tag/text
        )
        with pytest.raises(RedactionVerificationError, match="raw IP address detected"):
            serializer.serialize_memory_payload(
                investigation_id=inv_id,
                incident=incident,
                report=report,
                distinct_ssh_events=ssh_events,
                distinct_usernames=["administrator"],
                detection_results=detection_results,
            )

    # Leak raw username inside formatted tag prefix
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            serializer._pseudonymizer,
            "pseudonymize_username",
            lambda u, key_version=None: f"user:v1:{u}",  # Raw username leaks in tag/text
        )
        with pytest.raises(RedactionVerificationError, match="raw username detected"):
            serializer.serialize_memory_payload(
                investigation_id=inv_id,
                incident=incident,
                report=report,
                distinct_ssh_events=ssh_events,
                distinct_usernames=["administrator"],
                detection_results=detection_results,
            )


# =============================================================================
# 3. Parameterized IP & Username Privacy Tests
# =============================================================================

@pytest.mark.parametrize(
    "test_ip,surrounding_text",
    [
        ("198.51.100.25", "Observed traffic from 198.51.100.25 directly."),
        ("203.0.113.199", "Traffic from (203.0.113.199) enclosed in parens."),
        ("192.0.2.1", "Port connection 192.0.2.1:22 in report."),
        ("192.0.2.2", "Comma separated 192.0.2.2, in report."),
        ("192.0.2.3", "Bracketed [192.0.2.3] in report."),
        ("192.0.2.4", "Multiple occurrences 192.0.2.4 then 192.0.2.4 again."),
        ("2001:db8::1", "Compressed IPv6 2001:db8::1 in logs."),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "Full IPv6 2001:0db8:0000:0000:0000:0000:0000:0001 in logs."),
        ("2001:db8::2", "Bracketed IPv6 [2001:db8::2]:443 in logs."),
        ("2001:db8::3", "Parenthesized IPv6 (2001:db8::3) in logs."),
    ],
)
def test_parameterized_ip_redaction(serializer, test_ip, surrounding_text):
    """Verify that seeded IPs across various formats and punctuations never survive in JSON or tags."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Inject into summary and nested category fields
    report.summary = surrounding_text
    report.confirmed_findings[0].description = f"Nested finding with {test_ip}"
    report.hypotheses.append(
        Hypothesis(
            hypothesis_id="HYP-IP",
            description=f"Hypothesis referencing {test_ip}",
            likelihood="low",
            required_verification="Check secondary logs",
        )
    )
    report.evidence_gaps.append(
        EvidenceGap(gap_id="GAP-IP", description=f"Missing telemetry for {test_ip}")
    )
    report.root_cause_assessment = f"Root cause linked to {test_ip} activity."

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=["administrator"],
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)

    # 1. Assert raw IP never appears in JSON
    assert test_ip not in canonical_json

    # 2. Assert raw IP never appears in tags
    for tag in payload["tags"]:
        assert test_ip not in tag


def test_equivalent_full_and_compressed_ipv6_produce_identical_tags(serializer, pseudonymizer):
    """Verify that full and compressed IPv6 representations map to the identical pseudonym tag."""
    full_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0001"
    compressed_ipv6 = "2001:db8::1"

    expected_tag = pseudonymizer.pseudonymize_ip(compressed_ipv6)

    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()
    # Add an event with the full IPv6 representation
    ssh_events.append(
        SSHEvent(
            event_id=uuid.uuid4(),
            event_timestamp=datetime(2026, 11, 9, 11, 57, 0, tzinfo=timezone.utc),
            source_ip=full_ipv6,
            username="root",
            authentication_result="SUCCESS",
            event_type="login",
        )
    )
    report.summary = f"Checking connection from {full_ipv6} and later {compressed_ipv6}"

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)
    assert full_ipv6 not in canonical_json
    assert compressed_ipv6 not in canonical_json
    assert expected_tag in payload["tags"]
    assert expected_tag in payload["summary"]


@pytest.mark.parametrize(
    "raw_username,surrounding_text",
    [
        ("root", "Targeted user root in ssh log."),
        ("root", "Parenthesized (root) in report."),
        ("root", "Colon adjacent root: in report."),
        ("root", "Period adjacent root. in sentence end."),
        ("root", "Quoted \"root\" in finding."),
        ("administrator", "Compromised administrator account."),
        ("administrator", "Multiple administrator and administrator instances."),
        ("svc_backup", "Service account svc_backup was affected."),
        ("svc.backup", "Dot username svc.backup observed."),
        ("svc.backup", "Parenthesized (svc.backup) observed."),
        ("svc.backup", "Bracketed [svc.backup] observed."),
        ("svc.backup", "Colon adjacent svc.backup:22 observed."),
        ("svc.backup", "Period adjacent svc.backup. observed."),
        ("user-name", "Hyphenated user-name was targeted."),
        ("user-name", "Parenthesized (user-name) was targeted."),
        ("jörg", "Unicode username jörg authenticated."),
        ("administrateur", "French username administrateur in logs."),
        ("Admin", "Capitalized Admin user targeted."),
    ],
)
def test_parameterized_username_redaction(serializer, raw_username, surrounding_text):
    """Verify that usernames across dots, hyphens, Unicode, case, and punctuation never survive in JSON or tags."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    report.summary = surrounding_text
    report.confirmed_findings[0].description = f"Nested description with {raw_username}"
    report.hypotheses.append(
        Hypothesis(
            hypothesis_id="HYP-U",
            description=f"Hypothesis referencing {raw_username}",
            likelihood="low",
            required_verification="Check secondary logs",
        )
    )
    report.evidence_gaps.append(
        EvidenceGap(gap_id="GAP-U", description=f"Missing telemetry for user {raw_username}")
    )
    report.root_cause_assessment = f"Account {raw_username} compromised."

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=[raw_username],
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)

    # Assert word-bounded raw username never survives
    import re
    word_pattern = re.compile(rf"(?<![\w\-]){re.escape(raw_username)}(?![\w\-])(?!\.[\w])")
    assert not word_pattern.search(canonical_json)

    # Assert raw username never appears in tags
    for tag in payload["tags"]:
        assert raw_username not in tag


def test_username_case_distinction_preserved(serializer, pseudonymizer):
    """Verify case semantics: 'Admin' and 'admin' produce distinct pseudonyms."""
    tag_upper = pseudonymizer.pseudonymize_username("Admin")
    tag_lower = pseudonymizer.pseudonymize_username("admin")
    assert tag_upper != tag_lower

    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()
    report.summary = "Attacker targeted Admin then admin in same session."

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=["Admin", "admin"],
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)
    assert tag_upper in payload["tags"]
    assert tag_lower in payload["tags"]
    assert tag_upper in payload["summary"]
    assert tag_lower in payload["summary"]


# =============================================================================
# 4. Credential & Secret Protection Tests
# =============================================================================

@pytest.mark.parametrize(
    "secret_value,injected_text",
    [
        (
            "SuperSecretPassword123",
            "Attacker authenticated with password=SuperSecretPassword123 during session.",
        ),
        (
            "AnotherPasswd456!",
            "Config file contained passwd: 'AnotherPasswd456!' in cleartext.",
        ),
        (
            "Summer2026Password",
            "Investigation notes state password was Summer2026Password on host.",
        ),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Found Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c in auth header.",
        ),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.ABCDEF1234567890abcdef",
            "Found raw JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.ABCDEF1234567890abcdef in cookie.",
        ),
        (
            "AKIA" + "IOSFODNN7EXAMPLE",
            "Found compromised AWS key " + "AKIA" + "IOSFODNN7EXAMPLE in script.",
        ),
        (
            "AIza" + "SyD-1234567890abcdefghijklmnopqrstuv",
            "API key " + "AIza" + "SyD-1234567890abcdefghijklmnopqrstuv leaked in request url.",
        ),
        (
            "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz",
            "Found secret token " + "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz in environment.",
        ),
        (
            "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
            "Personal token " + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEF committed to git.",
        ),
        (
            "xoxb-" + "1234567890-abcdefghijklmnopqrstuv",
            "Slack bot token " + "xoxb-" + "1234567890-abcdefghijklmnopqrstuv detected.",
        ),
        (
            "super_secret_db_pass",
            "Connection string postgres://app_user:super_secret_db_pass@198.51.100.25:5432/sentinel in trace.",
        ),
        (
            "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Found AWS_SECRET_ACCESS_KEY=" + "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in bash history.",
        ),
        (
            "production_jwt_secret_token",
            "Setting JWT_SECRET=production_jwt_secret_token observed in .env dump.",
        ),
    ],
)
def test_credential_leakage_sanitization(serializer, secret_value, injected_text):
    """Verify that credentials, tokens, and keys are sanitized and never leak into payload or tags."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Inject credential into summary, finding description, and root cause
    report.summary = injected_text
    report.confirmed_findings[0].description = f"Finding notes: {injected_text}"
    report.root_cause_assessment = f"Root cause includes {injected_text}"

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=["administrator"],
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)

    # 1. Assert raw secret value NEVER appears in JSON
    assert secret_value not in canonical_json

    # 2. Assert raw secret value NEVER appears in tags
    for tag in payload["tags"]:
        assert secret_value not in tag

    # 3. Assert [REDACTED_SECRET] appears where the secret was removed
    assert "[REDACTED_SECRET]" in canonical_json


def test_pem_private_key_material_sanitized(serializer):
    """Verify PEM private key blocks are fully redacted with neutral marker."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    pem_header = "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    pem_footer = "-----END " + "RSA PRIVATE KEY-----"
    pem_key = (
        pem_header +
        "MIIEowIBAAKCAQEA0n51zK7V19kL+abcdefghijklmnopqrstuvwxyz1234567890\n"
        "ABCDEF1234567890abcdefghijklmnopqrstuvwxyz==\n" +
        pem_footer
    )
    report.confirmed_findings[0].description = f"Recovered private key:\n{pem_key}"

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)
    assert ("-----BEGIN " + "RSA PRIVATE KEY-----") not in canonical_json
    assert ("-----END " + "RSA PRIVATE KEY-----") not in canonical_json
    assert "MIIEowIBAAKCAQEA" not in canonical_json
    assert "[REDACTED_SECRET]" in canonical_json


@pytest.mark.parametrize(
    "raw_url,raw_user,raw_pass",
    [
        (
            "postgres://admin:SuperSecret123@db.example.com/sentinel",
            "admin",
            "SuperSecret123",
        ),
        (
            "mysql://root:p%40ss%3Aword!@198.51.100.25:3306/db",
            "root",
            "p%40ss%3Aword!",
        ),
        (
            "mongodb+srv://admin%40corp:Secret%23Pass@cluster0.mongodb.net/test",
            "admin%40corp",
            "Secret%23Pass",
        ),
        (
            "redis://default:mypassword@cache.example.com:6379/0",
            "default",
            "mypassword",
        ),
        (
            "http://alice:secret123@example.com/api",
            "alice",
            "secret123",
        ),
        (
            "https://user%20name:pass%26word@secure.bank.com/endpoint",
            "user%20name",
            "pass%26word",
        ),
    ],
)
def test_parameterized_credential_bearing_urls(serializer, raw_url, raw_user, raw_pass):
    """Verify that complete URL userinfo components (usernames, passwords, punctuation, percent-encoding)

    are redacted and never leak into canonical JSON or tags.
    """
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Inject URL into multiple free-text fields and nested structures
    report.summary = f"Database leak detected at {raw_url} during triage."
    report.confirmed_findings[0].description = f"Attacker extracted URI: {raw_url}"
    report.root_cause_assessment = f"Exfiltration endpoint identified as {raw_url}."

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        distinct_usernames=[raw_user] if raw_user in ["admin", "root", "default", "alice"] else [],
        detection_results=detection_results,
    )

    canonical_json = json.dumps(payload, ensure_ascii=False)

    # 1. Assert raw password never survives in canonical JSON
    assert raw_pass not in canonical_json

    # 2. Assert raw password never survives in tags
    for tag in payload["tags"]:
        assert raw_pass not in tag
        assert raw_user not in tag

    # 3. Assert raw username never survives as part of the userinfo in canonical JSON
    assert f"{raw_user}:" not in canonical_json
    assert f"{raw_user}@" not in canonical_json

    # 4. Assert [REDACTED_SECRET]@ is present in top-level and nested structures
    assert "[REDACTED_SECRET]@" in canonical_json
    assert "[REDACTED_SECRET]@" in payload["summary"]
    assert "[REDACTED_SECRET]@" in payload["investigation_findings"][0]["description"]
    assert raw_pass not in payload["investigation_findings"][0]["description"]
    assert "[REDACTED_SECRET]@" in payload["investigation_outcomes"][0]["root_cause_assessment"]
    assert raw_pass not in payload["investigation_outcomes"][0]["root_cause_assessment"]


def test_secret_leak_in_exception_fails_closed_without_revealing_secret(serializer):
    """Verify that post-serialization scan failure never includes the secret in the exception message."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    secret_key = "AIza" + "SyD-SuperSecretGoogleApiKey12345"

    # Monkeypatch text scrubber to bypass secret replacement, letting raw secret reach final scan
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            serializer,
            "_pseudonymizer",
            serializer._pseudonymizer,
        )
        # Inject directly into report summary with an active bypass of SECRET_PATTERNS
        report.summary = f"Leaked {secret_key}"
        with pytest.MonkeyPatch.context() as mp2:
            from app.services import incident_memory_serializer
            mp2.setattr(incident_memory_serializer, "SECRET_PATTERNS", [])

            with pytest.raises(RedactionVerificationError) as exc_info:
                serializer.serialize_memory_payload(
                    investigation_id=inv_id,
                    incident=incident,
                    report=report,
                    distinct_ssh_events=ssh_events,
                    detection_results=detection_results,
                )

            # Assert secret is NOT in exception message
            err_msg = str(exc_info.value)
            assert secret_key not in err_msg
            assert "raw secret pattern detected" in err_msg


# =============================================================================
# 5. Epistemic Boundary Tests
# =============================================================================

def test_epistemic_boundaries_unvalidated_hypotheses_never_promoted(serializer):
    """Verify that hypotheses remain strictly in hypotheses category and are never promoted to findings."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    # Clear confirmed findings, keep hypothesis
    report.confirmed_findings = []
    report.hypotheses = [
        Hypothesis(
            hypothesis_id="HYP-99",
            description="Unverified hypothesis about initial access.",
            likelihood="low",
            required_verification="Check secondary logs",
        )
    ]

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        detection_results=detection_results,
    )

    # Assert findings category is empty
    assert len(payload["investigation_findings"]) == 0
    assert "category:confirmed_finding" not in payload["tags"]

    # Assert hypothesis is retained in hypotheses
    assert len(payload["hypotheses"]) == 1
    assert payload["hypotheses"][0]["hypothesis_id"] == "HYP-99"
    assert "category:hypothesis" in payload["tags"]


def test_epistemic_boundaries_tool_traces_and_internal_thoughts_excluded(serializer):
    """Verify that serializer only accepts report and authoritative entities, excluding raw tool traces."""
    inv_id, incident, report, ssh_events, detection_results = _build_test_entities()

    payload = serializer.serialize_memory_payload(
        investigation_id=inv_id,
        incident=incident,
        report=report,
        distinct_ssh_events=ssh_events,
        detection_results=detection_results,
    )

    # Assert root keys match only the allowlisted memory container schema
    allowed_keys = {
        "schema_version",
        "investigation_id",
        "incident_id",
        "title",
        "summary",
        "tags",
        "observed_facts",
        "detection_results",
        "investigation_findings",
        "hypotheses",
        "mitre_mappings",
        "evidence_gaps",
        "investigation_outcomes",
    }
    assert set(payload.keys()) == allowed_keys

    canonical_json = json.dumps(payload)
    assert "conversation_history" not in canonical_json
    assert "tool_run" not in canonical_json
    assert "function_call" not in canonical_json
    assert "function_response" not in canonical_json
    assert "thought" not in canonical_json
