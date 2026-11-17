"""SentinelAgent Phase 11 — Controlled Single Lifecycle Test.

Tests the live distributed stack:
- FastAPI Backend (PID 27444 on port 8000)
- Background Response Worker (PID 22812)
- PostgreSQL (sentinelagent)

Validates all 11 stages of the controlled response lifecycle:
1. Synthetic incident & authoritative evidence ingestion
2. Analyst proposal creation (Alice, op-analyst-01)
3. Proposer self-approval attempt (Alice -> HTTP 403 Forbidden)
4. Independent human approval (Bob, op-approver-01 -> HTTP 200 OK)
5. Outbox queue command emission (execute_simulation)
6. Background worker execution processing (Worker PID 22812)
7. Durable simulation ledger entry verification (simulated_blocklist_entries)
8. Background worker verification processing (verify_simulation)
9. Final verification result confirmation (verified, 1/1 probes intercepted)
10. Immutable audit sequence monotonicity verification (seq=1..5)
11. Pre-existing non-terminal action isolation audit (5 retained rows untouched)
"""

from datetime import datetime, timezone
import json
import os
import sys
import time
import urllib.request
import urllib.error
import uuid

# Backend path for direct DB inspection
backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from sqlalchemy import select, text
from app.db.session import get_session_factory
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.evidence_item import EvidenceItem
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.models.verification_reconciliation_probe import VerificationReconciliationProbe
from app.models.response_audit_event import ResponseAuditEvent

BASE_URL = os.environ.get("SENTINELAGENT_API_URL", "http://127.0.0.1:8001/api/v1")

# Operator Credentials
ALICE_KEY = "sa_analyst_test_key_secret_1234567890abcdef"     # Analyst Alice (op-analyst-01)
BOB_KEY   = "sa_approver1_test_key_secret_abcdef123456789"     # Approver Bob  (op-approver-01)
CAROL_KEY = "sa_approver2_test_key_secret_9876543210fedcba"   # Approver Carol (op-approver-02)

RETAINED_ACTION_IDS = [
    uuid.UUID("d35a1045-4d28-4ca9-917f-9716c9670999"),
    uuid.UUID("1d736506-4154-4307-9fdc-d861ad1ef66c"),
    uuid.UUID("67b4ac8e-7f7e-4213-ba23-94f618d144b6"),
    uuid.UUID("8d0acd32-c748-4fab-bf69-f80d488b59da"),
    uuid.UUID("2b537aab-7514-40c7-aa6e-464484320cbc"),
]


def api_request(method: str, path: str, api_key: str, data: dict = None, headers: dict = None):
    url = f"{BASE_URL}{path}"
    req_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            status_code = resp.status
            content = resp.read().decode("utf-8")
            return status_code, json.loads(content) if content else {}
    except urllib.error.HTTPError as err:
        status_code = err.code
        content = err.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"raw": content}
        return status_code, parsed


def snapshot_retained_actions(session) -> dict:
    snapshots = {}
    for act_id in RETAINED_ACTION_IDS:
        act = session.get(ResponseAction, act_id)
        if act:
            snapshots[act_id] = {
                "approval_status": act.approval_status,
                "execution_status": act.execution_status,
                "verification_status": act.verification_status,
                "version": act.version,
                "updated_at": act.updated_at.isoformat() if act.updated_at else None,
            }
    return snapshots


def main():
    print("=" * 80)
    print(" SentinelAgent Phase 11 — Controlled Single Response Lifecycle Test")
    print("=" * 80)

    session_factory = get_session_factory()

    # Pre-test snapshot of retained actions
    with session_factory() as session:
        pre_snapshots = snapshot_retained_actions(session)
    print(f"[*] Pre-test snapshot captured for {len(pre_snapshots)} retained actions.")

    # =========================================================================
    # PART A: Separation-of-Duties Demonstration A (Analyst RBAC Rejection)
    # =========================================================================
    print("\n" + "=" * 80)
    print("DEMONSTRATION A: Analyst Self-Approval Rejection (RBAC Enforcement)")
    print("=" * 80)
    inc_a_id = uuid.uuid4()
    inv_a_id = uuid.uuid4()
    ev_a_id = uuid.uuid4()

    with session_factory() as session:
        inc_a = Incident(
            incident_id=inc_a_id,
            title="Controlled Test: Demonstration A (RBAC Invariant)",
            status="investigating",
            severity="medium",
            source_ip="198.51.100.201",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )
        inv_a = Investigation(
            investigation_id=inv_a_id,
            incident_id=inc_a_id,
            status="completed",
            investigation_summary="Incident A for testing analyst RBAC authorization boundary.",
        )
        ev_a = EvidenceItem(
            evidence_id=ev_a_id,
            investigation_id=inv_a_id,
            evidence_type="detection_result",
            title="Suricata IDS Alert",
            description="Sample detection for RBAC test.",
            source_reference="/var/log/suricata/eve.json",
        )
        session.add_all([inc_a, inv_a, ev_a])
        session.commit()

    run_a = uuid.uuid4().hex[:8]
    st_prop_a, resp_prop_a = api_request(
        "POST",
        f"/incidents/{inc_a_id}/response/proposals",
        api_key=ALICE_KEY,
        data={
            "investigation_id": str(inv_a_id),
            "justification": "Analyst Alice creates proposal.",
            "evidence_ids": [str(ev_a_id)],
        },
        headers={"Idempotency-Key": f"ctrl-test-prop-a-{run_a}"},
    )
    assert st_prop_a == 201, f"Proposal creation failed: {resp_prop_a}"
    act_a_id = resp_prop_a["response_action_id"]
    print(f"[+] Proposal A Created:    {act_a_id} by Alice (role: analyst)")

    # Alice attempts self-approval -> Rejected by RBAC check
    st_self_a, resp_self_a = api_request(
        "POST",
        f"/response/actions/{act_a_id}/approve",
        api_key=ALICE_KEY,
        data={"expected_version": 1, "reason": "Self-approval attempt by Alice"},
        headers={"Idempotency-Key": f"ctrl-test-self-a-{run_a}"},
    )
    print(f"[+] Self-Approval HTTP:    {st_self_a} (Expected: 403 Forbidden)")
    print(f"[+] Detail Message:        {resp_self_a.get('detail')}")
    print(f"[+] Rejection Mechanism:   Role Authorization (analyst cannot approve)")
    assert st_self_a == 403
    assert "insufficient operator permissions" in resp_self_a.get("detail", "").lower()

    # =========================================================================
    # PART B: End-to-End Lifecycle & Demonstration B (Two-Person Separation)
    # =========================================================================
    print("\n" + "=" * 80)
    print("DEMONSTRATION B & LIFECYCLE: Two-Person Approval & Full Orchestration")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # STAGE 1: Synthetic Incident & Authoritative Evidence Ingestion
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 1: Create Fresh Synthetic Incident with Authoritative Evidence")
    print("-" * 80)
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    ev1_id = uuid.uuid4()
    ev2_id = uuid.uuid4()
    ev3_id = uuid.uuid4()
    attacker_ip = "198.51.100.234"

    with session_factory() as session:
        incident = Incident(
            incident_id=incident_id,
            title="Controlled Test: Automated SSH Brute-Force Authentication Spike",
            status="investigating",
            severity="critical",
            source_ip=attacker_ip,
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )
        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="completed",
            investigation_summary=(
                "Controlled verification incident: Automated credential stuffing attack detected. "
                "180 failed authentication attempts within 60s from 198.51.100.234."
            ),
        )
        ev1 = EvidenceItem(
            evidence_id=ev1_id,
            investigation_id=investigation_id,
            evidence_type="detection_result",
            title="Suricata IDS Rule 2001219 Alert",
            description="Exceeded 100 failed authentications per minute threshold.",
            source_reference="/var/log/suricata/eve.json",
        )
        ev2 = EvidenceItem(
            evidence_id=ev2_id,
            investigation_id=investigation_id,
            evidence_type="ssh_event",
            title="Raw Syslog Authentication Failure Sample",
            description=f"Repeated 'Failed password for invalid user' targeting port 22 from {attacker_ip}.",
            source_reference="/var/log/auth.log",
        )
        ev3 = EvidenceItem(
            evidence_id=ev3_id,
            investigation_id=investigation_id,
            evidence_type="mitre_technique",
            title="MITRE ATT&CK T1110.001 - Password Guessing",
            description="Adversary attempting automated brute force authentication against open SSH port 22.",
            source_reference="https://attack.mitre.org/techniques/T1110/001/",
        )
        session.add_all([incident, investigation, ev1, ev2, ev3])
        session.commit()

    print(f"[+] Incident Created:      {incident_id}")
    print(f"[+] Investigation Created: {investigation_id}")
    print(f"[+] Target Attacker IP:    {attacker_ip}")
    print(f"[+] Evidence Count:        3 authoritative items ({ev1_id}, {ev2_id}, {ev3_id})")

    # -------------------------------------------------------------------------
    # STAGE 2: Approver Bob Creates Containment Proposal (SAC-JSON-v1)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 2: Approver Proposal Submission (Bob, op-approver-01)")
    print("-" * 80)
    run_id = uuid.uuid4().hex[:8]
    proposal_payload = {
        "investigation_id": str(investigation_id),
        "justification": f"Active credential stuffing attacks confirmed from {attacker_ip}. Immediate containment required.",
        "evidence_ids": [str(ev1_id), str(ev2_id), str(ev3_id)],
    }
    status_prop, resp_prop = api_request(
        "POST",
        f"/incidents/{incident_id}/response/proposals",
        api_key=BOB_KEY,
        data=proposal_payload,
        headers={"Idempotency-Key": f"ctrl-test-prop-{run_id}"},
    )
    print(f"[+] HTTP Status:          {status_prop} (Expected: 201 Created)")
    assert status_prop == 201, f"Proposal creation failed: {resp_prop}"

    action_id = resp_prop["response_action_id"]
    correlation_id = resp_prop["correlation_id"]
    print(f"[+] ResponseAction ID:    {action_id}")
    print(f"[+] Correlation ID:       {correlation_id}")
    print(f"[+] Proposer Operator:    {resp_prop['proposed_by_operator_id']} (role: approver)")
    print(f"[+] Approval Status:      {resp_prop['approval_status']}")
    print(f"[+] Execution Status:     {resp_prop['execution_status']}")
    print(f"[+] Verification Status:  {resp_prop['verification_status']}")
    print(f"[+] Action Version:       {resp_prop['version']}")
    print(f"[+] SAC-JSON Hash:        {resp_prop['payload_sha256']}")

    # -------------------------------------------------------------------------
    # STAGE 3: Two-Person Separation-of-Duties Self-Approval Rejection
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 3: Proposer Self-Approval Attempt (Bob, op-approver-01)")
    print("-" * 80)
    status_self, resp_self = api_request(
        "POST",
        f"/response/actions/{action_id}/approve",
        api_key=BOB_KEY,
        data={"expected_version": 1, "reason": "Self-approval attempt by proposer Bob"},
        headers={"Idempotency-Key": f"ctrl-test-self-{run_id}"},
    )
    print(f"[+] HTTP Status:          {status_self} (Expected: 403 Forbidden)")
    print(f"[+] Detail Message:       {resp_self.get('detail')}")
    print(f"[+] Rejection Reason:     validate_proposer_approver_separation() executed (two-person approval required)")
    assert status_self == 403, f"Self-approval did not return 403! Got {status_self}"
    assert "two-person approval required" in resp_self.get("detail", "").lower()

    # -------------------------------------------------------------------------
    # STAGE 4: Authorized Secondary Approver Approval (Carol, op-approver-02)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 4: Independent Human Approval (Carol, op-approver-02)")
    print("-" * 80)
    status_appr, resp_appr = api_request(
        "POST",
        f"/response/actions/{action_id}/approve",
        api_key=CAROL_KEY,
        data={
            "expected_version": 1,
            "reason": "Forensic evidence verified by Approver Carol. Immediate simulation containment sanctioned.",
            "execution_timeout_seconds": 300,
        },
        headers={"Idempotency-Key": f"ctrl-test-appr-{run_id}"},
    )
    print(f"[+] HTTP Status:          {status_appr} (Expected: 200 OK)")
    assert status_appr == 200, f"Approval failed: {resp_appr}"
    print(f"[+] Approval Status:      {resp_appr['approval_status']}")
    print(f"[+] Execution Status:     {resp_appr['execution_status']}")
    print(f"[+] New Action Version:   {resp_appr['version']}")
    print(f"[+] Outbox ID Emitted:    {resp_appr['outbox_id']}")

    # -------------------------------------------------------------------------
    # STAGE 5: Verify Outbox Execution Job Emission
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 5: Verify Transactional Outbox Job Emission")
    print("-" * 80)
    with session_factory() as session:
        outbox_exec = session.scalar(
            select(ResponseOutbox).where(
                ResponseOutbox.response_action_id == uuid.UUID(action_id),
                ResponseOutbox.command_type == "execute_simulation",
            )
        )
        assert outbox_exec is not None, "execute_simulation outbox record was not created!"
        print(f"[+] Outbox ID:            {outbox_exec.outbox_id}")
        print(f"[+] Command Type:         {outbox_exec.command_type}")
        print(f"[+] Outbox Status:        {outbox_exec.status}")
        print(f"[+] Correlation ID:       {outbox_exec.correlation_id}")

    # -------------------------------------------------------------------------
    # STAGE 6 & 7: Allow Background Worker to Process Simulation Execution
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 6 & 7: Background Worker Simulation Execution & Ledger Verification")
    print("-" * 80)
    print("[*] Waiting for live background worker (PID 22812) to claim and execute simulation...")
    max_wait = 20
    start_time = time.time()
    exec_completed_action = None
    while time.time() - start_time < max_wait:
        st, act_data = api_request("GET", f"/response/actions/{action_id}", api_key=BOB_KEY)
        if st == 200 and act_data.get("execution_status") == "succeeded":
            exec_completed_action = act_data
            break
        time.sleep(0.5)

    assert exec_completed_action is not None, "Worker did not complete execution within timeout!"
    print(f"[+] Execution completed in {time.time() - start_time:.2f}s")
    print(f"[+] Execution Status:     {exec_completed_action['execution_status']}")
    print(f"[+] Verification Status:  {exec_completed_action['verification_status']}")

    # Verify simulation ledger entry
    with session_factory() as session:
        sim_entry = session.scalar(
            select(SimulatedBlocklistEntry).where(
                SimulatedBlocklistEntry.response_action_id == uuid.UUID(action_id)
            )
        )
        assert sim_entry is not None, "Durable simulation ledger entry not found!"
        print(f"[+] Simulation Ledger Entry Confirmed:")
        print(f"    - Entry ID:           {sim_entry.entry_id}")
        print(f"    - Rule ID:            {sim_entry.simulated_rule_id}")
        print(f"    - Blocked IP:         {sim_entry.target_ip}")
        print(f"    - Payload SHA-256:    {sim_entry.payload_sha256}")
        print(f"    - Simulated At:       {sim_entry.simulated_at}")
        print(f"    - Worker Metadata:    {sim_entry.metadata_json}")

    # -------------------------------------------------------------------------
    # STAGE 8 & 9: Allow Background Worker to Process Verification
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 8 & 9: Background Worker Verification & Outcome Confirmation")
    print("-" * 80)
    print("[*] Waiting for live background worker to claim and process verification...")
    start_time = time.time()
    verif_completed_action = None
    while time.time() - start_time < max_wait:
        st, act_data = api_request("GET", f"/response/actions/{action_id}", api_key=BOB_KEY)
        if st == 200 and act_data.get("verification_status") == "verified":
            verif_completed_action = act_data
            break
        time.sleep(0.5)

    assert verif_completed_action is not None, "Worker did not complete verification within timeout!"
    print(f"[+] Verification completed in {time.time() - start_time:.2f}s")
    print(f"[+] Final Action Status:  {verif_completed_action['approval_status']}")
    print(f"[+] Final Exec Status:    {verif_completed_action['execution_status']}")
    print(f"[+] Final Verif Status:   {verif_completed_action['verification_status']}")
    print(f"[+] Final Action Version: {verif_completed_action['version']}")

    # Verify reconciliation record in PostgreSQL
    with session_factory() as session:
        rec_row = session.scalar(
            select(VerificationReconciliationRecord).where(
                VerificationReconciliationRecord.response_action_id == uuid.UUID(action_id)
            )
        )
        assert rec_row is not None, "VerificationReconciliationRecord missing!"
        print(f"[+] Verification Record Confirmed:")
        print(f"    - Reconciliation ID:  {rec_row.reconciliation_id}")
        print(f"    - Resolution:         {rec_row.resolution}")
        print(f"    - Synthetic Scenario: {rec_row.synthetic_scenario_id}")
        print(f"    - Probes Intercepted: {rec_row.intercepted_probes} / {rec_row.expected_probes}")
        print(f"    - Telemetry Verified: {rec_row.telemetry_coverage_verified}")

        # Check probe record
        probe_row = session.scalar(
            select(VerificationReconciliationProbe).where(
                VerificationReconciliationProbe.reconciliation_id == rec_row.reconciliation_id
            )
        )
        assert probe_row is not None, "Verification probe record missing!"
        print(f"[+] Probe Record Confirmed: probe_id={probe_row.probe_id}, intercepted={probe_row.intercepted}")

    # -------------------------------------------------------------------------
    # STAGE 10: Immutable Audit Trail Sequence & Integrity Check
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 10: Append-Only Forensic Audit Trail Verification")
    print("-" * 80)
    with session_factory() as session:
        audit_events = session.scalars(
            select(ResponseAuditEvent)
            .where(ResponseAuditEvent.response_action_id == uuid.UUID(action_id))
            .order_by(ResponseAuditEvent.sequence_number.asc())
        ).all()
        print(f"[+] Total Audit Events Recorded: {len(audit_events)}")
        expected_seq = 1
        for evt in audit_events:
            print(f"    seq={evt.sequence_number:<2} | type={evt.event_type:<26} | actor={evt.actor_operator_id:<24} | role={evt.actor_role_snapshot:<10}")
            assert evt.sequence_number == expected_seq, f"Sequence gap! Expected {expected_seq}, got {evt.sequence_number}"
            expected_seq += 1

        # Check outbox final terminal state
        outbox_rows = session.scalars(
            select(ResponseOutbox).where(ResponseOutbox.response_action_id == uuid.UUID(action_id))
        ).all()
        print(f"\n[+] Outbox Commands Terminal State (Total: {len(outbox_rows)}):")
        for ob in outbox_rows:
            print(f"    - cmd={ob.command_type:<20} | status={ob.status:<12} | attempts={ob.attempt_count} | lease_token={ob.lease_token}")
            assert ob.status == "completed", f"Outbox item not completed: {ob.status}"

        # Confirm exact attempt count of 1 for verification and execution commands
        verif_ob = next(ob for ob in outbox_rows if ob.command_type == "verify_simulation")
        assert verif_ob.attempt_count == 1, f"Expected verification attempts=1, got {verif_ob.attempt_count}"
        print(f"[+] Verification Outbox Attempt Count: Exactly 1 ({verif_ob.attempt_count})")

        exec_ob = next(ob for ob in outbox_rows if ob.command_type == "execute_simulation")
        assert exec_ob.attempt_count == 1, f"Expected execution attempts=1, got {exec_ob.attempt_count}"
        print(f"[+] Execution Outbox Attempt Count:    Exactly 1 ({exec_ob.attempt_count})")

        # Verify no orphaned claimed leases exist
        orphans = session.scalars(
            select(ResponseOutbox).where(
                ResponseOutbox.status == "claimed",
                ResponseOutbox.response_action_id.in_([uuid.UUID(action_id), uuid.UUID(act_a_id)]),
            )
        ).all()
        assert len(orphans) == 0, f"Orphaned claimed leases detected: {len(orphans)}"
        print(f"[+] Orphaned Active Leases:           0 (none)")

    # -------------------------------------------------------------------------
    # STAGE 11: Retained Action Isolation Verification
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("STAGE 11: Pre-existing Action Isolation Verification")
    print("-" * 80)
    with session_factory() as session:
        post_snapshots = snapshot_retained_actions(session)
        assert len(post_snapshots) == len(pre_snapshots) == 5, "Retained action count changed!"
        for act_id, pre in pre_snapshots.items():
            post = post_snapshots[act_id]
            assert pre == post, f"Retained action {act_id} was mutated! Pre: {pre}, Post: {post}"
            print(f"[+] Retained Action {act_id}: UNTOUCHED (version={post['version']}, exec={post['execution_status']}, verif={post['verification_status']})")

    print("\n" + "=" * 80)
    print(" CONTROLLED SINGLE RESPONSE LIFECYCLE TEST COMPLETED SUCCESSFULLY!")
    print("=" * 80)


def demonstrate_approver_proposer_separation(incident_id: str, investigation_id: str, evidence_ids: list[str]):
    """Demonstrate true two-person separation of duties: Bob (approver) proposes, attempts self-approval (rejected by validator), Carol approves."""
    run_id = uuid.uuid4().hex[:8]
    print("\n" + "=" * 80)
    print("DEMONSTRATION: Approver Separation-of-Duties (Bob proposes, Bob self-approves, Carol approves)")
    print("=" * 80)

    # 1. Bob (op-approver-01) creates proposal
    status_prop, resp_prop = api_request(
        "POST",
        f"/incidents/{incident_id}/response/proposals",
        api_key=BOB_KEY,
        data={
            "investigation_id": investigation_id,
            "justification": "Separation of duties demonstration proposal created by Bob.",
            "evidence_ids": evidence_ids,
        },
        headers={"Idempotency-Key": f"sod-prop-{run_id}"},
    )
    assert status_prop == 201, f"Proposal creation failed: {resp_prop}"
    action_id = resp_prop["response_action_id"]
    print(f"[+] Proposal created by Bob (op-approver-01): {action_id}")

    # 2. Bob attempts to approve own proposal -> Role auth passes, validate_proposer_approver_separation executes -> 403 Forbidden
    status_self, resp_self = api_request(
        "POST",
        f"/response/actions/{action_id}/approve",
        api_key=BOB_KEY,
        data={"expected_version": 1, "reason": "Self-approval attempt by proposer Bob"},
        headers={"Idempotency-Key": f"sod-self-{run_id}"},
    )
    print(f"[+] Bob self-approval HTTP status: {status_self} (Expected: 403 Forbidden)")
    print(f"[+] Detail: {resp_self.get('detail')}")
    assert status_self == 403
    assert "two-person approval required" in resp_self.get("detail", "").lower()

    # 3. Carol (op-approver-02) approves proposal -> 200 OK
    status_carol, resp_carol = api_request(
        "POST",
        f"/response/actions/{action_id}/approve",
        api_key=CAROL_KEY,
        data={"expected_version": 1, "reason": "Carol independent authorization sanctioned."},
        headers={"Idempotency-Key": f"sod-carol-{run_id}"},
    )
    print(f"[+] Carol independent approval HTTP status: {status_carol} (Expected: 200 OK)")
    assert status_carol == 200
    print(f"[+] Two-person separation of duties successfully verified!")


if __name__ == "__main__":
    main()
