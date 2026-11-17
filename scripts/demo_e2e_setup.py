"""SentinelAgent Phase 11 Operator Dashboard Demonstration & Seed Script.

Prepares an active, investigated security incident with authoritative evidence items in PostgreSQL,
configures operator credentials, and prints instructions for launching the full stack.

Usage:
    python scripts/demo_e2e_setup.py
"""

from datetime import datetime, timezone
import hashlib
import os
import sys
import uuid

# Ensure backend root is on sys.path
backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import get_session_factory
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation


def seed_demo_data() -> dict[str, str]:
    session_factory = get_session_factory()
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    ev1_id = uuid.uuid4()
    ev2_id = uuid.uuid4()
    ev3_id = uuid.uuid4()
    attacker_ip = "203.0.113.88"

    with session_factory() as session:
        # 1. Incident
        incident = Incident(
            incident_id=incident_id,
            title="Active Multi-Threaded SSH Brute Force Campaign",
            status="investigating",
            severity="critical",
            source_ip=attacker_ip,
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )

        # 2. Investigation
        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="completed",
            investigation_summary=(
                "Forensic investigation confirms high-frequency credential stuffing targeting internal SSH services. "
                "Over 120 unauthorized authentication attempts recorded in 30 seconds across root, admin, and deployer accounts."
            ),
        )

        # 3. Evidence Items
        ev1 = EvidenceItem(
            evidence_id=ev1_id,
            investigation_id=investigation_id,
            evidence_type="detection_result",
            title="Suricata IDS Alert: High Frequency SSH Failures",
            description="Rule SID 2001219 triggered: Exceeded 100 failed authentications per minute threshold.",
            source_reference="/var/log/suricata/eve.json",
        )
        ev2 = EvidenceItem(
            evidence_id=ev2_id,
            investigation_id=investigation_id,
            evidence_type="ssh_event",
            title="Raw Syslog Auth Failure Entries",
            description="Repeated 'Failed password for invalid user' lines matching attacker IP 203.0.113.88.",
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

    return {
        "incident_id": str(incident_id),
        "investigation_id": str(investigation_id),
        "source_ip": attacker_ip,
    }


def main():
    print("=" * 80)
    print(" SentinelAgent Phase 11 — Operator Dashboard Demo Seed Script")
    print("=" * 80)

    demo_info = seed_demo_data()

    print("\n[+] Successfully seeded active demonstration incident in PostgreSQL:")
    print(f"    - Incident ID:      {demo_info['incident_id']}")
    print(f"    - Investigation ID: {demo_info['investigation_id']}")
    print(f"    - Attacker IP:      {demo_info['source_ip']}")
    print("    - Status:           Investigated & Awaiting Containment Proposal")

    print("\n[+] Demonstration Operator Credentials (API Keys):")
    print("    1. Analyst Alice (Proposer):")
    print("       Key:  sa_analyst_test_key_secret_1234567890abcdef")
    print("       Role: analyst")
    print("    2. Approver Bob (Two-Person Approver):")
    print("       Key:  sa_approver1_test_key_secret_abcdef123456789")
    print("       Role: approver")
    print("    3. Approver Dave (Reconciliation & Replays):")
    print("       Key:  sa_approver2_test_key_secret_9876543210fedcba")
    print("       Role: approver")
    print("    4. Admin Charlie (System Admin):")
    print("       Key:  sa_admin_test_key_secret_99999999999999999999")
    print("       Role: admin")

    print("\n[+] Launching the Demonstration Stack:")
    print("    Terminal 1 (Backend API):")
    print("       uvicorn app.main:app --port 8000")
    print("    Terminal 2 (Outbox & Verification Worker):")
    print("       python backend/app/worker.py")
    print("    Terminal 3 (Operator Dashboard UI):")
    print("       cd frontend && npm run dev")
    print("       Open: http://localhost:5173")
    print("=" * 80)


if __name__ == "__main__":
    main()
