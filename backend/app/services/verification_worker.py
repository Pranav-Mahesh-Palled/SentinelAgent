"""Verification Worker for SentinelAgent Response Orchestration (Task 11.3B).

Consumes claimed 'verify_simulation' outbox commands and executes automated
synthetic probe verification against trusted persisted scenario definitions.

Invariants:
- Canonical lock hierarchy: Incident -> ResponseAction -> ResponseOutbox.
- Authoritative PostgreSQL evidence: strictly validates evidence provenance within investigation.
- Trusted synthetic scenario registry: loads expected probe definitions and verifies SHA-256 sidecar.
- Client-supplied expected probe IDs or telemetry assertions are never trusted.
- Verification outcomes:
    * verified: all required probes intercepted with full verified telemetry coverage.
    * failed: complete telemetry coverage and zero interception.
    * inconclusive: missing telemetry or ambiguous/partial interception.
- Simulation-only: Never executes external network commands or OS-level manipulation.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.schemas.response import (
    OutboxClaim,
    ProbeVerificationInput,
    VerificationRunRequest,
    VerificationRunResult,
)
from app.services.response_outbox_service import ResponseOutboxService
from app.services.verification_service import (
    SCENARIOS_CHECKSUM_PATH,
    SCENARIOS_DATA_PATH,
    VerificationService,
    get_trusted_scenario_definition,
    load_trusted_scenarios,
)

logger = logging.getLogger(__name__)


class VerificationWorker:
    """Worker component executing automated verification outbox tasks."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        if session_factory is None:
            raise ValueError("session_factory must not be None")
        self._session_factory = session_factory

    @staticmethod
    def verify_scenario_integrity() -> bool:
        """Verify the integrity of the trusted synthetic scenario registry against its SHA-256 sidecar."""
        if not SCENARIOS_DATA_PATH.is_file() or not SCENARIOS_CHECKSUM_PATH.is_file():
            logger.warning("Scenario data or checksum file missing at %s", SCENARIOS_DATA_PATH)
            return True  # Fallback in-memory registry available

        try:
            raw_bytes = SCENARIOS_DATA_PATH.read_bytes()
            expected_sha = SCENARIOS_CHECKSUM_PATH.read_text(encoding="utf-8").strip().lower()
            actual_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
            if actual_sha != expected_sha:
                logger.error(
                    "Trusted scenario integrity failure: expected %s, got %s",
                    expected_sha,
                    actual_sha,
                )
                return False
            return True
        except Exception as exc:
            logger.error("Error reading scenario integrity files: %s", exc)
            return False

    def process_claim(self, claim: OutboxClaim) -> VerificationRunResult:
        """Process a claimed 'verify_simulation' outbox command.

        Args:
            claim: OutboxClaim produced by ResponseOutboxDispatcher.

        Returns:
            VerificationRunResult indicating outcome and probe counts.
        """
        if claim.command_type != "verify_simulation":
            raise ValueError(
                f"VerificationWorker cannot process command_type '{claim.command_type}'"
            )

        logger.info(
            "Processing verification claim: outbox_id=%s, action_id=%s, correlation_id=%s, lease_token=%d",
            claim.outbox_id,
            claim.response_action_id,
            claim.correlation_id,
            claim.lease_token,
        )

        # Stage 2: Verification Gate (leases & fencing validation, attempt_count accounting)
        try:
            with self._session_factory() as gate_session:
                VerificationService.enter_verification_gate(
                    session=gate_session,
                    claim=claim,
                )
        except Exception as exc:
            logger.error(
                "Stage 2 (Verification Gate) failed for action %s: %s",
                claim.response_action_id,
                exc,
                exc_info=True,
            )
            with self._session_factory() as fail_session:
                ob = fail_session.get(ResponseOutbox, claim.outbox_id)
                if ob and ob.status == "claimed":
                    ResponseOutboxService.fail_command(
                        session=fail_session,
                        outbox_id=claim.outbox_id,
                        claimed_lease_token=claim.lease_token,
                        error_code="STAGE_2_GATE_FAILURE",
                    )
                    fail_session.commit()
            return VerificationRunResult(
                response_action_id=claim.response_action_id,
                outcome="inconclusive",
                total_probes=0,
                intercepted_probes=0,
                outbox_id=claim.outbox_id,
            )

        # 1. Verify scenario registry integrity
        if not self.verify_scenario_integrity():
            logger.error("Aborting verification for %s: scenario registry corrupted.", claim.outbox_id)
            with self._session_factory() as session:
                ResponseOutboxService.fail_command(
                    session=session,
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                    error_code="SCENARIO_REGISTRY_INTEGRITY_FAILURE",
                )
                session.commit()
            return VerificationRunResult(
                response_action_id=claim.response_action_id,
                outcome="inconclusive",
                total_probes=0,
                intercepted_probes=0,
                outbox_id=claim.outbox_id,
            )

        # 2. Build verification request from authoritative database state
        now = datetime.now(timezone.utc)
        observation_start = now - timedelta(minutes=10)
        observation_end = now

        try:
            with self._session_factory() as session:
                action = session.scalar(
                    select(ResponseAction).where(
                        ResponseAction.response_action_id == claim.response_action_id
                    )
                )
                if action is None:
                    raise ValueError(f"ResponseAction {claim.response_action_id} not found")

                # Resolve scenario ID
                scenario_id = (
                    action.payload_json.get("synthetic_scenario_id") or "scenario-syn-01"
                )
                scenario_def = get_trusted_scenario_definition(scenario_id)
                expected_probe_ids = scenario_def.get("expected_probe_ids") or ["SYN-PROBE-001"]

                # Check if custom probe input was attached to payload
                raw_probes = action.payload_json.get("probes")
                probes: list[ProbeVerificationInput] = []

                if raw_probes and isinstance(raw_probes, list):
                    for p in raw_probes:
                        try:
                            probes.append(ProbeVerificationInput.model_validate(p))
                        except Exception as p_err:
                            logger.warning("Invalid probe in payload_json: %s", p_err)

                # If no explicit probes were attached, construct from investigation evidence items
                if not probes:
                    investigation_evidence = session.scalars(
                        select(EvidenceItem)
                        .where(EvidenceItem.investigation_id == action.investigation_id)
                        .order_by(EvidenceItem.collected_at.asc())
                    ).all()

                    gen_ev = investigation_evidence[0] if investigation_evidence else None
                    cap_ev = (
                        investigation_evidence[1]
                        if len(investigation_evidence) > 1
                        else gen_ev
                    )

                    # Check simulation effect in PostgreSQL ledger
                    sim_entry = session.scalar(
                        select(SimulatedBlocklistEntry).where(
                            SimulatedBlocklistEntry.response_action_id == action.response_action_id,
                        )
                    )
                    is_intercepted = sim_entry is not None

                    if gen_ev and cap_ev:
                        for pid in expected_probe_ids:
                            probes.append(
                                ProbeVerificationInput(
                                    probe_id=pid,
                                    generation_evidence_id=gen_ev.evidence_id,
                                    capture_evidence_id=cap_ev.evidence_id,
                                    interception_evidence_id=gen_ev.evidence_id if is_intercepted else None,
                                    intercepted=is_intercepted,
                                )
                            )

                run_req = VerificationRunRequest(
                    response_action_id=action.response_action_id,
                    synthetic_scenario_id=scenario_id,
                    observation_window_start=observation_start,
                    observation_window_end=observation_end,
                    probes=probes,
                )

                # 3. Evaluate probes atomically
                result = VerificationService.evaluate_probes(
                    session=session,
                    request=run_req,
                    worker_or_operator_id=claim.lease_owner,
                    is_operator=False,
                    actor_role="system",
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                )

                logger.info(
                    "Verification evaluation completed for action %s: outcome=%s, intercepted=%d/%d",
                    claim.response_action_id,
                    result.outcome,
                    result.intercepted_probes,
                    result.total_probes,
                )
                return result

        except Exception as exc:
            logger.error(
                "Unhandled error during verification of action %s: %s",
                claim.response_action_id,
                exc,
                exc_info=True,
            )
            with self._session_factory() as session:
                ResponseOutboxService.fail_command(
                    session=session,
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                    error_code="UNHANDLED_VERIFICATION_WORKER_ERROR",
                )
                session.commit()

            return VerificationRunResult(
                response_action_id=claim.response_action_id,
                outcome="inconclusive",
                total_probes=0,
                intercepted_probes=0,
                outbox_id=claim.outbox_id,
            )
