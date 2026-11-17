"""Independent Security Validator for MITRE ATT&CK Behavioral Mappings (Task 8D).

Enforces strict forensic integrity, anti-circular provenance, and catalogue verification
before any MITRE ATT&CK candidate proposal can be persisted as an EvidenceItem or
included in an InvestigationReport.

Core Guarantees:
1. Version-Pinned Catalogue Verification:
   - Validates candidate technique against authoritative MitreCatalogueService.
   - Strictly rejects non-existent, deprecated, or revoked techniques.
2. Approved Rule-Technique-Status-Confidence Matrix:
   - MAP-SSH-001 -> strictly T1110, status=candidate, confidence in {medium, high}.
   - MAP-SSH-002 -> strictly T1110.003, status=hypothesis, confidence in {low, medium}.
   - MAP-SSH-003 -> strictly T1078, status=candidate, confidence in {low}.
   - Status 'supported' is strictly rejected across all rules (unsupported by single-source SSH telemetry).
   - Status 'rejected' is strictly rejected from persistence.
3. Anti-Circularity & Provenance Authorization:
   - Supporting references must be strictly canonical 'ssh_events/<uuid>' formats.
   - References to 'mitre/*', 'evidence_items/*', 'playbooks/*', 'incidents/*', or 'detection_results/*'
     are strictly forbidden (anti-circularity: mappings must be grounded directly in raw telemetry).
   - Every contributing SSH event UUID must be present in AuthorizedProvenanceSet.ssh_events.
   - event_ids must match supporting_references exactly.
4. Telemetry & Window Verification:
   - When authorized_ssh_events is provided:
     * Verifies all events share identical source_ip.
     * Verifies window_start and window_end strictly match earliest and latest contributing events.
   - When retrieval_metadata is provided:
     * MAP-SSH-003 strictly requires coverage_complete == True.
5. Authoritative Metadata Overwrite:
   - Technique name, tactics, and catalogue version are overwritten from MitreCatalogueService,
     preventing any LLM or engine tampering.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
import logging
from typing import TYPE_CHECKING, Optional, Set
import uuid

from app.schemas.investigation import SSHEventRecord, validate_canonical_source_reference
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import (
    EventRetrievalMetadata,
    MitreMappingEngine,
    compute_mapping_uuid5,
)

if TYPE_CHECKING:
    from app.services.investigation_service import AuthorizedProvenanceSet

logger = logging.getLogger(__name__)

# Permitted rule identifiers
RULE_MAP_SSH_001 = "MAP-SSH-001"
RULE_MAP_SSH_002 = "MAP-SSH-002"
RULE_MAP_SSH_003 = "MAP-SSH-003"

# Rule-to-Technique Matrix
APPROVED_RULE_TECHNIQUES: dict[str, str] = {
    RULE_MAP_SSH_001: "T1110",
    RULE_MAP_SSH_002: "T1110.003",
    RULE_MAP_SSH_003: "T1078",
}

# Rule-to-Status Matrix
APPROVED_RULE_STATUSES: dict[str, set[MitreMappingStatus]] = {
    RULE_MAP_SSH_001: {MitreMappingStatus.CANDIDATE},
    RULE_MAP_SSH_002: {MitreMappingStatus.HYPOTHESIS},
    RULE_MAP_SSH_003: {MitreMappingStatus.CANDIDATE},
}

# Rule-to-Confidence Matrix
APPROVED_RULE_CONFIDENCES: dict[str, set[MitreConfidenceLevel]] = {
    RULE_MAP_SSH_001: {MitreConfidenceLevel.MEDIUM, MitreConfidenceLevel.HIGH},
    RULE_MAP_SSH_002: {MitreConfidenceLevel.LOW, MitreConfidenceLevel.MEDIUM},
    RULE_MAP_SSH_003: {MitreConfidenceLevel.LOW},
}


class MitreMappingValidationError(Exception):
    """Raised when a candidate proposal violates MITRE mapping validation rules."""
    pass


class MitreMappingValidator:
    """Validates candidate proposals before persistence as authoritative mappings."""

    def __init__(self, catalogue: MitreCatalogueService) -> None:
        self.catalogue = catalogue

    def validate_proposal(
        self,
        proposal: MitreCandidateProposal,
        provenance_set: AuthorizedProvenanceSet,
        investigation_id: Optional[uuid.UUID] = None,
        authorized_ssh_events: Optional[Sequence[SSHEventRecord]] = None,
        retrieval_metadata: Optional[EventRetrievalMetadata] = None,
    ) -> MitreAttackMapping:
        """Validate a single MitreCandidateProposal and construct an authoritative MitreAttackMapping.

        Args:
            proposal: The candidate proposal to validate.
            provenance_set: The active investigation's AuthorizedProvenanceSet.
            investigation_id: Optional UUID of the active investigation for UUID5 verification.
            authorized_ssh_events: Optional sequence of raw authorized SSH events for telemetry checks.
            retrieval_metadata: Optional retrieval metadata for coverage checks.

        Returns:
            Authoritative, immutable MitreAttackMapping instance with evidence_item_id=None.

        Raises:
            MitreMappingValidationError: If any validation rule is violated.
        """
        # 1. Rule Identifier & Approved Matrix Checks
        rule_id = proposal.rule_id
        if rule_id not in APPROVED_RULE_TECHNIQUES:
            raise MitreMappingValidationError(
                f"Unknown or unapproved mapping rule identifier: '{rule_id}'. "
                f"Allowed rules: {sorted(APPROVED_RULE_TECHNIQUES.keys())}"
            )

        expected_technique_id = APPROVED_RULE_TECHNIQUES[rule_id]
        if proposal.technique_id != expected_technique_id:
            raise MitreMappingValidationError(
                f"Rule '{rule_id}' is restricted to technique '{expected_technique_id}', "
                f"but proposal mapped to '{proposal.technique_id}'."
            )

        # 2. Status & Confidence Level Checks
        allowed_statuses = APPROVED_RULE_STATUSES[rule_id]
        if proposal.mapping_status not in allowed_statuses:
            raise MitreMappingValidationError(
                f"Rule '{rule_id}' does not allow status '{proposal.mapping_status.value}'. "
                f"Allowed statuses: {[s.value for s in allowed_statuses]}"
            )

        allowed_confidences = APPROVED_RULE_CONFIDENCES[rule_id]
        if proposal.confidence not in allowed_confidences:
            raise MitreMappingValidationError(
                f"Rule '{rule_id}' does not allow confidence '{proposal.confidence.value}'. "
                f"Allowed confidences: {[c.value for c in allowed_confidences]}"
            )

        # 3. Catalogue Existence, Deprecation, and Revocation Checks
        technique = self.catalogue.get_technique(proposal.technique_id)
        if technique is None:
            raise MitreMappingValidationError(
                f"Technique '{proposal.technique_id}' was not found in MITRE ATT&CK catalogue "
                f"v{self.catalogue.version}."
            )

        if getattr(technique, "deprecated", False):
            raise MitreMappingValidationError(
                f"Technique '{proposal.technique_id}' is marked as deprecated in MITRE ATT&CK catalogue."
            )

        if getattr(technique, "revoked", False):
            raise MitreMappingValidationError(
                f"Technique '{proposal.technique_id}' is marked as revoked in MITRE ATT&CK catalogue."
            )

        # 4. Anti-Circularity & Supporting References Validation
        if not proposal.supporting_references:
            raise MitreMappingValidationError(
                f"Proposal for rule '{rule_id}' contains no supporting references."
            )

        ref_event_uuids: list[uuid.UUID] = []
        for ref in proposal.supporting_references:
            try:
                canonical_ref = validate_canonical_source_reference(ref)
            except ValueError as err:
                raise MitreMappingValidationError(
                    f"Malformed supporting reference '{ref}': {err}"
                ) from err

            prefix, ident = canonical_ref.split("/", 1)
            if prefix != "ssh_events":
                raise MitreMappingValidationError(
                    f"Anti-circularity violation: Supporting reference '{canonical_ref}' uses prefix '{prefix}'. "
                    f"Behavioral mappings must be grounded strictly in 'ssh_events/<uuid>'."
                )

            try:
                ev_uuid = uuid.UUID(ident)
            except ValueError as err:
                raise MitreMappingValidationError(
                    f"Invalid UUID in supporting reference '{canonical_ref}': {err}"
                ) from err

            if ev_uuid not in provenance_set.ssh_events:
                raise MitreMappingValidationError(
                    f"Unauthorized supporting reference '{canonical_ref}': "
                    f"Event UUID '{ev_uuid}' was not retrieved in this investigation's authorized session."
                )

            ref_event_uuids.append(ev_uuid)

        # 5. Event IDs Consistency Checks
        if not proposal.event_ids:
            raise MitreMappingValidationError(
                f"Proposal for rule '{rule_id}' has empty event_ids."
            )

        if set(proposal.event_ids) != set(ref_event_uuids):
            raise MitreMappingValidationError(
                f"Mismatch between supporting_references UUIDs and event_ids for rule '{rule_id}'."
            )

        # 5b. Catalogue Version Check
        if proposal.catalogue_version != self.catalogue.version:
            raise MitreMappingValidationError(
                f"Catalogue version mismatch: proposal specifies '{proposal.catalogue_version}', "
                f"but active catalogue is '{self.catalogue.version}'."
            )

        # 6. Deterministic UUID5 Fingerprint Verification
        if investigation_id is not None:
            expected_uuid = compute_mapping_uuid5(
                investigation_id=investigation_id,
                catalogue_version=self.catalogue.version,
                rule_id=rule_id,
                technique_id=proposal.technique_id,
                supporting_references=proposal.supporting_references,
            )
            if proposal.mapping_id != expected_uuid:
                raise MitreMappingValidationError(
                    f"Deterministic UUID5 fingerprint mismatch: proposal mapping_id is '{proposal.mapping_id}', "
                    f"expected '{expected_uuid}'."
                )

        # 7. Telemetry & Window Verification (when authorized_ssh_events provided)
        if authorized_ssh_events is not None:
            event_map: dict[uuid.UUID, SSHEventRecord] = {
                ev.event_id: ev for ev in authorized_ssh_events
            }

            for ev_id in proposal.event_ids:
                if ev_id not in event_map:
                    raise MitreMappingValidationError(
                        f"Event ID '{ev_id}' referenced in proposal was not found in authorized_ssh_events telemetry."
                    )

            contributing_events = [event_map[ev_id] for ev_id in proposal.event_ids]

            # IP Consistency check
            source_ips = {str(ev.source_ip).strip() for ev in contributing_events}
            if len(source_ips) > 1:
                raise MitreMappingValidationError(
                    f"Proposal references events across multiple source IPs: {sorted(source_ips)}. "
                    f"Mappings must be single-source IP behavioral patterns."
                )

            # Window Bounds check
            timestamps = [
                ev.event_timestamp.astimezone(timezone.utc)
                if ev.event_timestamp.tzinfo is not None
                else ev.event_timestamp
                for ev in contributing_events
            ]
            earliest_ts = min(timestamps)
            latest_ts = max(timestamps)

            prop_start = (
                proposal.window_start.astimezone(timezone.utc)
                if proposal.window_start.tzinfo is not None
                else proposal.window_start
            )
            prop_end = (
                proposal.window_end.astimezone(timezone.utc)
                if proposal.window_end.tzinfo is not None
                else proposal.window_end
            )

            if prop_start != earliest_ts:
                raise MitreMappingValidationError(
                    f"Window start mismatch: proposal has '{prop_start}', "
                    f"earliest event is '{earliest_ts}'."
                )

            if prop_end != latest_ts:
                raise MitreMappingValidationError(
                    f"Window end mismatch: proposal has '{prop_end}', "
                    f"latest event is '{latest_ts}'."
                )

            # Re-generate deterministic proposals using MitreMappingEngine to verify complete behavioral fidelity
            if investigation_id is not None:
                engine = MitreMappingEngine(catalogue=self.catalogue)
                regenerated = engine.evaluate(
                    investigation_id=investigation_id,
                    authorized_ssh_events=authorized_ssh_events,
                    retrieval_metadata=retrieval_metadata,
                )
                matching = [
                    p
                    for p in regenerated
                    if p.rule_id == proposal.rule_id and p.technique_id == proposal.technique_id
                ]
                if not matching:
                    raise MitreMappingValidationError(
                        f"Behavioral evaluation failure: Provided telemetry does not satisfy rule '{proposal.rule_id}'."
                    )
                matched_prop = matching[0]

                # Full field-by-field tampering checks against regenerated proposal
                if proposal.mapping_id != matched_prop.mapping_id:
                    raise MitreMappingValidationError(
                        f"Mapping ID tampering detected for rule '{proposal.rule_id}': "
                        f"engine produced '{matched_prop.mapping_id}', got '{proposal.mapping_id}'."
                    )
                if proposal.rule_id != matched_prop.rule_id:
                    raise MitreMappingValidationError(
                        f"Rule ID mismatch: expected '{matched_prop.rule_id}', got '{proposal.rule_id}'."
                    )
                if proposal.technique_id != matched_prop.technique_id:
                    raise MitreMappingValidationError(
                        f"Technique ID mismatch for rule '{proposal.rule_id}': "
                        f"expected '{matched_prop.technique_id}', got '{proposal.technique_id}'."
                    )
                if proposal.supporting_references != matched_prop.supporting_references:
                    raise MitreMappingValidationError(
                        f"Supporting references mismatch for rule '{proposal.rule_id}': "
                        f"expected {matched_prop.supporting_references}, got {proposal.supporting_references}."
                    )
                if proposal.event_ids != matched_prop.event_ids:
                    raise MitreMappingValidationError(
                        f"Behavioral event mismatch for rule '{proposal.rule_id}': "
                        f"engine produced {matched_prop.event_ids}, got {proposal.event_ids}."
                    )
                if proposal.mapping_status != matched_prop.mapping_status:
                    raise MitreMappingValidationError(
                        f"Behavioral status mismatch for rule '{proposal.rule_id}': "
                        f"engine evaluated '{matched_prop.mapping_status.value}', proposal claimed '{proposal.mapping_status.value}'."
                    )
                if proposal.confidence != matched_prop.confidence:
                    raise MitreMappingValidationError(
                        f"Behavioral confidence mismatch for rule '{proposal.rule_id}': "
                        f"engine evaluated '{matched_prop.confidence.value}', proposal claimed '{proposal.confidence.value}'."
                    )
                if proposal.window_start != matched_prop.window_start:
                    raise MitreMappingValidationError(
                        f"Window start mismatch for rule '{proposal.rule_id}': "
                        f"expected '{matched_prop.window_start}', got '{proposal.window_start}'."
                    )
                if proposal.window_end != matched_prop.window_end:
                    raise MitreMappingValidationError(
                        f"Window end mismatch for rule '{proposal.rule_id}': "
                        f"expected '{matched_prop.window_end}', got '{proposal.window_end}'."
                    )
                if proposal.rationale != matched_prop.rationale:
                    raise MitreMappingValidationError(
                        f"Behavioral rationale tampering detected for rule '{proposal.rule_id}'."
                    )
                if proposal.catalogue_version != matched_prop.catalogue_version:
                    raise MitreMappingValidationError(
                        f"Catalogue version mismatch for rule '{proposal.rule_id}': "
                        f"expected '{matched_prop.catalogue_version}', got '{proposal.catalogue_version}'."
                    )

        # 8. Complete Coverage Safeguard for MAP-SSH-003
        if rule_id == RULE_MAP_SSH_003:
            if retrieval_metadata is None:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 requires retrieval metadata to verify complete 2-hour coverage."
                )

            if retrieval_metadata.truncated:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 rejected: retrieval was truncated, so complete 2-hour coverage cannot be guaranteed."
                )

            if not retrieval_metadata.coverage_complete:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 requires complete 2-hour preceding coverage. "
                    "Retrieval metadata indicates coverage_complete is False."
                )

            if retrieval_metadata.window_start is None or retrieval_metadata.window_end is None:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 rejected: retrieval metadata window boundaries are missing."
                )

            meta_start = retrieval_metadata.window_start
            meta_end = retrieval_metadata.window_end

            if meta_start.tzinfo is None or meta_start.tzinfo.utcoffset(meta_start) is None:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 rejected: retrieval metadata window_start must be timezone-aware."
                )
            if meta_end.tzinfo is None or meta_end.tzinfo.utcoffset(meta_end) is None:
                raise MitreMappingValidationError(
                    "Rule MAP-SSH-003 rejected: retrieval metadata window_end must be timezone-aware."
                )

            meta_start_utc = meta_start.astimezone(timezone.utc)
            meta_end_utc = meta_end.astimezone(timezone.utc)

            success_time = proposal.window_end.astimezone(timezone.utc)
            required_start_time = success_time - timedelta(hours=2)

            if meta_start_utc > required_start_time:
                raise MitreMappingValidationError(
                    f"Rule MAP-SSH-003 rejected: query window_start ({meta_start_utc}) does not cover the "
                    f"full required 2-hour preceding window (must begin on or before {required_start_time})."
                )

            if meta_end_utc < success_time:
                raise MitreMappingValidationError(
                    f"Rule MAP-SSH-003 rejected: query window_end ({meta_end_utc}) ends before "
                    f"the authentication event ({success_time})."
                )

        # 9. Authoritative Metadata Overwrite & Construction
        tactic_ids = sorted(technique.tactics)
        tactic_names: list[str] = []
        for tac_id in tactic_ids:
            tac = self.catalogue.get_tactic(tac_id)
            if tac:
                tactic_names.append(tac.name)

        return MitreAttackMapping(
            mapping_id=proposal.mapping_id,
            evidence_item_id=None,
            rule_id=rule_id,
            technique_id=proposal.technique_id,
            technique_name=technique.name,
            tactic_ids=tactic_ids,
            tactic_names=tactic_names,
            mapping_status=proposal.mapping_status,
            confidence=proposal.confidence,
            supporting_references=sorted(proposal.supporting_references),
            event_ids=sorted(proposal.event_ids),
            window_start=proposal.window_start,
            window_end=proposal.window_end,
            rationale=proposal.rationale,
            catalogue_version=self.catalogue.version,
        )

    def validate_proposals(
        self,
        proposals: Sequence[MitreCandidateProposal],
        provenance_set: AuthorizedProvenanceSet,
        investigation_id: Optional[uuid.UUID] = None,
        authorized_ssh_events: Optional[Sequence[SSHEventRecord]] = None,
        retrieval_metadata: Optional[EventRetrievalMetadata] = None,
    ) -> list[MitreAttackMapping]:
        """Validate a sequence of proposals, returning a list of authoritative MitreAttackMapping records."""
        validated: list[MitreAttackMapping] = []
        for prop in proposals:
            mapping = self.validate_proposal(
                proposal=prop,
                provenance_set=provenance_set,
                investigation_id=investigation_id,
                authorized_ssh_events=authorized_ssh_events,
                retrieval_metadata=retrieval_metadata,
            )
            validated.append(mapping)
        return validated
