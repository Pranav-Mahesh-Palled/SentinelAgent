"""In-memory service for querying the local normalized MITRE ATT&CK Enterprise catalogue.

Adheres strictly to Task 8B Architecture:
- Application-instantiable (NO module-level singletons).
- Strictly offline, read-only, and thread-safe.
- Verifies external SHA-256 sidecar before parsing.
- Validates Enterprise domain and expected version.
- Validates catalogue counts, tactic references, and reciprocal parent-child relationships.
- O(1) canonical identifier lookups.
- Rejects inactive (deprecated/revoked) techniques from active lookup.
- Provides advisory replacement lookup without automatic remapping.
- Exposes immutable data structures.
"""

from dataclasses import dataclass
import hashlib
import json
import logging
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Optional, Sequence, Set, Tuple

from pydantic import ValidationError

from app.schemas.mitre import (
    MitreCatalogueDocument,
    MitreCatalogueMetadata,
    MitreTacticRecord,
    MitreTechniqueRecord,
)

logger = logging.getLogger(__name__)

EXPECTED_DOMAIN = "enterprise-attack"
EXPECTED_VERSION = "20.1"


class MitreCatalogueError(Exception):
    """Base exception for all MITRE catalogue service failures."""
    pass


class MitreCatalogueNotFoundError(MitreCatalogueError):
    """Raised when the catalogue or its checksum sidecar file does not exist."""
    pass


class MitreCatalogueChecksumError(MitreCatalogueError):
    """Raised when the computed SHA-256 digest does not match the sidecar checksum."""
    pass


class MitreCatalogueValidationError(MitreCatalogueError):
    """Raised when the catalogue content violates schema, domain, or relational constraints."""
    pass


@dataclass(frozen=True)
class MitreReplacementAdvisory:
    """Advisory information for a revoked technique and its replacement."""

    revoked_technique_id: str
    revoked_technique_name: str
    replacement_technique_id: Optional[str]
    replacement_technique_name: Optional[str]
    message: str


def _compute_sha256(filepath: Path) -> str:
    """Compute hex-encoded SHA-256 digest of a local file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class MitreCatalogueService:
    """Thread-safe, read-only in-memory service for querying the compiled MITRE ATT&CK catalogue."""

    def __init__(self, document: MitreCatalogueDocument) -> None:
        """Initialize the in-memory catalogue service from a validated document.

        Direct instantiation expects a validated MitreCatalogueDocument.
        To load from disk with sidecar verification, use `MitreCatalogueService.from_file()`.
        """
        self._document = document
        self._metadata = document.metadata

        # Internal mutable indexes during initialization
        tactics_map: dict[str, MitreTacticRecord] = {}
        techniques_map: dict[str, MitreTechniqueRecord] = {}
        active_techniques_map: dict[str, MitreTechniqueRecord] = {}
        parent_to_subtechniques_map: dict[str, list[str]] = {}

        for tac_id, tac in document.tactics.items():
            tactics_map[tac_id] = tac

        for tech_id, tech in document.techniques.items():
            techniques_map[tech_id] = tech
            if not tech.revoked and not tech.deprecated:
                active_techniques_map[tech_id] = tech

            if tech.is_subtechnique and tech.subtechnique_of:
                parent_to_subtechniques_map.setdefault(tech.subtechnique_of, []).append(tech_id)

        # Freeze indexes into read-only MappingProxyTypes
        self._tactics: Mapping[str, MitreTacticRecord] = MappingProxyType(tactics_map)
        self._techniques: Mapping[str, MitreTechniqueRecord] = MappingProxyType(techniques_map)
        self._active_techniques: Mapping[str, MitreTechniqueRecord] = MappingProxyType(active_techniques_map)
        self._parent_to_subtechniques: Mapping[str, Tuple[str, ...]] = MappingProxyType({
            k: tuple(sorted(v)) for k, v in parent_to_subtechniques_map.items()
        })

    @classmethod
    def from_file(
        cls,
        catalogue_path: Path | str,
        checksum_path: Optional[Path | str] = None,
        expected_version: str = EXPECTED_VERSION,
        expected_domain: str = EXPECTED_DOMAIN,
    ) -> "MitreCatalogueService":
        """Load, verify sidecar checksum, validate schema & relations, and initialize the service.

        Args:
            catalogue_path: Path to the compiled normalized JSON artifact.
            checksum_path: Optional path to the .sha256 sidecar file. If omitted,
                           defaults to `{catalogue_path}.sha256`.
            expected_version: Expected ATT&CK version (default '20.1').
            expected_domain: Expected ATT&CK domain (default 'enterprise-attack').

        Returns:
            Instantiated and verified MitreCatalogueService.

        Raises:
            MitreCatalogueNotFoundError: File or sidecar does not exist.
            MitreCatalogueChecksumError: Digest mismatch.
            MitreCatalogueValidationError: Schema, domain, count, or relational integrity error.
        """
        cat_file = Path(catalogue_path).resolve()
        sidecar_file = Path(checksum_path).resolve() if checksum_path else Path(f"{cat_file}.sha256")

        if not cat_file.exists():
            raise MitreCatalogueNotFoundError(f"MITRE catalogue file not found: {cat_file}")
        if not sidecar_file.exists():
            raise MitreCatalogueNotFoundError(f"MITRE catalogue checksum sidecar not found: {sidecar_file}")

        # 1. Verify Checksum
        computed_sha = _compute_sha256(cat_file)
        try:
            with open(sidecar_file, "r", encoding="utf-8") as f:
                expected_sha = f.read().strip().split()[0].lower()
        except Exception as exc:
            raise MitreCatalogueChecksumError(f"Failed to read checksum sidecar: {exc}") from exc

        if computed_sha.lower() != expected_sha:
            raise MitreCatalogueChecksumError(
                f"Catalogue checksum mismatch. Computed: {computed_sha}, Expected: {expected_sha}"
            )

        # 2. Parse JSON
        try:
            with open(cat_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as exc:
            raise MitreCatalogueValidationError(f"Catalogue JSON malformed: {exc}") from exc

        # 3. Pydantic Schema Validation
        try:
            document = MitreCatalogueDocument.model_validate(raw_data)
        except ValidationError as exc:
            raise MitreCatalogueValidationError(f"Catalogue document validation failed: {exc}") from exc

        # 4. Domain & Version Verification
        if document.metadata.domain != expected_domain:
            raise MitreCatalogueValidationError(
                f"Invalid catalogue domain '{document.metadata.domain}', expected '{expected_domain}'."
            )
        if document.metadata.version != expected_version:
            raise MitreCatalogueValidationError(
                f"Invalid catalogue version '{document.metadata.version}', expected '{expected_version}'."
            )

        # 5. Metadata Count Validation
        actual_tech_count = len(document.techniques)
        actual_tactic_count = len(document.tactics)
        actual_active = sum(1 for t in document.techniques.values() if not t.revoked and not t.deprecated)
        actual_revoked = sum(1 for t in document.techniques.values() if t.revoked)
        actual_deprecated = sum(1 for t in document.techniques.values() if t.deprecated)

        if actual_tech_count != document.metadata.technique_count:
            raise MitreCatalogueValidationError(
                f"Technique count mismatch: actual {actual_tech_count} vs metadata {document.metadata.technique_count}"
            )
        if actual_tactic_count != document.metadata.tactic_count:
            raise MitreCatalogueValidationError(
                f"Tactic count mismatch: actual {actual_tactic_count} vs metadata {document.metadata.tactic_count}"
            )
        if actual_active != document.metadata.active_technique_count:
            raise MitreCatalogueValidationError(
                f"Active technique count mismatch: actual {actual_active} vs metadata {document.metadata.active_technique_count}"
            )
        if actual_revoked != document.metadata.revoked_technique_count:
            raise MitreCatalogueValidationError(
                f"Revoked technique count mismatch: actual {actual_revoked} vs metadata {document.metadata.revoked_technique_count}"
            )
        if actual_deprecated != document.metadata.deprecated_technique_count:
            raise MitreCatalogueValidationError(
                f"Deprecated technique count mismatch: actual {actual_deprecated} vs metadata {document.metadata.deprecated_technique_count}"
            )

        # 6. Relational Integrity Checks
        known_tactics = set(document.tactics.keys())
        known_techniques = set(document.techniques.keys())

        for tech_id, tech in document.techniques.items():
            # Tactic membership validation
            for tac_id in tech.tactics:
                if tac_id not in known_tactics:
                    raise MitreCatalogueValidationError(
                        f"Technique {tech_id} references nonexistent tactic {tac_id}"
                    )

            # Sub-technique parent-child validation
            if tech.is_subtechnique and tech.subtechnique_of:
                if tech.subtechnique_of not in known_techniques:
                    raise MitreCatalogueValidationError(
                        f"Subtechnique {tech_id} references nonexistent parent {tech.subtechnique_of}"
                    )
            for child_id in tech.subtechniques:
                if child_id not in known_techniques:
                    raise MitreCatalogueValidationError(
                        f"Parent technique {tech_id} references nonexistent child {child_id}"
                    )

            # Replacement reference validation
            if tech.revoked and tech.replaced_by:
                if tech.replaced_by not in known_techniques:
                    raise MitreCatalogueValidationError(
                        f"Revoked technique {tech_id} references nonexistent replacement {tech.replaced_by}"
                    )

        logger.info(
            "Loaded MITRE ATT&CK Enterprise v%s (%d active, %d revoked, %d deprecated techniques across %d tactics)",
            document.metadata.version,
            actual_active,
            actual_revoked,
            actual_deprecated,
            actual_tactic_count,
        )

        return cls(document)

    # -------------------------------------------------------------------------
    # Public Read-Only Properties
    # -------------------------------------------------------------------------

    @property
    def version(self) -> str:
        """Return the ATT&CK catalogue version string (e.g. '20.1')."""
        return self._metadata.version

    @property
    def domain(self) -> str:
        """Return the ATT&CK domain (e.g. 'enterprise-attack')."""
        return self._metadata.domain

    @property
    def metadata(self) -> MitreCatalogueMetadata:
        """Return the immutable catalogue metadata record."""
        return self._metadata

    # -------------------------------------------------------------------------
    # Public Lookup Methods (O(1))
    # -------------------------------------------------------------------------

    def get_technique(self, technique_id: str) -> Optional[MitreTechniqueRecord]:
        """Retrieve any technique or sub-technique by canonical ID, including inactive records.

        Supports historical forensic resolution. Returns None if ID is unknown.
        """
        clean_id = technique_id.strip() if technique_id else ""
        return self._techniques.get(clean_id)

    def get_active_technique(self, technique_id: str) -> Optional[MitreTechniqueRecord]:
        """Retrieve an ACTIVE (non-revoked, non-deprecated) technique by canonical ID.

        Returns None if ID is unknown, revoked, or deprecated.
        Used by behavioral mapping engines to prevent assigning inactive techniques.
        """
        clean_id = technique_id.strip() if technique_id else ""
        return self._active_techniques.get(clean_id)

    def get_tactic(self, tactic_id: str) -> Optional[MitreTacticRecord]:
        """Retrieve an enterprise tactic by canonical ID (e.g. 'TA0006').

        Returns None if ID is unknown.
        """
        clean_id = tactic_id.strip() if tactic_id else ""
        return self._tactics.get(clean_id)

    def get_subtechniques(self, parent_technique_id: str) -> Tuple[MitreTechniqueRecord, ...]:
        """Retrieve all registered child sub-technique records for a parent technique.

        Returns an immutable tuple of MitreTechniqueRecord instances.
        """
        clean_id = parent_technique_id.strip() if parent_technique_id else ""
        child_ids = self._parent_to_subtechniques.get(clean_id, ())
        return tuple(self._techniques[cid] for cid in child_ids if cid in self._techniques)

    def list_active_techniques(self) -> Tuple[MitreTechniqueRecord, ...]:
        """Return all active (non-revoked, non-deprecated) enterprise techniques and sub-techniques.

        Returns an immutable tuple sorted by canonical ID.
        """
        return tuple(self._active_techniques[k] for k in sorted(self._active_techniques.keys()))

    def list_tactics(self) -> Tuple[MitreTacticRecord, ...]:
        """Return all enterprise tactics in the catalogue.

        Returns an immutable tuple sorted by canonical ID.
        """
        return tuple(self._tactics[k] for k in sorted(self._tactics.keys()))

    def get_replacement_advisory(self, technique_id: str) -> Optional[MitreReplacementAdvisory]:
        """Return replacement advisory information if the technique is revoked.

        Does NOT automatically substitute or remap the technique.
        Returns None if the technique is unknown or not revoked.
        """
        tech = self.get_technique(technique_id)
        if not tech or not tech.revoked:
            return None

        replacement_id = tech.replaced_by
        replacement_name: Optional[str] = None
        if replacement_id:
            repl_tech = self.get_technique(replacement_id)
            if repl_tech:
                replacement_name = repl_tech.name

        msg = (
            f"Technique {tech.id} ('{tech.name}') is revoked by MITRE."
        )
        if replacement_id:
            msg += f" Advisory replacement is {replacement_id} ('{replacement_name}'). Independent re-evaluation required."
        else:
            msg += " No direct replacement specified."

        return MitreReplacementAdvisory(
            revoked_technique_id=tech.id,
            revoked_technique_name=tech.name,
            replacement_technique_id=replacement_id,
            replacement_technique_name=replacement_name,
            message=msg,
        )

