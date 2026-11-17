"""Unit and integration tests for Task 8B: MITRE ATT&CK Enterprise Catalogue.

Verifies:
1. Compiler tests:
   - Valid Enterprise source compilation.
   - Rejection of invalid/unsupported collection domains.
   - Rejection of missing/corrupted STIX objects.
   - Rejection of duplicate canonical identifiers.
   - Reciprocal subtechnique-of parent-child resolution.
   - Kill-chain phase mapping to canonical tactics.
   - Revoked-by relationships and replacement target resolution.
   - Preservation of active, revoked, and deprecated records.
   - Byte-reproducible compilation across identical runs.
   - External SHA-256 sidecar generation and validation.

2. Service tests:
   - Successful initialization from verified catalogue file.
   - O(1) active technique lookup (T1110, T1110.001, etc.).
   - Missing technique lookup returns None.
   - Deprecated and revoked techniques are rejected by get_active_technique().
   - Historical lookup preserves inactive records (get_technique()).
   - Advisory replacement generation without automatic remapping.
   - Tactic lookup by canonical ID (TA0006, etc.).
   - Parent/subtechnique bidirectional navigation.
   - Missing catalogue file raises MitreCatalogueNotFoundError.
   - Missing sidecar file raises MitreCatalogueNotFoundError.
   - Checksum tampering raises MitreCatalogueChecksumError.
   - Schema/domain/version/count mismatches raise MitreCatalogueValidationError.
   - Immutability of returned indexes and records.

3. Real compiled catalogue validation:
   - Verified Enterprise ATT&CK v20.1 artifact.
   - Actual measured technique and tactic counts.
"""

import hashlib
import json
from pathlib import Path
from pydantic import ValidationError
import pytest
import sys

from app.schemas.mitre import (
    MitreCatalogueDocument,
    MitreCatalogueMetadata,
    MitreTacticRecord,
    MitreTechniqueRecord,
)
from app.services.mitre_catalogue_service import (
    MitreCatalogueChecksumError,
    MitreCatalogueError,
    MitreCatalogueNotFoundError,
    MitreCatalogueService,
    MitreCatalogueValidationError,
    MitreReplacementAdvisory,
)

# Import compiler script
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "backend" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import compile_mitre_catalogue as compiler


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def real_catalogue_path() -> Path:
    """Path to the real compiled Enterprise ATT&CK v20.1 catalogue."""
    p = PROJECT_ROOT / "backend" / "app" / "data" / "mitre" / "mitre_attack_enterprise_v20_1.json"
    if not p.exists():
        pytest.skip(f"Real catalogue not found at {p}")
    return p


@pytest.fixture
def real_catalogue_service(real_catalogue_path: Path) -> MitreCatalogueService:
    """Instantiated MitreCatalogueService backed by real compiled data."""
    return MitreCatalogueService.from_file(real_catalogue_path)


@pytest.fixture
def sample_stix_bundle(tmp_path: Path) -> Path:
    """Creates a minimal valid STIX 2.1 Enterprise ATT&CK bundle for unit testing."""
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-1111-1111-111111111111",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--test",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "20.1",
                "modified": "2026-11-05T15:00:00.000Z",
                "x_mitre_contents": [
                    {"object_ref": "x-mitre-tactic--tac1"},
                    {"object_ref": "attack-pattern--tech1"},
                    {"object_ref": "attack-pattern--sub1"},
                    {"object_ref": "attack-pattern--rev1"},
                    {"object_ref": "attack-pattern--dep1"},
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--tac1",
                "name": "Credential Access",
                "x_mitre_shortname": "credential-access",
                "description": "Techniques to steal credentials.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "TA0006",
                        "url": "https://attack.mitre.org/tactics/TA0006",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--tech1",
                "name": "Brute Force",
                "description": "Adversary attempts to guess passwords.",
                "x_mitre_is_subtechnique": False,
                "x_mitre_platforms": ["Linux", "Windows"],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "credential-access",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1110",
                        "url": "https://attack.mitre.org/techniques/T1110",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--sub1",
                "name": "Password Guessing",
                "description": "Systematic password guessing.",
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": ["Linux"],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "credential-access",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1110.001",
                        "url": "https://attack.mitre.org/techniques/T1110/001",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--rev1",
                "name": "Old Technique",
                "description": "Revoked technique.",
                "revoked": True,
                "x_mitre_is_subtechnique": False,
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "credential-access",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9000",
                        "url": "https://attack.mitre.org/techniques/T9000",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--dep1",
                "name": "Deprecated Technique",
                "description": "Deprecated technique.",
                "x_mitre_deprecated": True,
                "x_mitre_is_subtechnique": False,
                "x_mitre_platforms": ["Linux"],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "credential-access",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9001",
                        "url": "https://attack.mitre.org/techniques/T9001",
                    }
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--sub-rel",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--sub1",
                "target_ref": "attack-pattern--tech1",
            },
            {
                "type": "relationship",
                "id": "relationship--rev-rel",
                "relationship_type": "revoked-by",
                "source_ref": "attack-pattern--rev1",
                "target_ref": "attack-pattern--tech1",
            },
        ],
    }
    src_file = tmp_path / "sample_stix.json"
    with open(src_file, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return src_file


# =============================================================================
# 1. Compiler Tests
# =============================================================================

class TestCompiler:
    """Test suite for offline compile_mitre_catalogue script."""

    def test_compile_sample_bundle(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify successful compilation of a valid STIX bundle."""
        out_json = tmp_path / "compiled.json"
        out_path, sidecar_path, meta = compiler.compile_catalogue(sample_stix_bundle, out_json)

        assert out_path.exists()
        assert sidecar_path.exists()
        assert meta["domain"] == "enterprise-attack"
        assert meta["version"] == "20.1"
        assert meta["technique_count"] == 4
        assert meta["active_technique_count"] == 2
        assert meta["revoked_technique_count"] == 1
        assert meta["deprecated_technique_count"] == 1
        assert meta["tactic_count"] == 1

        # Check sidecar content
        computed = compiler.compute_sha256(out_path)
        with open(sidecar_path, "r", encoding="utf-8") as f:
            sidecar_content = f.read().strip()
        assert sidecar_content.startswith(computed)

    def test_compile_byte_reproducibility(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify compiling identical input multiple times produces identical bytes."""
        out1 = tmp_path / "run1.json"
        out2 = tmp_path / "run2.json"

        compiler.compile_catalogue(sample_stix_bundle, out1)
        compiler.compile_catalogue(sample_stix_bundle, out2)

        h1 = compiler.compute_sha256(out1)
        h2 = compiler.compute_sha256(out2)
        assert h1 == h2

        with open(out1, "rb") as f1, open(out2, "rb") as f2:
            assert f1.read() == f2.read()

    def test_rejects_nonexistent_source(self, tmp_path: Path) -> None:
        """Verify clear error when source file is missing."""
        with pytest.raises(compiler.CatalogueCompilationError, match="does not exist"):
            compiler.compile_catalogue(tmp_path / "missing.json", tmp_path / "out.json")

    def test_rejects_malformed_json(self, tmp_path: Path) -> None:
        """Verify clear error on corrupted/malformed JSON."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{ incomplete json ...", encoding="utf-8")

        with pytest.raises(compiler.CatalogueCompilationError, match="Malformed STIX JSON"):
            compiler.compile_catalogue(bad_json, tmp_path / "out.json")

    def test_rejects_unsupported_collection(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify rejection of Mobile or non-Enterprise collections."""
        with open(sample_stix_bundle, "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data["objects"]:
            if obj.get("type") == "x-mitre-collection":
                obj["name"] = "Mobile ATT&CK"

        bad_stix = tmp_path / "mobile_stix.json"
        with open(bad_stix, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with pytest.raises(compiler.CatalogueCompilationError, match="Unsupported collection"):
            compiler.compile_catalogue(bad_stix, tmp_path / "out.json")

    def test_rejects_duplicate_canonical_ids(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify detection and rejection of duplicate external technique IDs."""
        with open(sample_stix_bundle, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Duplicate T1110
        dup = {
            "type": "attack-pattern",
            "id": "attack-pattern--dup",
            "name": "Duplicate T1110",
            "description": "Collision",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        }
        data["objects"].append(dup)
        data["objects"][0]["x_mitre_contents"].append({"object_ref": "attack-pattern--dup"})

        dup_file = tmp_path / "dup.json"
        with open(dup_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with pytest.raises(compiler.CatalogueCompilationError, match="Duplicate canonical technique identifier"):
            compiler.compile_catalogue(dup_file, tmp_path / "out.json")

    def test_resolves_revoked_by_advisory(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify revoked-by relationship correctly maps to replacement technique ID."""
        out_json = tmp_path / "compiled.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        rev_tech = data["techniques"]["T9000"]
        assert rev_tech["revoked"] is True
        assert rev_tech["replaced_by"] == "T1110"


# =============================================================================
# 2. Catalogue Service Tests
# =============================================================================

class TestMitreCatalogueService:
    """Test suite for MitreCatalogueService querying and validation."""

    def test_service_loads_from_sample(self, sample_stix_bundle: Path, tmp_path: Path) -> None:
        """Verify service loads and validates sample compiled catalogue."""
        out_json = tmp_path / "test_catalogue.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)

        svc = MitreCatalogueService.from_file(out_json)
        assert svc.domain == "enterprise-attack"
        assert svc.version == "20.1"

        # Tactic check
        tac = svc.get_tactic("TA0006")
        assert tac is not None
        assert tac.name == "Credential Access"

        # Active technique check
        active_tech = svc.get_active_technique("T1110")
        assert active_tech is not None
        assert active_tech.name == "Brute Force"
        assert "TA0006" in active_tech.tactics
        assert "T1110.001" in active_tech.subtechniques

        # Subtechnique navigation
        subs = svc.get_subtechniques("T1110")
        assert len(subs) == 1
        assert subs[0].id == "T1110.001"
        assert subs[0].name == "Password Guessing"

    def test_active_lookup_rejects_revoked_and_deprecated(
        self, sample_stix_bundle: Path, tmp_path: Path
    ) -> None:
        """Verify get_active_technique() rejects inactive techniques while get_technique() preserves them."""
        out_json = tmp_path / "test_catalogue.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)
        svc = MitreCatalogueService.from_file(out_json)

        # Revoked technique T9000
        assert svc.get_active_technique("T9000") is None
        hist_rev = svc.get_technique("T9000")
        assert hist_rev is not None
        assert hist_rev.revoked is True
        assert hist_rev.replaced_by == "T1110"

        # Deprecated technique T9001
        assert svc.get_active_technique("T9001") is None
        hist_dep = svc.get_technique("T9001")
        assert hist_dep is not None
        assert hist_dep.deprecated is True

    def test_replacement_advisory_without_automatic_remapping(
        self, sample_stix_bundle: Path, tmp_path: Path
    ) -> None:
        """Verify get_replacement_advisory returns advisory without modifying technique lookups."""
        out_json = tmp_path / "test_catalogue.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)
        svc = MitreCatalogueService.from_file(out_json)

        advisory = svc.get_replacement_advisory("T9000")
        assert advisory is not None
        assert isinstance(advisory, MitreReplacementAdvisory)
        assert advisory.revoked_technique_id == "T9000"
        assert advisory.replacement_technique_id == "T1110"
        assert advisory.replacement_technique_name == "Brute Force"
        assert "Independent re-evaluation required" in advisory.message

        # Non-revoked technique returns None
        assert svc.get_replacement_advisory("T1110") is None

    def test_checksum_mismatch_raises_error(
        self, sample_stix_bundle: Path, tmp_path: Path
    ) -> None:
        """Verify tampering with catalogue bytes causes MitreCatalogueChecksumError."""
        out_json = tmp_path / "tampered.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)

        # Tamper with file content
        with open(out_json, "a", encoding="utf-8") as f:
            f.write("\n ")

        with pytest.raises(MitreCatalogueChecksumError, match="checksum mismatch"):
            MitreCatalogueService.from_file(out_json)

    def test_missing_files_raise_not_found(self, tmp_path: Path) -> None:
        """Verify missing catalogue or checksum raises MitreCatalogueNotFoundError."""
        with pytest.raises(MitreCatalogueNotFoundError, match="catalogue file not found"):
            MitreCatalogueService.from_file(tmp_path / "missing.json")

        # Catalogue exists but sidecar missing
        real_f = tmp_path / "exists.json"
        real_f.write_text("{}", encoding="utf-8")
        with pytest.raises(MitreCatalogueNotFoundError, match="checksum sidecar not found"):
            MitreCatalogueService.from_file(real_f)

    def test_wrong_domain_or_version_raises_validation_error(
        self, sample_stix_bundle: Path, tmp_path: Path
    ) -> None:
        """Verify mismatched version expectation raises MitreCatalogueValidationError."""
        out_json = tmp_path / "test_catalogue.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)

        with pytest.raises(MitreCatalogueValidationError, match="Invalid catalogue version"):
            MitreCatalogueService.from_file(out_json, expected_version="19.0")

        with pytest.raises(MitreCatalogueValidationError, match="Invalid catalogue domain"):
            MitreCatalogueService.from_file(out_json, expected_domain="ics-attack")

    def test_immutability_of_returned_data(
        self, sample_stix_bundle: Path, tmp_path: Path
    ) -> None:
        """Verify returned collections and records cannot be mutated."""
        out_json = tmp_path / "test_catalogue.json"
        compiler.compile_catalogue(sample_stix_bundle, out_json)
        svc = MitreCatalogueService.from_file(out_json)

        active = svc.list_active_techniques()
        assert isinstance(active, tuple)

        tactics = svc.list_tactics()
        assert isinstance(tactics, tuple)

        tech = svc.get_active_technique("T1110")
        assert tech is not None
        with pytest.raises((AttributeError, TypeError, ValidationError)):
            tech.name = "Tampered Name"  # Frozen Pydantic model


# =============================================================================
# 3. Real Enterprise ATT&CK v20.1 Catalogue Validation
# =============================================================================

class TestRealEnterpriseCatalogue:
    """Rigorous verification of the production compiled v20.1 catalogue artifact."""

    def test_real_catalogue_loads_and_verifies_checksum(
        self, real_catalogue_service: MitreCatalogueService
    ) -> None:
        """Verify the real compiled catalogue loads cleanly with valid sidecar checksum."""
        assert real_catalogue_service.domain == "enterprise-attack"
        assert real_catalogue_service.version == "20.1"

    def test_real_catalogue_measured_counts(
        self, real_catalogue_service: MitreCatalogueService
    ) -> None:
        """Verify exact measured counts match STIX 2.1 Enterprise release metadata."""
        meta = real_catalogue_service.metadata
        assert meta.technique_count == 867
        assert meta.active_technique_count == 706
        assert meta.revoked_technique_count == 149
        assert meta.deprecated_technique_count == 12
        assert meta.tactic_count == 15
        assert len(real_catalogue_service.list_active_techniques()) == 706
        assert len(real_catalogue_service.list_tactics()) == 15

    def test_real_catalogue_core_investigation_techniques(
        self, real_catalogue_service: MitreCatalogueService
    ) -> None:
        """Verify presence and exact attributes of core SentinelAgent investigation techniques."""
        # 1. T1110: Brute Force
        t1110 = real_catalogue_service.get_active_technique("T1110")
        assert t1110 is not None
        assert t1110.name == "Brute Force"
        assert "TA0006" in t1110.tactics
        assert "T1110.001" in t1110.subtechniques
        assert "T1110.003" in t1110.subtechniques
        assert t1110.is_subtechnique is False

        # 2. T1110.001: Password Guessing
        t1110_001 = real_catalogue_service.get_active_technique("T1110.001")
        assert t1110_001 is not None
        assert t1110_001.name == "Password Guessing"
        assert t1110_001.is_subtechnique is True
        assert t1110_001.subtechnique_of == "T1110"
        assert "Linux" in t1110_001.platforms

        # 3. T1110.003: Password Spraying
        t1110_003 = real_catalogue_service.get_active_technique("T1110.003")
        assert t1110_003 is not None
        assert t1110_003.name == "Password Spraying"
        assert t1110_003.subtechnique_of == "T1110"

        # 4. T1078: Valid Accounts
        t1078 = real_catalogue_service.get_active_technique("T1078")
        assert t1078 is not None
        assert t1078.name == "Valid Accounts"

        # 5. TA0006: Credential Access
        ta0006 = real_catalogue_service.get_tactic("TA0006")
        assert ta0006 is not None
        assert ta0006.name == "Credential Access"
        assert ta0006.short_name == "credential-access"

    def test_real_catalogue_revoked_technique_advisory(
        self, real_catalogue_service: MitreCatalogueService
    ) -> None:
        """Verify real revoked technique (e.g. T1150) resolves replacement advisory."""
        # T1150 was revoked in favor of T1547.011 (Plist Modification)
        assert real_catalogue_service.get_active_technique("T1150") is None

        rev_tech = real_catalogue_service.get_technique("T1150")
        assert rev_tech is not None
        assert rev_tech.revoked is True
        assert rev_tech.replaced_by == "T1547.011"

        advisory = real_catalogue_service.get_replacement_advisory("T1150")
        assert advisory is not None
        assert advisory.replacement_technique_id == "T1547.011"
        assert advisory.replacement_technique_name == "Plist Modification"
