#!/usr/bin/env python3
"""Offline STIX 2.1 Compiler for MITRE ATT&CK Enterprise Catalogue.

Extracts, normalizes, and validates MITRE ATT&CK Enterprise tactics, techniques,
and relationships from a local STIX 2.1 JSON bundle into a lean, deterministic,
byte-reproducible catalogue artifact with an external SHA-256 sidecar.

Zero runtime external dependencies (standard library only).
Zero network requests (strictly offline operation).
"""

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


class CatalogueCompilationError(Exception):
    """Raised when compilation cannot proceed due to validation or schema errors."""
    pass


def compute_sha256(filepath: Path) -> str:
    """Compute hex-encoded SHA-256 digest of a local file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_canonical_external_id(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Extract canonical ATT&CK external identifier (e.g. TA0006, T1110, T1110.001)."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id")
            if ext_id:
                return str(ext_id).strip()
    return None


def get_official_url(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Extract official ATT&CK documentation URL from external_references."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            url = ref.get("url")
            if url:
                return str(url).strip()
    return None


def compile_catalogue(
    source_path: Path,
    output_path: Path,
    upstream_commit: str = "f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7",
    upstream_repo: str = "https://github.com/mitre-attack/attack-stix-data",
) -> Tuple[Path, Path, Dict[str, Any]]:
    """Compile a local STIX 2.1 bundle into normalized JSON and SHA-256 sidecar.

    Args:
        source_path: Path to the local raw STIX 2.1 JSON file.
        output_path: Destination path for the compiled JSON catalogue.
        upstream_commit: Git commit SHA of the upstream source dataset.
        upstream_repo: Upstream source repository URL.

    Returns:
        Tuple of (compiled_json_path, checksum_path, metadata_dict)
    """
    if not source_path.exists():
        raise CatalogueCompilationError(f"STIX source file does not exist: {source_path}")

    # 1. Compute upstream file SHA-256
    upstream_sha256 = compute_sha256(source_path)

    # 2. Parse JSON
    try:
        with open(source_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as exc:
        raise CatalogueCompilationError(f"Malformed STIX JSON bundle: {exc}") from exc

    if not isinstance(bundle, dict) or "objects" not in bundle:
        raise CatalogueCompilationError("Invalid STIX bundle: missing top-level 'objects' list")

    objects: List[Dict[str, Any]] = bundle["objects"]

    # 3. Identify and validate Collection metadata
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if not collections:
        raise CatalogueCompilationError("No x-mitre-collection found in STIX bundle")

    coll = collections[0]
    coll_name = coll.get("name", "")
    if coll_name != "Enterprise ATT&CK":
        raise CatalogueCompilationError(
            f"Unsupported collection: '{coll_name}'. Compiler strictly requires 'Enterprise ATT&CK'."
        )

    version = coll.get("x_mitre_version")
    if not version:
        raise CatalogueCompilationError("Collection missing 'x_mitre_version'")

    release_date = coll.get("modified", "")[:10]  # YYYY-MM-DD

    # Set of STIX IDs officially included in this collection version
    included_stix_ids: Set[str] = {c["object_ref"] for c in coll.get("x_mitre_contents", [])}

    # 4. Extract Tactics (x-mitre-tactic)
    tactics_raw = [
        o for o in objects
        if o.get("type") == "x-mitre-tactic" and o.get("id") in included_stix_ids
    ]
    tactics: Dict[str, Dict[str, Any]] = {}
    shortname_to_tactic_id: Dict[str, str] = {}

    for t in tactics_raw:
        tac_id = get_canonical_external_id(t)
        if not tac_id:
            raise CatalogueCompilationError(f"Tactic object {t.get('id')} lacks canonical external_id")

        short_name = t.get("x_mitre_shortname", "")
        if not short_name:
            raise CatalogueCompilationError(f"Tactic {tac_id} lacks 'x_mitre_shortname'")

        shortname_to_tactic_id[short_name] = tac_id

        tactics[tac_id] = {
            "id": tac_id,
            "stix_id": t.get("id"),
            "name": t.get("name", "").strip(),
            "short_name": short_name.strip(),
            "description": t.get("description", "").strip(),
            "url": get_official_url(t),
        }

    # 5. Extract Techniques (attack-pattern)
    patterns_raw = [
        o for o in objects
        if o.get("type") == "attack-pattern" and o.get("id") in included_stix_ids
    ]
    stix_id_to_pattern: Dict[str, Dict[str, Any]] = {}
    canonical_id_to_stix_id: Dict[str, str] = {}
    stix_id_to_canonical_id: Dict[str, str] = {}

    for p in patterns_raw:
        stix_id = p.get("id")
        ext_id = get_canonical_external_id(p)
        if not ext_id:
            raise CatalogueCompilationError(f"attack-pattern {stix_id} lacks canonical external_id")

        if ext_id in canonical_id_to_stix_id:
            raise CatalogueCompilationError(f"Duplicate canonical technique identifier detected: {ext_id}")

        canonical_id_to_stix_id[ext_id] = stix_id
        stix_id_to_canonical_id[stix_id] = ext_id
        stix_id_to_pattern[stix_id] = p

    # 6. Extract Relationships (relationship)
    relationships = [o for o in objects if o.get("type") == "relationship"]

    # Map child STIX ID -> parent STIX ID (for subtechnique-of)
    child_to_parent_stix: Dict[str, str] = {}
    parent_to_children_stix: Dict[str, List[str]] = defaultdict(list)

    # Map source STIX ID -> target STIX ID (for revoked-by)
    revoked_by_stix: Dict[str, str] = {}

    for r in relationships:
        rel_type = r.get("relationship_type")
        src = r.get("source_ref")
        tgt = r.get("target_ref")

        if not src or not tgt:
            continue

        if rel_type == "subtechnique-of":
            if src in stix_id_to_pattern and tgt in stix_id_to_pattern:
                child_to_parent_stix[src] = tgt
                parent_to_children_stix[tgt].append(src)

        elif rel_type == "revoked-by":
            if src in stix_id_to_pattern and tgt in stix_id_to_pattern:
                revoked_by_stix[src] = tgt

    # 7. Compile and Normalize Techniques
    techniques: Dict[str, Dict[str, Any]] = {}
    active_count = 0
    revoked_count = 0
    deprecated_count = 0

    for stix_id, p in stix_id_to_pattern.items():
        tech_id = stix_id_to_canonical_id[stix_id]
        is_sub = bool(p.get("x_mitre_is_subtechnique", False))
        revoked = bool(p.get("revoked", False))
        deprecated = bool(p.get("x_mitre_deprecated", False))

        if revoked:
            revoked_count += 1
        elif deprecated:
            deprecated_count += 1
        else:
            active_count += 1

        # Resolve Tactic IDs from kill_chain_phases
        associated_tactics: Set[str] = set()
        for phase in p.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") in ("mitre-attack", "mitre-enterprise-attack"):
                phase_name = phase.get("phase_name")
                if phase_name in shortname_to_tactic_id:
                    associated_tactics.add(shortname_to_tactic_id[phase_name])

        # Resolve parent and child subtechniques
        parent_tech_id: Optional[str] = None
        if is_sub:
            parent_stix = child_to_parent_stix.get(stix_id)
            if parent_stix and parent_stix in stix_id_to_canonical_id:
                parent_tech_id = stix_id_to_canonical_id[parent_stix]
            elif "." in tech_id:
                # Fallback: canonical ID prefix for subtechnique (e.g. T1110 for T1110.001)
                inferred_parent = tech_id.split(".", 1)[0]
                if inferred_parent in canonical_id_to_stix_id:
                    parent_tech_id = inferred_parent

        child_tech_ids: List[str] = []
        for child_stix in parent_to_children_stix.get(stix_id, []):
            if child_stix in stix_id_to_canonical_id:
                child_tech_ids.append(stix_id_to_canonical_id[child_stix])

        # Resolve replacement if revoked
        replacement_id: Optional[str] = None
        if revoked:
            target_stix = revoked_by_stix.get(stix_id)
            if target_stix and target_stix in stix_id_to_canonical_id:
                replacement_id = stix_id_to_canonical_id[target_stix]

        # Extract sorted platforms
        platforms: List[str] = sorted(list(p.get("x_mitre_platforms", [])))

        techniques[tech_id] = {
            "id": tech_id,
            "stix_id": stix_id,
            "name": p.get("name", "").strip(),
            "description": p.get("description", "").strip(),
            "tactics": sorted(list(associated_tactics)),
            "platforms": platforms,
            "is_subtechnique": is_sub,
            "subtechnique_of": parent_tech_id,
            "subtechniques": sorted(child_tech_ids),
            "revoked": revoked,
            "deprecated": deprecated,
            "replaced_by": replacement_id,
            "url": get_official_url(p),
        }

    # 8. Reciprocal Parent-Child Validation
    for tech_id, t_dict in techniques.items():
        if t_dict["is_subtechnique"]:
            parent_id = t_dict["subtechnique_of"]
            if not parent_id:
                # Historical revoked subtechniques may lack parent relationship
                if not t_dict["revoked"] and not t_dict["deprecated"]:
                    raise CatalogueCompilationError(
                        f"Active subtechnique {tech_id} has no valid parent technique."
                    )
            elif parent_id in techniques:
                parent_dict = techniques[parent_id]
                if tech_id not in parent_dict["subtechniques"]:
                    parent_dict["subtechniques"].append(tech_id)
                    parent_dict["subtechniques"].sort()

    # 9. Build Root Document with Metadata
    metadata = {
        "domain": "enterprise-attack",
        "version": str(version),
        "release_date": release_date,
        "upstream_repository": upstream_repo,
        "upstream_commit": upstream_commit,
        "upstream_file": source_path.name,
        "upstream_sha256": upstream_sha256,
        "technique_count": len(techniques),
        "active_technique_count": active_count,
        "revoked_technique_count": revoked_count,
        "deprecated_technique_count": deprecated_count,
        "tactic_count": len(tactics),
    }

    # Sort dictionary keys for deterministic serialization
    sorted_tactics = {k: tactics[k] for k in sorted(tactics.keys())}
    sorted_techniques = {k: techniques[k] for k in sorted(techniques.keys())}

    document = {
        "metadata": metadata,
        "tactics": sorted_tactics,
        "techniques": sorted_techniques,
    }

    # 10. Write Normalized JSON Deterministically
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(document, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")

    # 11. Generate External SHA-256 Sidecar
    compiled_sha256 = compute_sha256(output_path)
    checksum_path = Path(f"{output_path}.sha256")
    with open(checksum_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{compiled_sha256}  {output_path.name}\n")

    return output_path, checksum_path, metadata


def main() -> None:
    """CLI entrypoint for offline MITRE ATT&CK catalogue compiler."""
    if len(sys.argv) < 3:
        print("Usage: python compile_mitre_catalogue.py <stix_source_json> <output_catalogue_json>")
        sys.exit(1)

    src = Path(sys.argv[1]).resolve()
    dst = Path(sys.argv[2]).resolve()

    print(f"Compiling MITRE ATT&CK catalogue from: {src}")
    try:
        out_json, out_sha, meta = compile_catalogue(src, dst)
        print(f"Successfully compiled: {out_json}")
        print(f"Checksum sidecar:     {out_sha}")
        print(f"Domain:               {meta['domain']}")
        print(f"Version:              {meta['version']}")
        print(f"Release Date:         {meta['release_date']}")
        print(f"Techniques Total:     {meta['technique_count']}")
        print(f"  - Active:           {meta['active_technique_count']}")
        print(f"  - Revoked:          {meta['revoked_technique_count']}")
        print(f"  - Deprecated:       {meta['deprecated_technique_count']}")
        print(f"Tactics Total:        {meta['tactic_count']}")
    except CatalogueCompilationError as exc:
        print(f"Compilation failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

