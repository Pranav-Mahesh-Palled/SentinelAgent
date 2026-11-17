"""Incident Memory Recall Service and Multi-Key Retrieval for SentinelAgent.

Adheres strictly to Task 9D Recall Architecture Specification (version 1.3.0):
- Coordinates the authenticated Hindsight recall client adapter (HindsightClientService).
- Enforces server-authoritative retrieval scope and deterministic query construction.
- Generates pseudonymous entity tags for active and historical HMAC key versions.
- Bounded concurrency with an application-instance-scoped asyncio.Semaphore.
- Strict 5.0s overall deadline enforcement with explicit task tracking and cleanup.
- Preserves successfully completed partial results upon timeouts or capacity limits.
- Interleaved round-robin result merging with stable memory ID deduplication.
- Strict rejection-first policy for oversized memories (>1000 chars) and 2000-char aggregate ceiling.
- Enforces epistemic boundaries: memories are HISTORICAL_CONTEXT_ONLY, never evidence.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import re
from typing import Any, Literal, Optional, Sequence, Union
import uuid

from app.core.config import Settings, get_settings
from app.schemas.mitre import MitreAttackMapping
from app.services.hindsight_client import (
    HindsightAuthenticationError,
    HindsightClientError,
    HindsightClientService,
    HindsightConnectionError,
    HindsightProtocolError,
    HindsightRecallItem,
    HindsightRecallResult,
    HindsightServerError,
    HindsightTimeoutError,
    HindsightValidationError,
)
from app.services.hmac_pseudonymizer import (
    HmacPseudonymizer,
    InvalidHMACKeyError,
    normalize_ip,
    normalize_username,
)
from app.services.investigation_tools import ActiveInvestigationContext
from app.services.mitre_mapping_validator import APPROVED_RULE_TECHNIQUES

logger = logging.getLogger(__name__)

# Architectural bounds from Task 9D Architecture Specification
MAX_FAN_OUT_QUERIES: int = 6
MAX_ITEMS_PER_QUERY: int = 5
MAX_RECALLED_MEMORIES: int = 10
MAX_SINGLE_MEMORY_CHARS: int = 1000
MAX_AGGREGATE_CONTEXT_CHARS: int = 2000
MAX_QUERY_STRING_LENGTH: int = 250

# Safe query token patterns (strict allowlist to prevent raw identifier or log line leaks)
SAFE_QUERY_TOKEN_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{2,64}$")
MITRE_TECHNIQUE_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")

# IP patterns to guard query string against sensitive identifier leakage
IPV4_DETECTION_PATTERN = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])"
)
IPV6_DETECTION_PATTERN = re.compile(
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


PERMITTED_INCIDENT_CLASSIFICATIONS: frozenset[str] = frozenset({
    "brute_force",
    "ssh_brute_force",
    "credential_stuffing",
    "password_spraying",
    "unauthorized_access",
    "distributed_brute_force",
    "reconnaissance",
    "anomalous_login",
    "privilege_escalation",
    "lateral_movement",
    "suspicious_activity",
    "ssh_anomaly",
})

PERMITTED_AUTH_PATTERNS: frozenset[str] = frozenset({
    "password_spray",
    "password_spraying",
    "dictionary_attack",
    "credential_stuffing",
    "single_source_distributed_users",
    "distributed_source_single_user",
    "rapid_failed_logins",
    "unusual_login_time",
    "invalid_user_enumeration",
    "root_login_attempt",
})

PERMITTED_DETECTION_CATEGORIES: frozenset[str] = frozenset({
    "ssh_telemetry",
    "rule_detection",
    "anomaly_detection",
    "isolation_forest",
    "ssh_anomaly",
    "failed_authentication",
})


@dataclass(frozen=True)
class RecallQueryPlan:
    """Internal plan for an individual scoped Hindsight recall query."""

    identity_category: Literal["source_ip", "username"]
    key_version: str
    tag: str
    query_text: str


@dataclass(frozen=True)
class RecallItemResult:
    """Immutable representation of a single accepted recalled memory unit.

    Forensic Invariant: Recalled memories are strictly historical background intelligence.
    They do not carry authoritative evidence classifications and cannot enter AuthorizedProvenanceSet.
    """

    memory_id: str
    text: str
    fact_type: Optional[str]
    context: Optional[str] = None
    document_id: Optional[str] = None
    identity_category: Literal["source_ip", "username"] = "source_ip"
    key_version: str = "v1"
    within_query_rank: int = 1
    occurred_start: Optional[datetime] = None
    occurred_end: Optional[datetime] = None
    mentioned_at: Optional[datetime] = None
    retrieved_at: Optional[datetime] = None
    trust_classification: str = "HISTORICAL_CONTEXT_ONLY"
    scope_verified: bool = True


@dataclass(frozen=True)
class AuthoritativeRecallContext:
    """Immutable, strictly-validated server-authoritative context for incident memory recall.

    Enforces that:
    - investigation_id and incident_id are valid UUID instances.
    - source_ip (if provided) is a syntactically valid IPv4 or IPv6 address.
    - username (if provided) is a normalized, non-empty, non-whitespace identifier.
    - incident_type (if provided) belongs to PERMITTED_INCIDENT_CLASSIFICATIONS.
    - auth_pattern (if provided) belongs to PERMITTED_AUTH_PATTERNS.
    - mitre_techniques (if provided) contains only valid MITRE technique IDs (T#### or T####.###).
    - detection_category (if provided) belongs to PERMITTED_DETECTION_CATEGORIES.
    - incident_timestamp (if provided) is a valid datetime.
    """

    investigation_id: uuid.UUID
    incident_id: uuid.UUID
    source_ip: Optional[str] = None
    username: Optional[str] = None
    incident_type: Optional[str] = None
    auth_pattern: Optional[str] = None
    mitre_techniques: tuple[str, ...] = ()
    detection_category: Optional[str] = None
    incident_timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not isinstance(self.investigation_id, uuid.UUID):
            raise ValueError(f"investigation_id must be a uuid.UUID instance, got {type(self.investigation_id).__name__}")
        if not isinstance(self.incident_id, uuid.UUID):
            raise ValueError(f"incident_id must be a uuid.UUID instance, got {type(self.incident_id).__name__}")

        if self.source_ip is not None:
            if not isinstance(self.source_ip, str) or not self.source_ip.strip():
                raise ValueError("source_ip, if supplied, must be a non-empty string.")
            try:
                norm_ip = normalize_ip(self.source_ip)
                object.__setattr__(self, "source_ip", norm_ip)
            except ValueError as e:
                raise ValueError(f"Invalid source_ip in AuthoritativeRecallContext: {e}") from e

        if self.username is not None:
            if not isinstance(self.username, str) or not self.username.strip():
                raise ValueError("username, if supplied, must be a non-empty string.")
            clean_user = normalize_username(self.username)
            if len(clean_user) > 64 or IPV4_DETECTION_PATTERN.search(clean_user) or IPV6_DETECTION_PATTERN.search(clean_user):
                raise ValueError(f"Invalid username in AuthoritativeRecallContext: '{clean_user}'.")
            object.__setattr__(self, "username", clean_user)

        if self.incident_type is not None:
            if not isinstance(self.incident_type, str):
                raise ValueError(f"incident_type must be a string, got {type(self.incident_type).__name__}")
            clean_type = self.incident_type.strip().lower()
            if clean_type not in PERMITTED_INCIDENT_CLASSIFICATIONS:
                raise ValueError(
                    f"Invalid incident_type '{self.incident_type}'. Must be one of allowlisted classifications."
                )
            object.__setattr__(self, "incident_type", clean_type)

        if self.auth_pattern is not None:
            if not isinstance(self.auth_pattern, str):
                raise ValueError(f"auth_pattern must be a string, got {type(self.auth_pattern).__name__}")
            clean_pattern = self.auth_pattern.strip().lower()
            if clean_pattern not in PERMITTED_AUTH_PATTERNS:
                raise ValueError(
                    f"Invalid auth_pattern '{self.auth_pattern}'. Must be one of allowlisted authentication patterns."
                )
            object.__setattr__(self, "auth_pattern", clean_pattern)

        if self.detection_category is not None:
            if not isinstance(self.detection_category, str):
                raise ValueError(f"detection_category must be a string, got {type(self.detection_category).__name__}")
            clean_cat = self.detection_category.strip().lower()
            if clean_cat not in PERMITTED_DETECTION_CATEGORIES:
                raise ValueError(
                    f"Invalid detection_category '{self.detection_category}'. Must be one of allowlisted detection categories."
                )
            object.__setattr__(self, "detection_category", clean_cat)

        if self.mitre_techniques:
            validated_mitre: list[str] = []
            for tid in self.mitre_techniques:
                if not isinstance(tid, str) or not MITRE_TECHNIQUE_PATTERN.match(tid.strip().upper()):
                    raise ValueError(f"Invalid MITRE technique ID: '{tid}'. Must match pattern T#### or T####.###.")
                validated_mitre.append(tid.strip().upper())
            object.__setattr__(self, "mitre_techniques", tuple(sorted(set(validated_mitre))))

        if self.incident_timestamp is not None:
            if not isinstance(self.incident_timestamp, datetime):
                raise ValueError("incident_timestamp must be a datetime instance or None.")

    @classmethod
    def from_investigation_context(
        cls,
        context: ActiveInvestigationContext,
    ) -> "AuthoritativeRecallContext":
        """Construct an internal AuthoritativeRecallContext from a server-managed ActiveInvestigationContext."""
        if not isinstance(context, ActiveInvestigationContext):
            raise TypeError(
                f"context must be an ActiveInvestigationContext instance, got {type(context).__name__}"
            )

        # Extract MITRE techniques strictly from server-validated mapping results (MitreAttackMapping).
        # Unvalidated candidate proposals, raw strings, historical MemoryMitreMapping objects,
        # or arbitrary mappings not adhering to APPROVED_RULE_TECHNIQUES are excluded.
        extracted_mitre: list[str] = []
        raw_mappings = getattr(context, "validated_mitre_mappings", ()) or ()
        for m in raw_mappings:
            if isinstance(m, MitreAttackMapping):
                rule = getattr(m, "rule_id", None)
                tid = getattr(m, "technique_id", None)
                if rule in APPROVED_RULE_TECHNIQUES and APPROVED_RULE_TECHNIQUES[rule] == tid:
                    if tid and isinstance(tid, str) and tid.strip():
                        extracted_mitre.append(tid.strip().upper())

        return cls(
            investigation_id=context.investigation_id,
            incident_id=context.incident_id,
            source_ip=context.source_ip,
            username=getattr(context, "username", None),
            incident_type=getattr(context, "incident_type", None),
            auth_pattern=getattr(context, "auth_pattern", None),
            mitre_techniques=tuple(sorted(set(extracted_mitre))),
            detection_category=getattr(context, "detection_category", None),
            incident_timestamp=context.created_at,
        )


@dataclass(frozen=True)
class IncidentMemoryRecallResult:
    """Typed service-level outcome of a multi-query incident memory recall operation."""

    status: Literal["success", "empty", "partial", "skipped", "unavailable"]
    items: tuple[RecallItemResult, ...] = ()
    total_candidates_retrieved: int = 0
    items_rejected_oversized: int = 0
    attempted_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    skipped_reason: Optional[str] = None
    diagnostic_classifications: tuple[str, ...] = ()
    retrieved_at: Optional[datetime] = None


def sanitize_query_token(token: Any) -> Optional[str]:
    """Sanitize and validate an individual query token against strict allowlists."""
    if not isinstance(token, str):
        return None
    clean = token.strip()
    if not clean or len(clean) > 64:
        return None
    # Reject strings with whitespace or non-identifier characters
    if not SAFE_QUERY_TOKEN_PATTERN.match(clean):
        return None
    # Guard against IP addresses accidentally matching identifier patterns
    if IPV4_DETECTION_PATTERN.search(clean) or IPV6_DETECTION_PATTERN.search(clean):
        return None
    return clean.lower()


def build_recall_query(
    incident_type: Optional[str] = None,
    auth_pattern: Optional[str] = None,
    mitre_techniques: Optional[Sequence[str]] = None,
    detection_category: Optional[str] = None,
) -> Optional[str]:
    """Construct a deterministic, server-controlled behavioral search query from allowlisted inputs.

    Never includes raw IP addresses, usernames, passwords, credentials, tokens, or raw log lines.
    Returns None if insufficient safe context exists to formulate a meaningful search query.
    """
    clean_type = sanitize_query_token(incident_type)
    clean_pattern = sanitize_query_token(auth_pattern)
    clean_category = sanitize_query_token(detection_category)

    valid_mitre: list[str] = []
    if mitre_techniques:
        for m in mitre_techniques:
            if isinstance(m, str) and MITRE_TECHNIQUE_PATTERN.match(m.strip().upper()):
                valid_mitre.append(m.strip().upper())
    # Sort deterministically
    sorted_mitre = sorted(set(valid_mitre))

    # If zero valid structural elements exist, refuse to formulate a broad generic query
    if not clean_type and not clean_pattern and not clean_category and not sorted_mitre:
        return None

    query_components: list[str] = []
    if clean_type:
        query_components.append(f"classification: {clean_type}")
    if clean_pattern:
        query_components.append(f"pattern: {clean_pattern}")
    if clean_category:
        query_components.append(f"category: {clean_category}")
    if sorted_mitre:
        query_components.append(f"techniques: {', '.join(sorted_mitre)}")

    assembled = "Incident attack context; " + "; ".join(query_components)
    return assembled[:MAX_QUERY_STRING_LENGTH].strip()


class IncidentMemoryRecallService:
    """Application-instance-scoped service coordinating multi-key historical incident memory retrieval."""

    def __init__(
        self,
        hindsight_client: HindsightClientService,
        pseudonymizer: HmacPseudonymizer,
        settings: Optional[Settings] = None,
    ) -> None:
        if not isinstance(hindsight_client, HindsightClientService):
            raise TypeError(
                f"hindsight_client must be an instance of HindsightClientService, got {type(hindsight_client).__name__}"
            )
        if not isinstance(pseudonymizer, HmacPseudonymizer):
            raise TypeError(
                f"pseudonymizer must be an instance of HmacPseudonymizer, got {type(pseudonymizer).__name__}"
            )

        self._hindsight_client = hindsight_client
        self._pseudonymizer = pseudonymizer
        self._settings = settings or get_settings()

        # Instance-scoped concurrency control: exactly one Semaphore per service instance
        max_concurrent = int(self._settings.HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS)
        self._max_concurrency = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        self._semaphore_timeout = float(self._settings.HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS)
        self._overall_timeout = float(self._settings.HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS)
        self._request_timeout = float(self._settings.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS)
        self._max_tokens = int(self._settings.HINDSIGHT_RECALL_MAX_TOKENS)
        self._budget = str(self._settings.HINDSIGHT_RECALL_BUDGET)

    @property
    def max_concurrency(self) -> int:
        """Return the maximum concurrent recall operations configured for this service instance."""
        return self._max_concurrency

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Return the instance-scoped concurrency semaphore."""
        return self._semaphore

    def generate_query_plans(
        self,
        source_ip: Optional[str],
        username: Optional[str],
        query_text: str,
    ) -> list[RecallQueryPlan]:
        """Generate deterministic, deduplicated recall query plans prioritized by entity and key version.

        Priority order:
        1. IP category: active key version
        2. IP category: historical key versions (sorted)
        3. Username category: active key version
        4. Username category: historical key versions (sorted)

        Maximum fan-out is strictly capped at MAX_FAN_OUT_QUERIES (6).
        """
        plans: list[RecallQueryPlan] = []
        seen_tags: set[str] = set()

        # 1. IP Category
        if source_ip and isinstance(source_ip, str) and source_ip.strip():
            try:
                norm_ip = normalize_ip(source_ip)
                active_ver = self._pseudonymizer.active_version

                # Active key first
                tag_active = self._pseudonymizer.pseudonymize_ip(norm_ip, key_version=active_ver)
                if tag_active not in seen_tags:
                    seen_tags.add(tag_active)
                    plans.append(
                        RecallQueryPlan(
                            identity_category="source_ip",
                            key_version=active_ver,
                            tag=tag_active,
                            query_text=query_text,
                        )
                    )

                # Historical keys sorted deterministically
                for ver in sorted(self._pseudonymizer.available_versions):
                    if ver == active_ver:
                        continue
                    tag_hist = self._pseudonymizer.pseudonymize_ip(norm_ip, key_version=ver)
                    if tag_hist not in seen_tags:
                        seen_tags.add(tag_hist)
                        plans.append(
                            RecallQueryPlan(
                                identity_category="source_ip",
                                key_version=ver,
                                tag=tag_hist,
                                query_text=query_text,
                            )
                        )
            except (ValueError, InvalidHMACKeyError) as exc:
                logger.warning("Failed to normalize or pseudonymize source IP for recall: %s", type(exc).__name__)

        # 2. Username Category
        if username and isinstance(username, str) and username.strip():
            try:
                norm_user = normalize_username(username)
                active_ver = self._pseudonymizer.active_version

                # Active key first
                tag_active = self._pseudonymizer.pseudonymize_username(norm_user, key_version=active_ver)
                if tag_active not in seen_tags:
                    seen_tags.add(tag_active)
                    plans.append(
                        RecallQueryPlan(
                            identity_category="username",
                            key_version=active_ver,
                            tag=tag_active,
                            query_text=query_text,
                        )
                    )

                # Historical keys sorted deterministically
                for ver in sorted(self._pseudonymizer.available_versions):
                    if ver == active_ver:
                        continue
                    tag_hist = self._pseudonymizer.pseudonymize_username(norm_user, key_version=ver)
                    if tag_hist not in seen_tags:
                        seen_tags.add(tag_hist)
                        plans.append(
                            RecallQueryPlan(
                                identity_category="username",
                                key_version=ver,
                                tag=tag_hist,
                                query_text=query_text,
                            )
                        )
            except (ValueError, InvalidHMACKeyError) as exc:
                logger.warning("Failed to normalize or pseudonymize username for recall: %s", type(exc).__name__)

        return plans[:MAX_FAN_OUT_QUERIES]

    async def _execute_single_query(
        self,
        plan: RecallQueryPlan,
        incident_timestamp: Optional[datetime],
    ) -> tuple[RecallQueryPlan, Optional[HindsightRecallResult], Optional[str]]:
        """Execute a single recall query bounded by the concurrency semaphore and request timeout.

        Guarantees that semaphore permits are released in finally blocks upon success,
        exception, or external task cancellation.
        """
        acquired = False
        try:
            # Non-blocking semaphore acquisition with bounded timeout
            await asyncio.wait_for(self._semaphore.acquire(), timeout=self._semaphore_timeout)
            acquired = True
        except (TimeoutError, asyncio.TimeoutError):
            logger.warning("Recall semaphore capacity exhausted for %s query", plan.identity_category)
            return plan, None, "SEMAPHORE_CAPACITY_EXHAUSTED"
        except asyncio.CancelledError:
            raise

        try:
            result = await self._hindsight_client.recall_incident_memories(
                tag=plan.tag,
                query=plan.query_text,
                query_timestamp=incident_timestamp,
                max_tokens=self._max_tokens,
                budget=self._budget,
                request_timeout=self._request_timeout,
            )
            return plan, result, None
        except HindsightAuthenticationError:
            logger.error("Hindsight recall authentication error for %s query", plan.identity_category)
            return plan, None, "AUTHENTICATION_ERROR"
        except HindsightTimeoutError:
            logger.warning("Hindsight recall request timed out for %s query", plan.identity_category)
            return plan, None, "REQUEST_TIMEOUT"
        except HindsightConnectionError:
            logger.warning("Hindsight recall connection error for %s query", plan.identity_category)
            return plan, None, "CONNECTION_ERROR"
        except HindsightServerError:
            logger.warning("Hindsight recall server error for %s query", plan.identity_category)
            return plan, None, "SERVER_ERROR"
        except HindsightProtocolError:
            logger.warning("Hindsight recall protocol error for %s query", plan.identity_category)
            return plan, None, "PROTOCOL_ERROR"
        except HindsightValidationError:
            logger.warning("Hindsight recall validation error for %s query", plan.identity_category)
            return plan, None, "VALIDATION_ERROR"
        except HindsightClientError:
            logger.warning("Hindsight recall client error for %s query", plan.identity_category)
            return plan, None, "CLIENT_ERROR"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Unexpected error during recall query: %s", type(exc).__name__)
            return plan, None, "UNKNOWN_ERROR"
        finally:
            if acquired:
                self._semaphore.release()

    async def recall_memories(
        self,
        context: ActiveInvestigationContext,
    ) -> IncidentMemoryRecallResult:
        """Execute parallel multi-key recall across source IP and targeted username scopes.

        Bounds overall execution to HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS (5.0s), cancels
        outstanding tasks on deadline expiry, preserves partial results, and merges memories
        using deterministic round-robin interleaving and stable memory ID deduplication.
        """
        retrieved_at = datetime.now(timezone.utc)

        # 1. Feature Flag: Enforce that recall is globally enabled
        if not self._settings.HINDSIGHT_RECALL_ENABLED:
            return IncidentMemoryRecallResult(
                status="skipped",
                skipped_reason="RECALL_DISABLED",
                retrieved_at=retrieved_at,
            )

        # 2. Strict Provenance Enforcement: Reject directly supplied AuthoritativeRecallContext,
        # dictionaries, and arbitrary objects. Only server-managed ActiveInvestigationContext is accepted.
        if isinstance(context, AuthoritativeRecallContext):
            raise TypeError(
                "Direct AuthoritativeRecallContext input is rejected. "
                "recall_memories only accepts server-managed ActiveInvestigationContext."
            )
        if not isinstance(context, ActiveInvestigationContext):
            raise TypeError(
                f"context must be an ActiveInvestigationContext instance, got {type(context).__name__}"
            )

        # 3. Resolve authoritative parameters from strictly validated server context
        auth_context = AuthoritativeRecallContext.from_investigation_context(context)

        eff_ip = auth_context.source_ip
        eff_user = auth_context.username
        eff_type = auth_context.incident_type
        eff_pattern = auth_context.auth_pattern
        eff_mitre = auth_context.mitre_techniques
        eff_category = auth_context.detection_category
        eff_timestamp = auth_context.incident_timestamp

        # 3. Guard against missing identifiers: at least one identity category is required
        if not eff_ip and not eff_user:
            return IncidentMemoryRecallResult(
                status="skipped",
                skipped_reason="NO_USABLE_IDENTIFIERS",
                retrieved_at=retrieved_at,
            )

        # 4. Deterministic query construction from allowlisted structural fields
        query_text = build_recall_query(
            incident_type=eff_type,
            auth_pattern=eff_pattern,
            mitre_techniques=eff_mitre,
            detection_category=eff_category,
        )
        if not query_text:
            return IncidentMemoryRecallResult(
                status="skipped",
                skipped_reason="INSUFFICIENT_QUERY_CONTEXT",
                retrieved_at=retrieved_at,
            )

        # 5. Generate prioritized query plans (max 6 queries)
        plans = self.generate_query_plans(
            source_ip=eff_ip,
            username=eff_user,
            query_text=query_text,
        )
        if not plans:
            return IncidentMemoryRecallResult(
                status="skipped",
                skipped_reason="NO_QUERY_PLANS_GENERATED",
                retrieved_at=retrieved_at,
            )

        # 6. Execute bounded parallel queries with overall deadline enforcement
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._overall_timeout

        task_map = {
            asyncio.create_task(
                self._execute_single_query(plan, eff_timestamp)
            ): plan
            for plan in plans
        }

        successful_results: dict[RecallQueryPlan, HindsightRecallResult] = {}
        diagnostic_classifications: list[str] = []
        attempted_count = len(plans)
        success_count = 0
        failed_count = 0

        try:
            remaining_time = max(0.0, deadline - loop.time())
            done, pending = await asyncio.wait(
                task_map.keys(),
                timeout=remaining_time,
                return_when=asyncio.ALL_COMPLETED,
            )
        except asyncio.CancelledError:
            # Caller cancelled: cleanly cancel and await all scheduled query tasks
            for t in task_map.keys():
                t.cancel()
            await asyncio.gather(*task_map.keys(), return_exceptions=True)
            raise

        # If overall deadline expired while queries were still running, cancel pending
        if pending:
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in pending:
                diagnostic_classifications.append("OVERALL_DEADLINE_EXCEEDED")
                failed_count += 1

        # Process completed tasks
        for t in done:
            if t.cancelled():
                diagnostic_classifications.append("QUERY_CANCELLED")
                failed_count += 1
            elif t.exception() is not None:
                exc = t.exception()
                diagnostic_classifications.append(type(exc).__name__)
                failed_count += 1
            else:
                plan, result, error_code = t.result()
                if error_code is not None:
                    diagnostic_classifications.append(error_code)
                    failed_count += 1
                elif result is not None:
                    successful_results[plan] = result
                    success_count += 1
                else:
                    diagnostic_classifications.append("EMPTY_RESPONSE")
                    failed_count += 1

        # 7. Deterministic Interleaved Round-Robin Merge
        query_streams: list[tuple[RecallQueryPlan, list[HindsightRecallItem]]] = []
        for plan in plans:
            if plan in successful_results:
                raw_items = list(successful_results[plan].items)[:MAX_ITEMS_PER_QUERY]
                query_streams.append((plan, raw_items))

        seen_memory_ids: set[str] = set()
        accepted_items: list[RecallItemResult] = []
        items_rejected_oversized = 0
        total_candidates = sum(len(items) for _, items in query_streams)
        current_total_chars = 0

        max_depth = max((len(items) for _, items in query_streams), default=0)

        for depth in range(max_depth):
            for plan, stream in query_streams:
                if depth < len(stream):
                    candidate = stream[depth]

                    # Deduplicate by stable Hindsight memory UUID
                    if candidate.id in seen_memory_ids:
                        continue

                    # Rejection-first policy for oversized individual memory facts (> 1000 chars)
                    if len(candidate.text) > MAX_SINGLE_MEMORY_CHARS:
                        seen_memory_ids.add(candidate.id)
                        items_rejected_oversized += 1
                        continue

                    # Aggregate character budget ceiling (2000 chars max)
                    if current_total_chars + len(candidate.text) > MAX_AGGREGATE_CONTEXT_CHARS:
                        continue

                    seen_memory_ids.add(candidate.id)
                    current_total_chars += len(candidate.text)

                    accepted_items.append(
                        RecallItemResult(
                            memory_id=candidate.id,
                            text=candidate.text,
                            fact_type=candidate.fact_type,
                            context=candidate.context,
                            document_id=candidate.document_id,
                            identity_category=plan.identity_category,
                            key_version=plan.key_version,
                            within_query_rank=depth + 1,
                            occurred_start=candidate.occurred_start,
                            occurred_end=candidate.occurred_end,
                            mentioned_at=candidate.mentioned_at,
                            retrieved_at=retrieved_at,
                            scope_verified=candidate.scope_verified,
                        )
                    )

                    if len(accepted_items) >= MAX_RECALLED_MEMORIES:
                        break
            if len(accepted_items) >= MAX_RECALLED_MEMORIES:
                break

        # 8. Resolve retrieval status
        if success_count == attempted_count and failed_count == 0:
            if len(accepted_items) > 0:
                retrieval_status: Literal["success", "empty", "partial", "skipped", "unavailable"] = "success"
            else:
                retrieval_status = "empty"
        elif success_count > 0 and len(accepted_items) > 0:
            retrieval_status = "partial"
        else:
            retrieval_status = "unavailable"

        return IncidentMemoryRecallResult(
            status=retrieval_status,
            items=tuple(accepted_items),
            total_candidates_retrieved=total_candidates,
            items_rejected_oversized=items_rejected_oversized,
            attempted_queries=attempted_count,
            successful_queries=success_count,
            failed_queries=failed_count,
            diagnostic_classifications=tuple(diagnostic_classifications),
            retrieved_at=retrieved_at,
        )
