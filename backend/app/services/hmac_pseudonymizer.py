"""Cryptographic HMAC-SHA256 Pseudonymization Service for SentinelAgent.

Implements Section 9 of the Task 9A architecture specification:
- Truncated 128-bit HMAC-SHA256 digests (32 lowercase hexadecimal characters).
- Cryptographic domain separation using canonical prefixes:
    * IP address:       ip:<key_version>:<normalized_ip>
    * Username:         user:<key_version>:<normalized_username>
- IP normalization using python's `ipaddress.ip_address()`.
- Username case-preservation with Unicode NFC normalization.
- Fail-closed key configuration validation (minimum 32-character / 256-bit key length).
- Active-key generation for new memories; historical multi-key generation for recall.
- Sensitive identifier scanning and scrubbing in free-text and structured records.
"""

from collections.abc import Iterable
import hashlib
import hmac
import ipaddress
import logging
import re
from typing import Any, Optional, Union
import unicodedata

from pydantic import SecretStr

from app.core.config import Settings, settings

logger = logging.getLogger(__name__)

# Output length: 128 bits = 32 lowercase hex characters
PSEUDONYM_HEX_LENGTH = 32

# Pattern matching valid 32-hex pseudonym digests
PSEUDONYM_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{32}$")

# Minimum secret key byte length (256 bits = 32 bytes in UTF-8 representation).
# Keys should be generated using a cryptographically secure random generator
# (e.g., secrets.token_bytes(32) or secrets.token_hex(32)) and supplied via protected configuration.
MIN_KEY_BYTES = 32
MIN_KEY_LENGTH = 32  # Backwards compatibility alias


class PseudonymizationError(Exception):
    """Base exception for pseudonymization and redaction failures."""
    pass


class InvalidHMACKeyError(PseudonymizationError):
    """Raised when an HMAC key is missing, empty, or insufficient in length."""
    pass


class RedactionVerificationError(PseudonymizationError):
    """Raised when residual sensitive identifiers are detected post-serialization."""
    pass


def normalize_ip(raw_ip: str) -> str:
    """Normalize IPv4 or IPv6 address using standard ipaddress parser.

    Produces canonical compressed representation (e.g. lowercase IPv6, no leading zeros).
    """
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        raise ValueError("IP address must be a non-empty string.")
    try:
        parsed = ipaddress.ip_address(raw_ip.strip())
        return str(parsed)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: {e}") from e


def normalize_username(raw_username: str) -> str:
    """Normalize username preserving case with Unicode NFC normalization and stripped whitespace.

    Preserves case to prevent colliding distinct accounts (e.g. 'Admin' vs 'admin'
    in case-sensitive identity systems) while standardizing equivalent Unicode forms.
    """
    if not isinstance(raw_username, str) or not raw_username.strip():
        raise ValueError("Username must be a non-empty string.")
    # Standardize to Unicode NFC (canonical composition) and strip leading/trailing whitespace
    return unicodedata.normalize("NFC", raw_username.strip())


class HmacPseudonymizer:
    """Cryptographic HMAC-SHA256 pseudonymizer with domain separation and key rotation."""

    def __init__(
        self,
        active_key: Union[SecretStr, str],
        active_version: str = "v1",
        previous_keys: Optional[dict[str, Union[SecretStr, str]]] = None,
    ) -> None:
        if isinstance(active_key, str):
            active_key = SecretStr(active_key)
        if not active_key or not active_key.get_secret_value().strip():
            raise InvalidHMACKeyError("Active HMAC key cannot be empty.")
        raw_key = active_key.get_secret_value().strip()
        raw_key_bytes = raw_key.encode("utf-8")
        if len(raw_key_bytes) < MIN_KEY_BYTES:
            raise InvalidHMACKeyError(
                f"Active HMAC key must be at least {MIN_KEY_BYTES} UTF-8 bytes (256 bits) for cryptographic security."
            )

        if not active_version or not active_version.strip():
            raise InvalidHMACKeyError("Active HMAC key version cannot be empty.")

        self._active_key_bytes = raw_key_bytes
        self._active_version = active_version.strip()
        self._previous_keys_bytes: dict[str, bytes] = {}

        if previous_keys:
            for ver, prev_key in previous_keys.items():
                if not ver or not ver.strip():
                    raise InvalidHMACKeyError("Previous key version identifier cannot be empty.")
                clean_ver = ver.strip()
                if clean_ver == self._active_version:
                    raise InvalidHMACKeyError(
                        f"Previous key version '{clean_ver}' conflicts with active version."
                    )
                if isinstance(prev_key, str):
                    prev_key = SecretStr(prev_key)
                if not prev_key or not prev_key.get_secret_value().strip():
                    raise InvalidHMACKeyError(f"Previous key for version '{clean_ver}' cannot be empty.")
                prev_raw = prev_key.get_secret_value().strip()
                prev_raw_bytes = prev_raw.encode("utf-8")
                if len(prev_raw_bytes) < MIN_KEY_BYTES:
                    raise InvalidHMACKeyError(
                        f"Previous key for version '{clean_ver}' must be at least {MIN_KEY_BYTES} UTF-8 bytes."
                    )
                self._previous_keys_bytes[clean_ver] = prev_raw_bytes

    @property
    def active_version(self) -> str:
        """Return the active HMAC key version."""
        return self._active_version

    @property
    def available_versions(self) -> list[str]:
        """Return all available key versions (active first, followed by previous)."""
        return [self._active_version] + sorted(self._previous_keys_bytes.keys())

    def _compute_digest(self, key_bytes: bytes, canonical_input: str) -> str:
        """Compute truncated 128-bit HMAC-SHA256 digest (32 lowercase hex characters)."""
        h = hmac.new(key_bytes, canonical_input.encode("utf-8"), hashlib.sha256)
        full_hex = h.hexdigest().lower()
        return full_hex[:PSEUDONYM_HEX_LENGTH]

    def pseudonymize_ip(self, raw_ip: str, key_version: Optional[str] = None) -> str:
        """Compute the canonical pseudonym for an IP address.

        Canonical format: ip:<key_version>:<32-hex-digest>
        Domain input:     ip:<key_version>:<normalized_ip>
        """
        norm_ip = normalize_ip(raw_ip)
        target_version = (key_version or self._active_version).strip()

        if target_version == self._active_version:
            key_bytes = self._active_key_bytes
        elif target_version in self._previous_keys_bytes:
            key_bytes = self._previous_keys_bytes[target_version]
        else:
            raise InvalidHMACKeyError(f"Requested key version '{target_version}' is not configured.")

        canonical_input = f"ip:{target_version}:{norm_ip}"
        digest = self._compute_digest(key_bytes, canonical_input)
        return f"ip:{target_version}:{digest}"

    def pseudonymize_username(self, raw_username: str, key_version: Optional[str] = None) -> str:
        """Compute the canonical pseudonym for a username.

        Canonical format: user:<key_version>:<32-hex-digest>
        Domain input:     user:<key_version>:<normalized_username>
        """
        norm_user = normalize_username(raw_username)
        target_version = (key_version or self._active_version).strip()

        if target_version == self._active_version:
            key_bytes = self._active_key_bytes
        elif target_version in self._previous_keys_bytes:
            key_bytes = self._previous_keys_bytes[target_version]
        else:
            raise InvalidHMACKeyError(f"Requested key version '{target_version}' is not configured.")

        canonical_input = f"user:{target_version}:{norm_user}"
        digest = self._compute_digest(key_bytes, canonical_input)
        return f"user:{target_version}:{digest}"

    def generate_all_ip_pseudonyms(self, raw_ip: str) -> dict[str, str]:
        """Generate pseudonyms for an IP across active and all previous key versions.

        Used for multi-key recall queries in Task 9D.
        Returns: {key_version: pseudonym_tag}
        """
        norm_ip = normalize_ip(raw_ip)
        results = {
            self._active_version: self.pseudonymize_ip(norm_ip, key_version=self._active_version)
        }
        for ver in self._previous_keys_bytes:
            results[ver] = self.pseudonymize_ip(norm_ip, key_version=ver)
        return results

    def generate_all_username_pseudonyms(self, raw_username: str) -> dict[str, str]:
        """Generate pseudonyms for a username across active and all previous key versions.

        Used for multi-key recall queries in Task 9D.
        Returns: {key_version: pseudonym_tag}
        """
        norm_user = normalize_username(raw_username)
        results = {
            self._active_version: self.pseudonymize_username(norm_user, key_version=self._active_version)
        }
        for ver in self._previous_keys_bytes:
            results[ver] = self.pseudonymize_username(norm_user, key_version=ver)
        return results


def get_pseudonymizer_from_settings(app_settings: Optional[Settings] = None) -> HmacPseudonymizer:
    """Factory creating an HmacPseudonymizer instance from application settings."""
    cfg = app_settings or settings
    if not cfg.HINDSIGHT_HMAC_KEY:
        raise InvalidHMACKeyError(
            "HINDSIGHT_HMAC_KEY must be configured before initializing the pseudonymizer."
        )
    return HmacPseudonymizer(
        active_key=cfg.HINDSIGHT_HMAC_KEY,
        active_version=cfg.HINDSIGHT_HMAC_KEY_VERSION,
        previous_keys=cfg.HINDSIGHT_PREVIOUS_HMAC_KEYS,
    )
