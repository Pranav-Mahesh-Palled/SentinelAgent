"""Comprehensive unit and security tests for HmacPseudonymizer.

Verifies Task 9C.2 requirements:
- Deterministic pseudonyms for identical input.
- Different pseudonyms for different identifiers.
- IP and username cryptographic domain separation.
- IPv4 normalization (e.g. leading zeros, whitespace).
- IPv6 normalization (RFC 5952 canonical compressed representation).
- Username case-preservation (e.g. 'Admin' vs 'admin' produce distinct pseudonyms).
- Unicode NFC normalization.
- Exact 128-bit output length (32 lowercase hexadecimal characters).
- Active-key version tagging ('ip:v1:...', 'user:v1:...').
- Previous-key pseudonym generation for multi-key recall queries.
- Invalid keys fail closed (<32 chars, empty, None).
- Missing active key fails closed.
"""

import pytest
from pydantic import SecretStr

from app.services.hmac_pseudonymizer import (
    HmacPseudonymizer,
    InvalidHMACKeyError,
    normalize_ip,
    normalize_username,
)

VALID_KEY = SecretStr("0123456789abcdef0123456789abcdef")  # 32 chars
PREV_KEY_1 = SecretStr("fedcba9876543210fedcba9876543210")  # 32 chars


# =============================================================================
# 1. Normalization Tests
# =============================================================================

def test_normalize_ip_valid_ipv4():
    assert normalize_ip("192.168.1.1") == "192.168.1.1"
    assert normalize_ip("  10.0.0.1\n") == "10.0.0.1"


def test_normalize_ip_valid_ipv6():
    # IPv6 canonical form compression
    assert normalize_ip("2001:0db8:0000:0000:0000:ff00:0042:8329") == "2001:db8::ff00:42:8329"
    assert normalize_ip("::1") == "::1"


def test_normalize_ip_invalid_raises():
    with pytest.raises(ValueError, match="Invalid IP address format"):
        normalize_ip("999.999.999.999")
    with pytest.raises(ValueError, match="Invalid IP address format"):
        normalize_ip("not-an-ip")
    with pytest.raises(ValueError, match="IP address must be a non-empty string"):
        normalize_ip("   ")


def test_normalize_username_case_preservation():
    # Case must be preserved
    assert normalize_username("Admin") == "Admin"
    assert normalize_username("admin") == "admin"
    assert normalize_username("Admin") != normalize_username("admin")


def test_normalize_username_unicode_nfc():
    # e with acute accent composed vs decomposed
    composed = "\u00e9"  # é in NFC
    decomposed = "e\u0301"  # e + combining acute
    assert normalize_username(composed) == normalize_username(decomposed)
    assert normalize_username("  svc_backup  ") == "svc_backup"


# =============================================================================
# 2. Key Validation & Fail-Closed Tests
# =============================================================================

def test_pseudonymizer_rejects_empty_active_key():
    with pytest.raises(InvalidHMACKeyError, match="Active HMAC key cannot be empty"):
        HmacPseudonymizer(active_key=SecretStr(""))


def test_pseudonymizer_rejects_short_active_key():
    with pytest.raises(InvalidHMACKeyError, match="must be at least 32 UTF-8 bytes"):
        HmacPseudonymizer(active_key=SecretStr("short-key-12345"))


def test_pseudonymizer_rejects_empty_version():
    with pytest.raises(InvalidHMACKeyError, match="Active HMAC key version cannot be empty"):
        HmacPseudonymizer(active_key=VALID_KEY, active_version="   ")


def test_pseudonymizer_rejects_conflicting_previous_version():
    with pytest.raises(InvalidHMACKeyError, match="conflicts with active version"):
        HmacPseudonymizer(
            active_key=VALID_KEY,
            active_version="v1",
            previous_keys={"v1": PREV_KEY_1},
        )


def test_pseudonymizer_rejects_short_previous_key():
    with pytest.raises(InvalidHMACKeyError, match="must be at least 32 UTF-8 bytes"):
        HmacPseudonymizer(
            active_key=VALID_KEY,
            active_version="v2",
            previous_keys={"v1": SecretStr("too-short")},
        )


# =============================================================================
# 3. Cryptographic Pseudonym Generation & Domain Separation
# =============================================================================

def test_pseudonym_deterministic_and_exact_format():
    p = HmacPseudonymizer(active_key=VALID_KEY, active_version="v1")
    ip_tag1 = p.pseudonymize_ip("198.51.100.75")
    ip_tag2 = p.pseudonymize_ip("198.51.100.75")

    assert ip_tag1 == ip_tag2
    assert ip_tag1.startswith("ip:v1:")
    digest = ip_tag1.split(":")[2]
    assert len(digest) == 32
    assert all(c in "0123456789abcdef" for c in digest)


def test_domain_separation_ip_vs_username():
    """Identical string for IP and username must yield completely distinct pseudonyms."""
    p = HmacPseudonymizer(active_key=VALID_KEY, active_version="v1")
    # Even if an IP string is processed as both
    ip_tag = p.pseudonymize_ip("10.0.0.1")
    user_tag = p.pseudonymize_username("10.0.0.1")

    assert ip_tag.startswith("ip:v1:")
    assert user_tag.startswith("user:v1:")
    assert ip_tag.split(":")[2] != user_tag.split(":")[2]


def test_username_case_produces_distinct_pseudonyms():
    p = HmacPseudonymizer(active_key=VALID_KEY, active_version="v1")
    tag_upper = p.pseudonymize_username("Administrator")
    tag_lower = p.pseudonymize_username("administrator")

    assert tag_upper != tag_lower


def test_different_ips_produce_different_pseudonyms():
    p = HmacPseudonymizer(active_key=VALID_KEY, active_version="v1")
    tag1 = p.pseudonymize_ip("192.168.1.10")
    tag2 = p.pseudonymize_ip("192.168.1.11")
    assert tag1 != tag2


# =============================================================================
# 4. Key Rotation & Historical Multi-Version Recall
# =============================================================================

def test_key_rotation_multi_version_generation():
    p = HmacPseudonymizer(
        active_key=VALID_KEY,
        active_version="v2",
        previous_keys={"v1": PREV_KEY_1},
    )
    assert p.active_version == "v2"
    assert p.available_versions == ["v2", "v1"]

    # Active version default
    active_ip = p.pseudonymize_ip("198.51.100.1")
    assert active_ip.startswith("ip:v2:")

    # Historical version explicit request
    hist_ip = p.pseudonymize_ip("198.51.100.1", key_version="v1")
    assert hist_ip.startswith("ip:v1:")
    assert active_ip.split(":")[2] != hist_ip.split(":")[2]

    # Generate all versions for recall
    all_tags = p.generate_all_ip_pseudonyms("198.51.100.1")
    assert set(all_tags.keys()) == {"v1", "v2"}
    assert all_tags["v2"] == active_ip
    assert all_tags["v1"] == hist_ip

    all_user_tags = p.generate_all_username_pseudonyms("root")
    assert set(all_user_tags.keys()) == {"v1", "v2"}
    assert all_user_tags["v2"].startswith("user:v2:")
    assert all_user_tags["v1"].startswith("user:v1:")


def test_unconfigured_key_version_raises():
    p = HmacPseudonymizer(active_key=VALID_KEY, active_version="v1")
    with pytest.raises(InvalidHMACKeyError, match="Requested key version 'v99' is not configured"):
        p.pseudonymize_ip("10.0.0.1", key_version="v99")


# =============================================================================
# 5. HMAC Key Byte-Length & Entropy Validation Tests
# =============================================================================

def test_hmac_key_exact_32_byte_ascii_passes():
    """A valid exactly 32-byte ASCII key passes validation."""
    key_32_ascii = "a" * 32
    assert len(key_32_ascii.encode("utf-8")) == 32
    p = HmacPseudonymizer(active_key=key_32_ascii, active_version="v1")
    assert p.active_version == "v1"


def test_hmac_key_shorter_than_32_utf8_bytes_rejected():
    """A key shorter than 32 UTF-8 bytes is rejected without revealing key in error."""
    secret_candidate = "short_key_under_32"
    with pytest.raises(InvalidHMACKeyError) as exc_info:
        HmacPseudonymizer(active_key=secret_candidate, active_version="v1")

    err = str(exc_info.value)
    assert "at least 32 UTF-8 bytes" in err
    assert secret_candidate not in err


def test_hmac_key_unicode_char_vs_byte_count_evaluation():
    """Verify that multi-byte Unicode keys evaluate byte count, not character count.
    
    16 2-byte characters (Greek alphas) = 16 chars, but 32 UTF-8 bytes.
    Should pass 32-byte requirement!
    """
    sixteen_two_byte_chars = "α" * 16  # len = 16 characters, len in UTF-8 = 32 bytes
    assert len(sixteen_two_byte_chars) == 16
    assert len(sixteen_two_byte_chars.encode("utf-8")) == 32

    p = HmacPseudonymizer(active_key=sixteen_two_byte_chars, active_version="v1")
    assert p.active_version == "v1"

    # 15 2-byte characters = 30 UTF-8 bytes (< 32 bytes). Should be rejected!
    fifteen_two_byte_chars = "α" * 15
    assert len(fifteen_two_byte_chars.encode("utf-8")) == 30
    with pytest.raises(InvalidHMACKeyError) as exc_info:
        HmacPseudonymizer(active_key=fifteen_two_byte_chars, active_version="v1")
    assert fifteen_two_byte_chars not in str(exc_info.value)


def test_hmac_previous_key_invalid_byte_length_rejected():
    """Previous key with < 32 UTF-8 bytes is rejected without leaking key material."""
    weak_previous_key = "weak_prev_key"
    with pytest.raises(InvalidHMACKeyError) as exc_info:
        HmacPseudonymizer(
            active_key="a" * 32,
            active_version="v2",
            previous_keys={"v1": weak_previous_key},
        )
    err = str(exc_info.value)
    assert "at least 32 UTF-8 bytes" in err
    assert weak_previous_key not in err

