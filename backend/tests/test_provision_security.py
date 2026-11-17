"""Automated tests for provision_db ACL permission parsing and URL credential encoding."""

import sys
from pathlib import Path
from sqlalchemy.engine import make_url

# Add project root to sys.path to import provision_db functions
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from scripts.provision_db import (
    build_database_url,
    parse_and_validate_icacls_permissions,
)


# ---------------------------------------------------------------------------
# ACL Validation Tests
# ---------------------------------------------------------------------------

def test_accepts_valid_exclusive_full_control():
    """Verify Full Control '(F)' for target user exclusively is accepted."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(F)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


def test_accepts_valid_exclusive_modify():
    """Verify Modify '(M)' for target user exclusively is accepted."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(M)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


def test_accepts_valid_exclusive_read_write():
    """Verify explicit Read AND Write '(R,W)' for target user exclusively is accepted."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(R,W)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


def test_accepts_valid_exclusive_read_write_delete():
    """Verify explicit Read, Write, Delete '(R,W,D)' for target user exclusively is accepted."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(R,W,D)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


def test_accepts_multiple_acl_entries_same_user_combining():
    """Verify multiple entries for the same user (e.g. R on one, W on another) combine into sufficient rights."""
    acl_output = (
        "D:\\path\\.env.tmp LAPTOP\\TestUser:(R)\n"
        "                  LAPTOP\\TestUser:(W,D)\n"
        "Successfully processed 1 files"
    )
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


def test_rejects_allow_followed_by_deny():
    """Verify Allow followed by DENY for target user causes validation failure."""
    acl_output = (
        "D:\\path\\.env.tmp LAPTOP\\TestUser:(R,W,D)\n"
        "                  LAPTOP\\TestUser:(DENY)(W)\n"
        "Successfully processed 1 files"
    )
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_deny_followed_by_allow():
    """Verify DENY followed by Allow for target user causes validation failure."""
    acl_output = (
        "D:\\path\\.env.tmp LAPTOP\\TestUser:(DENY)(R)\n"
        "                  LAPTOP\\TestUser:(F)\n"
        "Successfully processed 1 files"
    )
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_unexpected_additional_user():
    """Verify exclusivity requirement: presence of unexpected user causes validation failure."""
    acl_output = (
        "D:\\path\\.env.tmp LAPTOP\\TestUser:(R,W,D)\n"
        "                  Everyone:(R)\n"
        "Successfully processed 1 files"
    )
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_unexpected_builtin_users():
    """Verify unexpected BUILTIN\\Users or other group causes validation failure."""
    acl_output = (
        "D:\\path\\.env.tmp LAPTOP\\TestUser:(F)\n"
        "                  BUILTIN\\Users:(RX)\n"
        "Successfully processed 1 files"
    )
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_read_only():
    """Verify Read-Only '(R)' is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(R)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_read_and_execute():
    """Verify Read & Execute '(RX)' without Write is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(RX)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_write_only():
    """Verify Write-Only '(W)' without Read is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(W)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_delete_only():
    """Verify Delete-Only '(D)' without Read or Write is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(D)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_read_delete():
    """Verify Read and Delete '(R,D)' without Write is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(R,D)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_rejects_insufficient_write_delete():
    """Verify Write and Delete '(W,D)' without Read is strictly rejected."""
    acl_output = "D:\\path\\.env.tmp LAPTOP\\TestUser:(W,D)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is False


def test_handles_case_and_domain_prefix():
    """Verify domain prefix and case-insensitive matching work correctly."""
    acl_output = "D:\\path\\.env.tmp DOMAIN_CORP\\testuser:(R,W,D)\nSuccessfully processed 1 files"
    assert parse_and_validate_icacls_permissions(acl_output, "TestUser") is True


# ---------------------------------------------------------------------------
# Database Password URL Encoding Tests
# ---------------------------------------------------------------------------

def test_database_url_plain_password():
    """Verify standard alphanumeric password encoding."""
    url = build_database_url("sentinelagent_user", "Secr3tPass123")
    assert url == "postgresql+psycopg://sentinelagent_user:Secr3tPass123@localhost:5432/sentinelagent"
    parsed = make_url(url)
    assert parsed.password == "Secr3tPass123"


def test_database_url_password_with_spaces():
    """Verify password with spaces is encoded as %20 (not +)."""
    raw_pass = "my secret password with spaces"
    url = build_database_url("sentinelagent_user", raw_pass)
    assert "%20" in url
    assert "+" not in url.split("@")[0].split(":")[-1]  # Ensure space is %20 not '+'
    parsed = make_url(url)
    assert parsed.password == raw_pass


def test_database_url_reserved_url_characters():
    """Verify reserved characters (@, :, /, ?, #, [, ], %, &, =, etc.) are properly escaped."""
    raw_pass = "p@ss:w/o?r#d%[1]!$&*()+=,"
    url = build_database_url("sentinelagent_user", raw_pass)
    # Confirm none of the unencoded delimiter characters exist unescaped in the password part
    pw_part = url.split("sentinelagent_user:")[1].split("@localhost")[0]
    assert "@" not in pw_part
    assert ":" not in pw_part
    assert "/" not in pw_part
    assert "#" not in pw_part
    assert "?" not in pw_part
    parsed = make_url(url)
    assert parsed.password == raw_pass


def test_database_url_plus_and_encoded_literals():
    """Verify literal plus sign and percent symbols decode accurately without ambiguity."""
    raw_pass = "Complex+Pass%20_Literal#99"
    url = build_database_url("sentinelagent_user", raw_pass)
    parsed = make_url(url)
    assert parsed.password == raw_pass
