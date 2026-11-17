"""Tests for SSH Event SQLAlchemy model, constraints, indexes, and migrations."""

import uuid
from datetime import datetime, timezone
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import delete, inspect, select, text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db import connection
from app.db.base import Base
from app.models.ssh_event import SSHEvent


# ---------------------------------------------------------------------------
# Unit Tests: Model Metadata & Declarative Definition
# ---------------------------------------------------------------------------

def test_ssh_event_table_name():
    """Verify table name is ssh_events."""
    assert SSHEvent.__tablename__ == "ssh_events"


def test_ssh_event_columns_definition():
    """Verify all required columns exist with proper types and nullability."""
    table = SSHEvent.__table__
    columns = table.columns

    # Check existence
    expected_cols = {
        "event_id",
        "event_timestamp",
        "source_ip",
        "username",
        "authentication_result",
        "event_type",
        "ingested_at",
    }
    assert expected_cols.issubset(set(columns.keys()))

    # Column: event_id
    col_id = columns["event_id"]
    assert col_id.primary_key is True
    assert col_id.nullable is False
    assert isinstance(col_id.type, UUID)

    # Column: event_timestamp
    col_ts = columns["event_timestamp"]
    assert col_ts.nullable is False
    assert col_ts.type.timezone is True

    # Column: source_ip
    col_ip = columns["source_ip"]
    assert col_ip.nullable is False
    assert isinstance(col_ip.type, INET)

    # Column: username
    col_user = columns["username"]
    assert col_user.nullable is False
    assert col_user.type.length == 128

    # Column: authentication_result
    col_auth = columns["authentication_result"]
    assert col_auth.nullable is False
    assert col_auth.type.length == 16

    # Column: event_type
    col_type = columns["event_type"]
    assert col_type.nullable is False
    assert col_type.type.length == 32

    # Column: ingested_at
    col_ingest = columns["ingested_at"]
    assert col_ingest.nullable is False
    assert col_ingest.type.timezone is True
    assert col_ingest.server_default is not None


def test_ssh_event_constraints_definition():
    """Verify primary key and check constraint names and definitions."""
    table = SSHEvent.__table__
    constraint_names = {c.name for c in table.constraints}

    assert "pk_ssh_events" in constraint_names
    assert "ck_ssh_events_auth_result" in constraint_names
    assert "ck_ssh_events_username_not_empty" in constraint_names

    check_constraints = [c for c in table.constraints if c.__class__.__name__ == "CheckConstraint"]
    ck_dict = {c.name: str(c.sqltext) for c in check_constraints}

    assert "authentication_result IN ('success', 'failure')" in ck_dict["ck_ssh_events_auth_result"]
    assert "length(username) > 0" in ck_dict["ck_ssh_events_username_not_empty"]


def test_ssh_event_indexes_definition():
    """Verify explicitly named indexes and their column lists."""
    table = SSHEvent.__table__
    index_dict = {idx.name: [c.name for c in idx.columns] for idx in table.indexes}

    assert "ix_ssh_events_event_timestamp" in index_dict
    assert index_dict["ix_ssh_events_event_timestamp"] == ["event_timestamp"]

    assert "ix_ssh_events_source_ip" in index_dict
    assert index_dict["ix_ssh_events_source_ip"] == ["source_ip"]

    assert "ix_ssh_events_source_ip_event_timestamp" in index_dict
    assert index_dict["ix_ssh_events_source_ip_event_timestamp"] == ["source_ip", "event_timestamp"]


def test_ssh_event_repr():
    """Verify model string representation formatting."""
    uid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    event = SSHEvent(
        event_id=uid,
        event_timestamp=now,
        source_ip="192.168.1.100",
        username="admin",
        authentication_result="failure",
        event_type="ssh_login",
    )
    rep = repr(event)
    assert "SSHEvent" in rep
    assert str(uid) in rep
    assert "192.168.1.100" in rep
    assert "admin" in rep
    assert "failure" in rep


# ---------------------------------------------------------------------------
# Migration & Schema Inspection Tests (Live PostgreSQL)
# ---------------------------------------------------------------------------

@pytest.fixture
def db_engine():
    """Provides a live database engine."""
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def db_session(db_engine):
    """Provides an isolated database session with post-test rollback."""
    SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def cleanup_events(db_engine):
    """Tracks inserted event UUIDs and removes them after test execution."""
    created_ids = []
    yield created_ids
    if created_ids:
        with db_engine.begin() as conn:
            conn.execute(
                delete(SSHEvent).where(SSHEvent.event_id.in_(created_ids))
            )


def test_alembic_current_revision_matches_head(db_engine):
    """Verify that the database migration state is upgraded to the latest revision."""
    with db_engine.connect() as conn:
        current_rev = conn.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()

    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    head_rev = script.get_current_head()

    assert current_rev is not None
    assert current_rev == head_rev


def test_postgres_schema_inspection(db_engine):
    """Verify table, columns, constraints, and indexes in PostgreSQL catalogs."""
    insp = inspect(db_engine)
    table_names = insp.get_table_names()
    assert "ssh_events" in table_names
    assert "alembic_version" in table_names

    # Verify column existence and types from PostgreSQL
    columns = {col["name"]: col for col in insp.get_columns("ssh_events")}
    assert "event_id" in columns
    assert "event_timestamp" in columns
    assert "source_ip" in columns
    assert "username" in columns
    assert "authentication_result" in columns
    assert "event_type" in columns
    assert "ingested_at" in columns

    # Verify check constraints in PostgreSQL
    check_constraints = {ck["name"] for ck in insp.get_check_constraints("ssh_events")}
    assert "ck_ssh_events_auth_result" in check_constraints
    assert "ck_ssh_events_username_not_empty" in check_constraints

    # Verify indexes in PostgreSQL
    indexes = {idx["name"] for idx in insp.get_indexes("ssh_events")}
    assert "ix_ssh_events_event_timestamp" in indexes
    assert "ix_ssh_events_source_ip" in indexes
    assert "ix_ssh_events_source_ip_event_timestamp" in indexes


# ---------------------------------------------------------------------------
# Integration Tests: Insert, Retrieve, and Constraint Validation
# ---------------------------------------------------------------------------

def test_db_insert_and_retrieve_success(db_session, cleanup_events):
    """Successfully insert and retrieve a valid SSH event."""
    test_id = uuid.uuid4()
    cleanup_events.append(test_id)
    now = datetime.now(timezone.utc)

    event = SSHEvent(
        event_id=test_id,
        event_timestamp=now,
        source_ip="10.0.0.50",
        username="secops_user",
        authentication_result="success",
        event_type="password",
    )
    db_session.add(event)
    db_session.commit()

    retrieved = db_session.get(SSHEvent, test_id)
    assert retrieved is not None
    assert retrieved.event_id == test_id
    assert retrieved.source_ip == "10.0.0.50"
    assert retrieved.username == "secops_user"
    assert retrieved.authentication_result == "success"
    assert retrieved.event_type == "password"
    assert retrieved.ingested_at is not None


def test_db_default_uuid_and_server_default_ingested_at(db_session, cleanup_events):
    """Verify that event_id and ingested_at are automatically generated when omitted."""
    now = datetime.now(timezone.utc)
    event = SSHEvent(
        event_timestamp=now,
        source_ip="172.16.0.5",
        username="dev_user",
        authentication_result="failure",
        event_type="publickey",
    )
    db_session.add(event)
    db_session.commit()

    assert event.event_id is not None
    cleanup_events.append(event.event_id)

    db_session.refresh(event)
    assert event.ingested_at is not None
    assert isinstance(event.event_id, uuid.UUID)


def test_db_check_constraint_auth_result_rejected(db_session):
    """Verify that invalid authentication_result violates check constraint."""
    invalid_event = SSHEvent(
        event_id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.50",
        username="attacker",
        authentication_result="unknown_status",
        event_type="password",
    )
    db_session.add(invalid_event)
    with pytest.raises(IntegrityError) as exc_info:
        db_session.commit()

    db_session.rollback()
    assert "ck_ssh_events_auth_result" in str(exc_info.value).lower()


def test_db_check_constraint_empty_username_rejected(db_session):
    """Verify that an empty username string violates check constraint."""
    empty_user_event = SSHEvent(
        event_id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.50",
        username="",
        authentication_result="failure",
        event_type="password",
    )
    db_session.add(empty_user_event)
    with pytest.raises(IntegrityError) as exc_info:
        db_session.commit()

    db_session.rollback()
    assert "ck_ssh_events_username_not_empty" in str(exc_info.value).lower()


def test_db_non_nullable_fields_enforced(db_session):
    """Verify that omitting non-nullable fields is rejected."""
    bad_event = SSHEvent(
        event_id=uuid.uuid4(),
        # Missing event_timestamp
        source_ip="10.0.0.1",
        username="user1",
        authentication_result="success",
        event_type="password",
    )
    db_session.add(bad_event)
    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_db_duplicate_primary_key_rejected(db_engine, cleanup_events):
    """Verify that duplicate primary keys violate primary key constraint in PostgreSQL."""
    duplicate_id = uuid.uuid4()
    cleanup_events.append(duplicate_id)
    now = datetime.now(timezone.utc)

    SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False)
    session1 = SessionLocal()
    session2 = SessionLocal()

    try:
        event1 = SSHEvent(
            event_id=duplicate_id,
            event_timestamp=now,
            source_ip="10.0.0.1",
            username="user1",
            authentication_result="success",
            event_type="password",
        )
        session1.add(event1)
        session1.commit()

        event2 = SSHEvent(
            event_id=duplicate_id,
            event_timestamp=now,
            source_ip="10.0.0.2",
            username="user2",
            authentication_result="failure",
            event_type="password",
        )
        session2.add(event2)
        with pytest.raises(IntegrityError) as exc_info:
            session2.commit()

        session2.rollback()
        assert "pk_ssh_events" in str(exc_info.value).lower() or "unique" in str(exc_info.value).lower()
    finally:
        session1.close()
        session2.close()
