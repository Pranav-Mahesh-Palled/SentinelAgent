"""Pydantic schemas for SSH authentication events ingestion and responses."""

from datetime import datetime
import ipaddress
from typing import Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SSHEventCreate(BaseModel):
    """Schema for incoming single SSH event ingestion requests.

    Does not accept ingested_at from external callers; PostgreSQL generates it.
    Strictly enforces schema constraints.
    """

    event_id: uuid.UUID = Field(
        ...,
        description="Unique RFC 4122 event identifier",
    )
    event_timestamp: datetime = Field(
        ...,
        description="Timezone-aware timestamp of the SSH event",
    )
    source_ip: str = Field(
        ...,
        description="Valid IPv4 or IPv6 client address",
    )
    username: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Target username for the authentication attempt",
    )
    authentication_result: Literal["success", "failure"] = Field(
        ...,
        description="Authentication outcome ('success' or 'failure')",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Authentication method or event type",
    )

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "event_id": "1a3d1fa7-bc89-40a9-a3b8-c1e9392456de",
                "event_timestamp": "2026-11-08T10:00:00Z",
                "source_ip": "192.0.2.100",
                "username": "secops_admin",
                "authentication_result": "success",
                "event_type": "password",
            }
        },
    )

    @field_validator("event_timestamp")
    @classmethod
    def validate_timezone_aware(cls, v: datetime) -> datetime:
        """Validate that the event timestamp is timezone-aware."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("event_timestamp must be timezone-aware (tzinfo cannot be None)")
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        """Validate that source_ip is a valid IPv4 or IPv6 address string."""
        try:
            addr = ipaddress.ip_address(v)
            return str(addr)
        except ValueError as err:
            raise ValueError(f"source_ip must be a valid IPv4 or IPv6 address: '{v}'") from err


class SSHEventBatchCreate(BaseModel):
    """Schema for batch SSH event ingestion requests."""

    events: list[SSHEventCreate] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of SSH events to ingest (1 to 500 events)",
    )

    model_config = ConfigDict(extra="forbid")


class SSHEventIngestResponse(BaseModel):
    """Response schema for single SSH event ingestion."""

    event_id: uuid.UUID
    status: str = "created"
    message: str = "Event ingested successfully"


class SSHEventBatchResponse(BaseModel):
    """Response schema for batch SSH event ingestion."""

    accepted_count: int
    event_ids: list[uuid.UUID]
    status: str = "created"
    message: str = "Batch ingested successfully"

