"""make_started_at_nullable_in_investigations_and_tool_runs

Revision ID: 73ce52b4ca79
Revises: 8a70914c5c3e
Create Date: 2026-11-08 13:05:27.489152

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '73ce52b4ca79'
down_revision: Union[str, Sequence[str], None] = '8a70914c5c3e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        'investigation_tool_runs',
        'started_at',
        existing_type=postgresql.TIMESTAMP(timezone=True),
        nullable=True,
        server_default=None,
    )
    op.alter_column(
        'investigations',
        'started_at',
        existing_type=postgresql.TIMESTAMP(timezone=True),
        nullable=True,
        server_default=None,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        'investigations',
        'started_at',
        existing_type=postgresql.TIMESTAMP(timezone=True),
        nullable=False,
        server_default=sa.text('now()'),
    )
    op.alter_column(
        'investigation_tool_runs',
        'started_at',
        existing_type=postgresql.TIMESTAMP(timezone=True),
        nullable=False,
        server_default=sa.text('now()'),
    )
