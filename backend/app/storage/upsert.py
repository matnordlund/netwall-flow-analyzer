"""Idempotent upserts (Core, ON CONFLICT) to avoid UniqueViolation and flush. No schema migrations."""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .models import Endpoint

_ENDPOINT_UQ = ["device", "ip", "mac"]


def upsert_endpoint_safe(
    session: Session,
    device: str,
    ip: str,
    mac: Optional[str],
    device_name: Optional[str] = None,
) -> None:
    """Insert endpoint with ON CONFLICT DO NOTHING. Idempotent; safe for concurrent batches and HA.
    Does not flush. Caller should SELECT to get the row id if needed.
    """
    table = Endpoint.__table__
    dialect = session.get_bind().dialect.name
    values: dict[str, Any] = {
        "device": device,
        "ip": ip,
        "mac": mac,
        "device_name": device_name,
    }
    if dialect == "postgresql":
        stmt = pg_insert(table).values(**values).on_conflict_do_nothing(
            index_elements=_ENDPOINT_UQ
        )
    else:
        stmt = sqlite_insert(table).values(**values).on_conflict_do_nothing(
            index_elements=_ENDPOINT_UQ
        )
    session.execute(stmt)
