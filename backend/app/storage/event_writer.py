"""EventWriter abstraction for batched ingest writes. Isolates DB-specific SQL and PRAGMAs for future PostgreSQL support."""

from __future__ import annotations

from typing import Any, List, Protocol

from sqlalchemy.orm import Session
from sqlalchemy import text

from .models import RawLog, Event


class EventWriter(Protocol):
    """Interface for batched raw_log and event inserts. Implementations handle DB-specific SQL and tuning."""

    def configure_ingest_mode(self, session: Session) -> None:
        """Apply connection-level settings for fast ingest (e.g. SQLite PRAGMAs). Call once per connection/session."""
        ...

    def insert_raw_logs(self, session: Session, batch: List[dict[str, Any]]) -> None:
        """Bulk insert raw_log rows. Each dict has keys matching RawLog columns (omit id)."""
        ...

    def insert_events(self, session: Session, batch: List[dict[str, Any]]) -> None:
        """Bulk insert event rows. Each dict has keys matching Event columns (omit id)."""
        ...

    def commit_batch(self, session: Session) -> None:
        """Commit the current batch (after insert_raw_logs and insert_events)."""
        ...


class SQLiteEventWriter:
    """SQLite implementation: PRAGMAs for WAL/speed (SQLite only), bulk_insert_mappings for raw_logs and events."""

    def configure_ingest_mode(self, session: Session) -> None:
        """Set connection-level settings for fast ingest. SQLite only: WAL and related PRAGMAs; no-op for Postgres."""
        dialect = session.get_bind().dialect.name
        if dialect != "sqlite":
            return
        session.execute(text("PRAGMA journal_mode=WAL"))
        session.execute(text("PRAGMA synchronous=NORMAL"))
        session.execute(text("PRAGMA busy_timeout=10000"))
        session.execute(text("PRAGMA temp_store=MEMORY"))
        session.execute(text("PRAGMA cache_size=-200000"))  # ~200 MB
        session.execute(text("PRAGMA wal_autocheckpoint=2000"))

    def insert_raw_logs(self, session: Session, batch: List[dict[str, Any]]) -> None:
        if not batch:
            return
        session.bulk_insert_mappings(RawLog, batch)

    def insert_events(self, session: Session, batch: List[dict[str, Any]]) -> None:
        if not batch:
            return
        session.bulk_insert_mappings(Event, batch)

    def commit_batch(self, session: Session) -> None:
        session.commit()
