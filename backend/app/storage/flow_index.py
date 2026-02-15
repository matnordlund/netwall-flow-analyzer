"""Ensure flows table has unique index for upsert (ON CONFLICT). Required for existing DBs where create_all() did not add the constraint."""

from __future__ import annotations

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)

UX_FLOWS_IDENTITY_COLS = (
    "device",
    "basis",
    "from_value",
    "to_value",
    "proto",
    "dest_port",
    "src_endpoint_id",
    "dst_endpoint_id",
    "view_kind",
)


def ensure_flows_unique_index(engine) -> bool:
    """Create unique index ux_flows_identity on flows if missing (SQLite only). Returns True if index exists or was created."""
    if engine.dialect.name != "sqlite":
        return True
    identity_list = ", ".join(UX_FLOWS_IDENTITY_COLS)
    sql = f"CREATE UNIQUE INDEX IF NOT EXISTS ux_flows_identity ON flows ({identity_list})"
    try:
        with engine.connect() as conn:
            conn.execute(text(sql))
            conn.commit()
        logger.info("Flows unique index ux_flows_identity ensured.")
        return True
    except Exception as e:  # noqa: BLE001
        # Duplicate rows in table prevent creating the unique index
        logger.warning(
            "Could not create flows unique index (duplicates may exist): %s. Run: python -m scripts.dedup_flows_and_add_unique_index",
            e,
        )
        return False


def ensure_ingest_job_error_columns(engine) -> None:
    """Add error_type and error_stage columns to ingest_jobs if missing (SQLite only). Idempotent."""
    if engine.dialect.name != "sqlite":
        return
    for col, typ in [("error_type", "VARCHAR(128)"), ("error_stage", "VARCHAR(64)")]:
        try:
            with engine.connect() as conn:
                conn.execute(text(f"ALTER TABLE ingest_jobs ADD COLUMN {col} {typ}"))
                conn.commit()
            logger.info("Added ingest_jobs.%s", col)
        except Exception as e:  # noqa: BLE001
            if "duplicate column name" in str(e).lower():
                pass
            else:
                logger.warning("Could not add ingest_jobs.%s: %s", col, e)


def ensure_ingest_job_finished_at(engine) -> None:
    """Add finished_at column to ingest_jobs if missing (SQLite only). Idempotent."""
    if engine.dialect.name != "sqlite":
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE ingest_jobs ADD COLUMN finished_at DATETIME"))
            conn.commit()
        logger.info("Added ingest_jobs.finished_at")
    except Exception as e:  # noqa: BLE001
        if "duplicate column name" in str(e).lower():
            pass
        else:
            logger.warning("Could not add ingest_jobs.finished_at: %s", e)


def ensure_event_ha_columns(engine) -> None:
    """Add device_member, firewall_key, ingest_source to events if missing. Idempotent."""
    for col, typ in [
        ("device_member", "VARCHAR(255)"),
        ("firewall_key", "VARCHAR(255)"),
        ("ingest_source", "VARCHAR(32)"),
    ]:
        try:
            with engine.connect() as conn:
                if engine.dialect.name == "sqlite":
                    conn.execute(text(f"ALTER TABLE events ADD COLUMN {col} {typ}"))
                else:
                    conn.execute(text(f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {col} {typ}"))
                conn.commit()
            logger.info("Added events.%s", col)
        except Exception as e:  # noqa: BLE001
            if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                pass
            else:
                logger.warning("Could not add events.%s: %s", col, e)


def ensure_firewall_source_type(engine) -> None:
    """Add source_type to firewalls if missing. Idempotent."""
    try:
        with engine.connect() as conn:
            if engine.dialect.name == "sqlite":
                conn.execute(text("ALTER TABLE firewalls ADD COLUMN source_type VARCHAR(32)"))
            else:
                conn.execute(text("ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS source_type VARCHAR(32)"))
            conn.commit()
        logger.info("Added firewalls.source_type")
    except Exception as e:  # noqa: BLE001
        if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
            pass
        else:
            logger.warning("Could not add firewalls.source_type: %s", e)


def ensure_ingest_job_phase(engine) -> None:
    """Add phase column to ingest_jobs if missing (SQLite only). Idempotent."""
    if engine.dialect.name != "sqlite":
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE ingest_jobs ADD COLUMN phase VARCHAR(32)"))
            conn.commit()
        logger.info("Added ingest_jobs.phase")
    except Exception as e:  # noqa: BLE001
        if "duplicate column name" in str(e).lower():
            pass
        else:
            logger.warning("Could not add ingest_jobs.phase: %s", e)


def ensure_ingest_job_worker_columns(engine) -> None:
    """Add started_at, cancel_requested, device_key to ingest_jobs if missing (SQLite only). Idempotent."""
    if engine.dialect.name != "sqlite":
        return
    for col, typ in [
        ("started_at", "DATETIME"),
        ("cancel_requested", "BOOLEAN"),
        ("device_key", "VARCHAR(255)"),
    ]:
        try:
            with engine.connect() as conn:
                conn.execute(text(f"ALTER TABLE ingest_jobs ADD COLUMN {col} {typ}"))
                conn.commit()
            logger.info("Added ingest_jobs.%s", col)
        except Exception as e:  # noqa: BLE001
            if "duplicate column name" in str(e).lower():
                pass
            else:
                logger.warning("Could not add ingest_jobs.%s: %s", col, e)
