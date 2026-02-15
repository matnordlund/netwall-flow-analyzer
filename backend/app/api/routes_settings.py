"""Settings, maintenance (cleanup), and DB stats endpoints."""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from ..storage.models import Event, IngestJob, RawLog
from ..storage.settings import get_all_settings, get_setting, set_setting

logger = logging.getLogger("netwall.settings")

router = APIRouter(tags=["settings"])

CLEANUP_BATCH_SIZE = 10_000
VACUUM_ROW_THRESHOLD = 50_000


# ── helpers ──

def _get_db(request: Request) -> Session:
    return request.app.state.db_sessionmaker()


def _is_sqlite(request: Request) -> bool:
    url = str(request.app.state.db_engine.url)
    return "sqlite" in url.lower()


def _sqlite_path(request: Request) -> Optional[str]:
    url = str(request.app.state.db_engine.url)
    if "sqlite" not in url.lower():
        return None
    # e.g. sqlite:///path/to/db.sqlite or sqlite+pysqlite:///path
    path = url.split("///")[-1] if "///" in url else None
    if path and os.path.isfile(path):
        return path
    return None


# ── GET /api/settings ──

@router.get("/settings")
def get_settings(request: Request) -> Dict[str, Any]:
    db = _get_db(request)
    try:
        return get_all_settings(db)
    finally:
        db.close()


# ── PUT /api/settings/log-retention ──

class LogRetentionPayload(BaseModel):
    enabled: bool
    keep_days: int = Field(ge=1, le=365)


@router.put("/settings/log-retention")
def update_log_retention(request: Request, payload: LogRetentionPayload) -> Dict[str, Any]:
    db = _get_db(request)
    try:
        value = {"enabled": payload.enabled, "keep_days": payload.keep_days}
        set_setting(db, "log_retention", value)
        db.commit()
        return {"ok": True, "log_retention": value}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── GET/PUT /api/settings/local-networks ──

class LocalNetworksPayload(BaseModel):
    enabled: bool
    cidrs: List[str]

    @field_validator("cidrs", mode="before")
    @classmethod
    def validate_cidrs(cls, v: Any) -> List[str]:
        if not isinstance(v, list):
            raise ValueError("cidrs must be a list")
        normalized: List[str] = []
        for raw in v:
            if not isinstance(raw, str):
                raise ValueError(f"Each CIDR must be a string, got {type(raw).__name__}")
            try:
                net = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR '{raw}': {exc}") from exc
            normalized.append(str(net))
        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped: List[str] = []
        for c in normalized:
            if c not in seen:
                seen.add(c)
                deduped.append(c)
        return deduped


@router.get("/settings/local-networks")
def get_local_networks(request: Request) -> Dict[str, Any]:
    db = _get_db(request)
    try:
        val = get_setting(db, "local_networks")
        return val  # type: ignore[return-value]
    finally:
        db.close()


@router.put("/settings/local-networks")
def update_local_networks(request: Request, payload: LocalNetworksPayload) -> Dict[str, Any]:
    db = _get_db(request)
    try:
        value = {"enabled": payload.enabled, "cidrs": payload.cidrs}
        set_setting(db, "local_networks", value)
        db.commit()
        return {"ok": True, "local_networks": value}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Cleanup logic (shared by scheduled job and manual trigger) ──

def run_cleanup(session_factory, engine) -> Dict[str, Any]:
    """Execute one cleanup pass. Only deletes data for firewalls with source_syslog=1 (retention excluded for import-only)."""
    from ..storage.firewall_source import expand_device_keys_to_member_devices, get_syslog_only_device_keys_for_retention

    t0 = time.monotonic()
    db: Session = session_factory()
    try:
        retention = get_setting(db, "log_retention")
        if not retention or not retention.get("enabled"):
            return {"skipped": True, "reason": "retention disabled"}

        keep_days = int(retention.get("keep_days", 3))
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

        # SQLite: skip cleanup when an ingest job is running to avoid lock contention
        if db.execute(select(IngestJob.id).where(IngestJob.status.in_(["queued", "running"])).limit(1)).first():
            return {"skipped": True, "reason": "ingest job in progress", "cutoff": cutoff.isoformat()}

        # Only purge data for firewalls that are syslog-only (never imported); imported firewalls are retention-exempt
        syslog_only_keys = get_syslog_only_device_keys_for_retention(db)
        allowed_devices = expand_device_keys_to_member_devices(db, syslog_only_keys)
        if not allowed_devices:
            return {"skipped": True, "reason": "no syslog-only firewalls (imported firewalls are excluded)", "cutoff": cutoff.isoformat()}

        deleted_events = 0
        deleted_raw_logs = 0

        # Delete only events for allowed (syslog) devices
        while True:
            sub = (
                select(Event.id)
                .where(Event.device.in_(allowed_devices))
                .where(Event.ts_utc < cutoff)
                .limit(CLEANUP_BATCH_SIZE)
            )
            result = db.execute(delete(Event).where(Event.id.in_(sub)))
            batch = result.rowcount
            db.commit()
            deleted_events += batch
            if batch < CLEANUP_BATCH_SIZE:
                break

        # Delete only raw_logs for allowed (syslog) devices
        while True:
            sub = (
                select(RawLog.id)
                .where(RawLog.device.in_(allowed_devices))
                .where(RawLog.ts_utc < cutoff)
                .limit(CLEANUP_BATCH_SIZE)
            )
            result = db.execute(delete(RawLog).where(RawLog.id.in_(sub)))
            batch = result.rowcount
            db.commit()
            deleted_raw_logs += batch
            if batch < CLEANUP_BATCH_SIZE:
                break

        total_deleted = deleted_events + deleted_raw_logs

        # VACUUM for SQLite only, when enough rows deleted
        vacuum_ran = False
        db_url = str(engine.url).lower()
        if "sqlite" in db_url and total_deleted >= VACUUM_ROW_THRESHOLD:
            try:
                with engine.connect() as conn:
                    conn.execute(text("VACUUM"))
                    conn.commit()
                vacuum_ran = True
            except Exception as exc:
                logger.warning("VACUUM failed: %s", exc)

        duration_ms = int((time.monotonic() - t0) * 1000)
        summary = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            "duration_ms": duration_ms,
            "deleted_events": deleted_events,
            "deleted_raw_logs": deleted_raw_logs,
            "vacuum_ran": vacuum_ran,
            "keep_days": keep_days,
            "cutoff": cutoff.isoformat(),
        }

        # Persist summary
        set_setting(db, "maintenance_last_cleanup", summary)
        db.commit()

        logger.info(
            "Cleanup done: %d events, %d raw_logs deleted (cutoff %s, %dms, vacuum=%s)",
            deleted_events, deleted_raw_logs, cutoff.isoformat(), duration_ms, vacuum_ran,
        )
        return summary
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── POST /api/maintenance/cleanup (manual trigger) ──

@router.post("/maintenance/cleanup")
def manual_cleanup(request: Request) -> Dict[str, Any]:
    session_factory = request.app.state.db_sessionmaker
    engine = request.app.state.db_engine
    return run_cleanup(session_factory, engine)


# ── GET /api/stats/db ──

@router.get("/stats/db")
def get_db_stats(request: Request) -> Dict[str, Any]:
    db = _get_db(request)
    try:
        events_count = db.execute(select(func.count(Event.id))).scalar() or 0
        raw_logs_count = db.execute(select(func.count(RawLog.id))).scalar() or 0

        oldest_event_ts = db.execute(select(func.min(Event.ts_utc))).scalar()
        newest_event_ts = db.execute(select(func.max(Event.ts_utc))).scalar()
        oldest_raw_ts = db.execute(select(func.min(RawLog.ts_utc))).scalar()
        newest_raw_ts = db.execute(select(func.max(RawLog.ts_utc))).scalar()

        def _iso(dt):
            return dt.isoformat() if dt else None

        is_sqlite = "sqlite" in str(request.app.state.db_engine.url).lower()
        db_type = "sqlite" if is_sqlite else "postgres"

        db_file_size_bytes = None
        if is_sqlite:
            path = _sqlite_path(request)
            if path:
                try:
                    db_file_size_bytes = os.path.getsize(path)
                except OSError:
                    pass

        last_cleanup = get_setting(db, "maintenance_last_cleanup")

        return {
            "db_type": db_type,
            "raw_logs_count": raw_logs_count,
            "events_count": events_count,
            "oldest_event_ts": _iso(oldest_event_ts),
            "newest_event_ts": _iso(newest_event_ts),
            "oldest_raw_received_at": _iso(oldest_raw_ts),
            "newest_raw_received_at": _iso(newest_raw_ts),
            "db_file_size_bytes": db_file_size_bytes,
            "last_cleanup": last_cleanup,
        }
    finally:
        db.close()
