"""Firewall inventory: list firewalls with log stats, overrides, and purge."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..api.device_resolve import resolve_device
from ..api.routes_ingest import _device_key_from_detected, _phase_from_status, _progress_from_job
from ..storage.models import (
    Classification,
    DeviceIdentification,
    DeviceOverride,
    Endpoint,
    Event,
    FirewallInventory,
    FirewallOverride,
    Flow,
    HaCluster,
    IngestJob,
    MaintenanceJob,
    RawLog,
    RouterMac,
    UnclassifiedEndpoint,
)

router = APIRouter(tags=["firewalls"])
logger = logging.getLogger(__name__)

HA_MASTER_SUFFIX = "_Master"
HA_SLAVE_SUFFIX = "_Slave"


def get_db(request: Request) -> Session:
    return request.app.state.db_sessionmaker()


def _normalize_single_column_strings(rows: list) -> List[str]:
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, (list, tuple)):
            r = row[0] if row else None
        elif hasattr(row, "__getitem__") and not isinstance(row, str):
            r = row[0]
        else:
            r = row
        if r is None:
            continue
        s = str(r).strip()
        if not s:
            continue
        seen.add(s)
    return sorted(seen)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@router.get("/firewalls", response_model=List[Dict[str, Any]])
def list_firewalls(request: Request):
    """List all known firewalls (standalone + enabled HA clusters) with oldest/latest log and event count."""
    db: Session = get_db(request)
    try:
        # Same base set as list_device_groups: devices from events + enabled HA
        stmt = select(Event.device).where(Event.device.isnot(None)).distinct()
        raw_devices = _normalize_single_column_strings(db.execute(stmt).scalars().all())
        enabled_clusters: List[HaCluster] = db.execute(
            select(HaCluster).where(HaCluster.is_enabled.is_(True))
        ).scalars().all()
        enabled_bases = {c.base for c in enabled_clusters}

        # (device_key, display_name_default, members_list)
        firewall_rows: List[tuple] = []
        for d in raw_devices:
            if not d:
                continue
            if d.endswith(HA_MASTER_SUFFIX):
                base = d[: -len(HA_MASTER_SUFFIX)]
                if base in enabled_bases:
                    continue
            if d.endswith(HA_SLAVE_SUFFIX):
                base = d[: -len(HA_SLAVE_SUFFIX)]
                if base in enabled_bases:
                    continue
            firewall_rows.append((d, d, [d]))

        for c in enabled_clusters:
            members = list(c.members) if isinstance(c.members, list) else []
            default_label = c.label or f"{c.base} (HA)"
            # Use ha:base as device_key so it matches dropdown and purge
            firewall_rows.append((f"ha:{c.base}", default_label, members))

        # Load overrides by device_key (support both ha:base and base for HA for backwards compat)
        overrides_map: Dict[str, FirewallOverride] = {}
        for o in db.execute(select(FirewallOverride)).scalars().all():
            overrides_map[o.device_key] = o

        # Load firewall source (syslog/import) by device_key
        inventory_map: Dict[str, FirewallInventory] = {}
        for inv in db.execute(select(FirewallInventory)).scalars().all():
            inventory_map[inv.device_key] = inv

        # Active import jobs: group by device_key (jobs with no device_key yet are "pending")
        active_jobs = db.execute(
            select(IngestJob).where(
                IngestJob.status.in_(["queued", "uploading", "running"])
            ).order_by(IngestJob.created_at.desc())
        ).scalars().all()
        device_to_jobs: Dict[str, List[Dict[str, Any]]] = {}
        pending_import_jobs: List[Dict[str, Any]] = []
        for job in active_jobs:
            summary = {
                "job_id": job.id,
                "filename": job.filename,
                "status": job.status,
                "phase": _phase_from_status(job.status),
                "progress": round(_progress_from_job(job), 4),
                "lines_processed": job.lines_processed,
                "lines_total": job.lines_total,
                "created_at": _iso(job.created_at),
            }
            dk = getattr(job, "device_key", None) or (
                _device_key_from_detected(job.device_detected) if job.device_detected else None
            )
            if dk:
                device_to_jobs.setdefault(dk, []).append(summary)
            else:
                pending_import_jobs.append(summary)

        # Stats per device_key: for single device_key is the device; for HA we need to query by members
        result: List[Dict[str, Any]] = []
        for device_key, default_label, members in firewall_rows:
            display_name = default_label
            override = overrides_map.get(device_key)
            if not override and device_key.startswith("ha:") and len(device_key) > 3:
                override = overrides_map.get(device_key[3:])  # legacy key by base
            if override:
                display_name = (override.display_name or "").strip() or default_label

            # Query events: single device or HA members (for ha:base use members list)
            devices_to_query = members if members else [device_key]
            stmt = (
                select(
                    func.min(Event.ts_utc).label("oldest"),
                    func.max(Event.ts_utc).label("latest"),
                    func.count(Event.id).label("event_count"),
                )
                .where(Event.device.in_(devices_to_query))
            )
            row = db.execute(stmt).one_or_none()
            oldest_log = row.oldest if row else None
            latest_log = row.latest if row else None
            event_count = row.event_count if row else 0

            inv = inventory_map.get(device_key)
            source_syslog = bool(inv and inv.source_syslog)
            source_import = bool(inv and inv.source_import)
            last_import_ts = _iso(inv.last_import_ts) if inv and inv.last_import_ts else None
            # Pills for UI: import wins — if ever imported, show only IMPORT (never SYSLOG)
            if source_import:
                source_display = ["IMPORT"]
            elif source_syslog:
                source_display = ["SYSLOG"]
            else:
                source_display = ["—"]

            active_jobs_for_device = device_to_jobs.get(device_key, [])
            result.append({
                "device_key": device_key,
                "display_name": display_name,
                "members": members,
                "oldest_log": _iso(oldest_log),
                "latest_log": _iso(latest_log),
                "event_count": event_count,
                "source": {
                    "syslog": source_syslog,
                    "import": source_import,
                    "last_import_ts": last_import_ts,
                    "source_display": source_display,
                },
                "is_importing": len(active_jobs_for_device) > 0,
                "active_import_jobs": active_jobs_for_device,
            })

        result.sort(key=lambda x: (x["display_name"].lower(), x["device_key"]))
        return result
    finally:
        db.close()


@router.get("/firewalls/{device_key}/import-jobs", response_model=List[Dict[str, Any]])
def list_firewall_import_jobs(request: Request, device_key: str):
    """List import jobs associated with this firewall (by device_key). For use in firewall details modal."""
    db: Session = get_db(request)
    try:
        # Jobs where device_key matches (set by processor when device is detected)
        stmt = (
            select(IngestJob)
            .where(IngestJob.device_key == device_key)
            .order_by(IngestJob.created_at.desc())
            .limit(50)
        )
        jobs = db.execute(stmt).scalars().all()
        out: List[Dict[str, Any]] = []
        for job in jobs:
            out.append({
                "job_id": job.id,
                "filename": job.filename,
                "status": job.status,
                "phase": _phase_from_status(job.status),
                "progress": round(_progress_from_job(job), 4),
                "lines_processed": job.lines_processed,
                "lines_total": job.lines_total,
                "parse_ok": job.parse_ok,
                "parse_err": job.parse_err,
                "raw_logs_inserted": job.raw_logs_inserted,
                "events_inserted": job.events_inserted,
                "time_min": job.time_min,
                "time_max": job.time_max,
                "created_at": _iso(job.created_at),
                "started_at": _iso(getattr(job, "started_at", None)),
                "finished_at": _iso(job.finished_at),
                "error_message": job.error_message,
            })
        return out
    finally:
        db.close()


@router.get("/firewalls/{device_key}", response_model=Dict[str, Any])
def get_firewall_override(request: Request, device_key: str):
    """Get override for one firewall. Returns display_name and comment or nulls if no override."""
    db: Session = get_db(request)
    try:
        row = db.execute(
            select(FirewallOverride).where(FirewallOverride.device_key == device_key)
        ).scalars().one_or_none()
        if not row:
            return {"device_key": device_key, "display_name": None, "comment": None, "updated_at": None}
        return {
            "device_key": row.device_key,
            "display_name": row.display_name,
            "comment": row.comment,
            "updated_at": _iso(row.updated_at),
        }
    finally:
        db.close()


@router.put("/firewalls/{device_key}", response_model=Dict[str, Any])
def update_firewall_override(request: Request, device_key: str, body: Dict[str, Any]):
    """Set display name and comment for a firewall. display_name required and non-empty after trim."""
    display_name = (body.get("display_name") or "").strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="display_name is required and cannot be empty")
    comment = (body.get("comment") or "").strip() or None

    db: Session = get_db(request)
    try:
        row = db.execute(
            select(FirewallOverride).where(FirewallOverride.device_key == device_key)
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if row:
            row.display_name = display_name
            row.comment = comment
            row.updated_at = now
        else:
            db.add(FirewallOverride(
                device_key=device_key,
                display_name=display_name,
                comment=comment,
                updated_at=now,
            ))
        db.commit()
        o = db.execute(
            select(FirewallOverride).where(FirewallOverride.device_key == device_key)
        ).scalars().one()
        return {
            "device_key": o.device_key,
            "display_name": o.display_name,
            "comment": o.comment,
            "updated_at": _iso(o.updated_at),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


def _run_purge_firewall(session_factory, job_id: str, device_key: str) -> None:
    """Background: resolve device_key to members, delete all related rows, update job."""
    db = session_factory()
    try:
        job = db.get(MaintenanceJob, job_id)
        if not job or job.status != "queued":
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        logger.exception("Purge job %s failed to start: %s", job_id, e)
        try:
            job = db.get(MaintenanceJob, job_id)
            if job:
                job.status = "error"
                job.error_message = str(e)[:1000]
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
        return
    finally:
        db.close()

    members: List[str] = []
    try:
        db = session_factory()
        members, _ = resolve_device(db, device_key)
        db.close()
    except Exception as e:
        logger.exception("Purge resolve_device failed: %s", e)
        db = session_factory()
        try:
            job = db.get(MaintenanceJob, job_id)
            if job:
                job.status = "error"
                job.error_message = f"Resolve failed: {e}"[:1000]
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
        return

    if not members:
        members = [device_key] if not device_key.startswith("ha:") else []

    counts: Dict[str, int] = {}
    canonical_override_key = device_key[3:].strip() if device_key.startswith("ha:") else device_key

    db = None
    try:
        db = session_factory()
        try:
            # Flows (device IN members)
            r = db.execute(delete(Flow).where(Flow.device.in_(members)))
            counts["flows_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            # Endpoints (device IN members)
            r = db.execute(delete(Endpoint).where(Endpoint.device.in_(members)))
            counts["endpoints_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(Event).where(Event.device.in_(members)))
            counts["events_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(RawLog).where(RawLog.device.in_(members)))
            counts["raw_logs_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(UnclassifiedEndpoint).where(UnclassifiedEndpoint.device.in_(members)))
            counts["unclassified_endpoints_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(Classification).where(Classification.device.in_(members)))
            counts["classifications_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(DeviceIdentification).where(DeviceIdentification.firewall_device.in_(members)))
            counts["device_identifications_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(DeviceOverride).where(DeviceOverride.firewall_device.in_(members)))
            counts["device_overrides_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(RouterMac).where(RouterMac.device.in_(members)))
            counts["router_macs_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(FirewallOverride).where(FirewallOverride.device_key == device_key))
            r2 = db.execute(delete(FirewallOverride).where(FirewallOverride.device_key == canonical_override_key))
            counts["firewall_overrides_deleted"] = r.rowcount + r2.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise
        try:
            r = db.execute(delete(FirewallInventory).where(FirewallInventory.device_key == device_key))
            counts["firewall_inventory_deleted"] = r.rowcount
            db.commit()
        except Exception:
            db.rollback()
            raise

        job = db.get(MaintenanceJob, job_id)
        if job:
            job.status = "done"
            job.result_counts = counts
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as e:
        logger.exception("Purge job %s failed: %s", job_id, e)
        err_db = session_factory()
        try:
            job = err_db.get(MaintenanceJob, job_id)
            if job:
                job.status = "error"
                job.error_message = str(e)[:1000]
                job.result_counts = counts
                job.finished_at = datetime.now(timezone.utc)
                err_db.commit()
        except Exception:
            err_db.rollback()
        finally:
            err_db.close()
    finally:
        if db is not None:
            db.close()


@router.post("/firewalls/{device_key}/purge", response_model=Dict[str, Any])
def purge_firewall(request: Request, device_key: str, body: Dict[str, Any]):
    """Start a background purge of all data for this firewall. Body: { \"confirm\": true }."""
    if not body.get("confirm"):
        raise HTTPException(status_code=400, detail="confirm is required and must be true")
    db: Session = get_db(request)
    try:
        # Refuse if an import is in progress
        busy = db.execute(
            select(IngestJob).where(IngestJob.status.in_(["uploading", "processing"]))
        ).scalars().first()
        if busy:
            raise HTTPException(
                status_code=409,
                detail="Import in progress; try again later.",
            )
        job_id = str(uuid.uuid4())
        job = MaintenanceJob(
            id=job_id,
            type="purge_firewall",
            status="queued",
            device_key=device_key,
        )
        db.add(job)
        db.commit()
        session_factory = request.app.state.db_sessionmaker
        thread = threading.Thread(
            target=_run_purge_firewall,
            args=(session_factory, job_id, device_key),
            daemon=True,
        )
        thread.start()
        return {"ok": True, "job_id": job_id}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()
