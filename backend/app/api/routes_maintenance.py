"""Maintenance jobs: purge firewall, etc. Status polling."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.orm import Session

from ..storage.models import MaintenanceJob

router = APIRouter(tags=["maintenance"])
logger = logging.getLogger(__name__)


def get_db(request: Request) -> Session:
    return request.app.state.db_sessionmaker()


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@router.get("/maintenance/jobs/{job_id}", response_model=Dict[str, Any])
def get_maintenance_job(request: Request, job_id: str):
    """Return maintenance job status and result counters."""
    db: Session = get_db(request)
    try:
        job = db.get(MaintenanceJob, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return {
            "job_id": job.id,
            "type": job.type,
            "status": job.status,
            "device_key": job.device_key,
            "result_counts": job.result_counts or {},
            "error_message": job.error_message,
            "created_at": _iso(job.created_at),
            "started_at": _iso(job.started_at),
            "finished_at": _iso(job.finished_at),
        }
    finally:
        db.close()
