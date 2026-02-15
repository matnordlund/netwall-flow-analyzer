from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from sqlalchemy import update

from ..api.routes_zones import HA_MASTER_SUFFIX, HA_SLAVE_SUFFIX
from ..ingest.job_processor import run_import_job
from ..ingest.stats import ingest_stats
from ..storage.models import IngestJob

router = APIRouter(tags=["ingest"])

# Max upload size for syslog file (1 GB)
UPLOAD_MAX_BYTES = 1024 * 1024 * 1024


def mark_stale_ingest_jobs_error(session_factory) -> int:
    """Mark any jobs left as uploading/running/queued (e.g. after server restart) as error. Returns count updated."""
    now = datetime.now(timezone.utc)
    db = session_factory()
    try:
        stmt = (
            update(IngestJob)
            .where(IngestJob.status.in_(["uploading", "running", "queued"]))
            .values(
                status="error",
                error_message="Server restarted",
                updated_at=now,
                finished_at=now,
            )
        )
        result = db.execute(stmt)
        db.commit()
        return result.rowcount if hasattr(result, "rowcount") else 0
    finally:
        db.close()

# Directory for temporary upload files (one per job)
UPLOAD_JOBS_DIR = Path("uploads").resolve()


def _ensure_upload_dir() -> Path:
    UPLOAD_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    return UPLOAD_JOBS_DIR


@router.get("/stats")
def get_stats_snapshot():
    """Lightweight read-only snapshot of ingest pipeline state for the frontend banner."""
    return ingest_stats.snapshot()


@router.get("/ingest/stats")
def get_ingest_stats():
    """Return current ingest pipeline counters (UDP packets, lines, records, DB writes). Useful for troubleshooting."""
    return ingest_stats.to_dict()


@router.post("/ingest/stats/reset")
def reset_ingest_stats():
    """Reset ingest counters to zero. Useful to watch a fresh batch (e.g. after changing device format)."""
    ingest_stats.reset()
    return {"status": "ok"}


@router.post("/ingest/file")
async def ingest_file(request: Request, file: UploadFile = File(...)):
    """Stream uploaded file through the same ingest pipeline as UDP."""
    ingestor = request.app.state.syslog_ingestor

    # Feed by lines so wrapped records are reconstructed properly.
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        text = chunk.decode(errors="replace")
        for line in text.splitlines():
            if not line.strip():
                continue
            ingest_stats.lines_received += 1
            await ingestor.handle_line(line)

    await ingestor.flush()
    ingest_stats.touch()
    return {"status": "ok"}


@router.post("/ingest/upload")
async def ingest_upload(
    request: Request,
    file: UploadFile = File(...),
    device: str | None = Form(None),
    source: str | None = Form(None),
):
    """Upload a syslog file; create job, save to temp file, return job_id. Processing runs in background."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    upload_dir = _ensure_upload_dir()
    file_path = upload_dir / f"{job_id}.log"

    db = request.app.state.db_sessionmaker()
    try:
        job = IngestJob(
            id=job_id,
            status="uploading",
            filename=file.filename,
            bytes_total=0,
            bytes_received=0,
            created_at=now,
            updated_at=now,
        )
        db.add(job)
        db.commit()
    finally:
        db.close()

    # Stream to disk; then we return job_id and process in a background thread (no request blocking)

    # Stream to disk in 4 MB chunks to avoid loading large uploads into memory
    UPLOAD_CHUNK_BYTES = 4 * 1024 * 1024
    total_bytes = 0
    try:
        with open(file_path, "wb") as out:
            while True:
                chunk = await file.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > UPLOAD_MAX_BYTES:
                    file_path.unlink(missing_ok=True)
                    db = request.app.state.db_sessionmaker()
                    try:
                        j = db.get(IngestJob, job_id)
                        if j:
                            j.status = "error"
                            j.error_message = "File too large (max 1 GB)"
                            j.error_type = "RequestEntityTooLarge"
                            j.error_stage = "upload"
                            j.updated_at = datetime.now(timezone.utc)
                            db.commit()
                    finally:
                        db.close()
                    raise HTTPException(
                        status_code=413,
                        detail="File too large (max 1 GB)",
                    )
                out.write(chunk)
                if total_bytes % (512 * 1024) == 0 or len(chunk) < UPLOAD_CHUNK_BYTES:
                    db = request.app.state.db_sessionmaker()
                    try:
                        j = db.get(IngestJob, job_id)
                        if j:
                            j.bytes_received = total_bytes
                            j.updated_at = datetime.now(timezone.utc)
                            db.commit()
                    finally:
                        db.close()
    except HTTPException:
        raise
    except Exception as exc:
        file_path.unlink(missing_ok=True)
        db = request.app.state.db_sessionmaker()
        try:
            j = db.get(IngestJob, job_id)
            if j:
                j.status = "error"
                j.error_message = str(exc)[:1000]
                j.error_type = type(exc).__name__
                j.error_stage = "upload"
                j.updated_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        raise

    if total_bytes == 0:
        file_path.unlink(missing_ok=True)
        db = request.app.state.db_sessionmaker()
        try:
            j = db.get(IngestJob, job_id)
            if j:
                j.status = "error"
                j.error_message = "Empty file"
                j.error_type = "ValueError"
                j.error_stage = "upload"
                j.updated_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        raise HTTPException(status_code=400, detail="Empty file")

    db = request.app.state.db_sessionmaker()
    try:
        j = db.get(IngestJob, job_id)
        if j:
            j.bytes_total = total_bytes
            j.bytes_received = total_bytes
            j.status = "queued"
            j.updated_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()

    # Import is handled by the single ingest worker; do not start a thread here.
    return {"ok": True, "job_id": job_id, "filename": file.filename, "size_bytes": total_bytes}


def _device_key_from_detected(device_detected: str | None) -> str | None:
    """Canonical key for dropdown: 'ha:base' for HA members, else raw device name."""
    if not device_detected or not device_detected.strip():
        return device_detected
    d = device_detected.strip()
    if d.endswith(HA_MASTER_SUFFIX):
        base = d[: -len(HA_MASTER_SUFFIX)]
        return f"ha:{base}" if base else d
    if d.endswith(HA_SLAVE_SUFFIX):
        base = d[: -len(HA_SLAVE_SUFFIX)]
        return f"ha:{base}" if base else d
    return d


def _phase_from_status(status: str) -> str:
    """Map job status to UI phase: upload | parsing | db_insert | finalizing."""
    if status == "uploading":
        return "upload"
    if status in ("queued", "running"):
        return "parsing"
    if status == "done":
        return "finalizing"
    return "error"


def _progress_from_job(job: IngestJob) -> float:
    """Return 0.0–1.0 progress: bytes or lines based. Running jobs cap at 0.99 until done."""
    if job.status == "running":
        # Avoid showing 100% while still processing (bytes complete but commit pending)
        if job.bytes_total and job.bytes_total > 0:
            return min(0.99, (job.bytes_received or 0) / job.bytes_total)
        if job.lines_total and job.lines_total > 0:
            return min(0.99, (job.lines_processed or 0) / job.lines_total)
        return 0.0
    if job.bytes_total and job.bytes_total > 0:
        return min(1.0, (job.bytes_received or 0) / job.bytes_total)
    if job.lines_total and job.lines_total > 0:
        return min(1.0, (job.lines_processed or 0) / job.lines_total)
    return 0.0


def _phase_for_job(job: IngestJob) -> str:
    """Return UI phase: use job.phase if set (e.g. finalizing), else derive from status."""
    phase = getattr(job, "phase", None)
    if phase:
        return phase
    return _phase_from_status(job.status)


@router.get("/ingest/upload/status")
def ingest_upload_status(request: Request, job_id: str = Query(..., description="Ingest job ID")):
    """Return current status and counters for an ingest upload job."""
    db = request.app.state.db_sessionmaker()
    try:
        job = db.get(IngestJob, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        imported = job.raw_logs_inserted
        discarded = job.filtered_id + job.parse_err
        device_key = getattr(job, "device_key", None) or _device_key_from_detected(job.device_detected)
        progress = _progress_from_job(job)
        phase = _phase_for_job(job)
        return {
            "job_id": job.id,
            "status": job.status,
            "state": job.status,
            "phase": phase,
            "progress": round(progress, 4),
            "filename": job.filename,
            "bytes_total": job.bytes_total,
            "bytes_received": job.bytes_received,
            "bytes_processed": job.bytes_received,
            "lines_total": job.lines_total,
            "lines_processed": job.lines_processed,
            "parse_ok": job.parse_ok,
            "parse_err": job.parse_err,
            "filtered_id": job.filtered_id,
            "raw_logs_inserted": job.raw_logs_inserted,
            "events_inserted": job.events_inserted,
            "imported": imported,
            "discarded": discarded,
            "time_min": job.time_min,
            "time_max": job.time_max,
            "device_detected": job.device_detected,
            "device_key": device_key,
            "device_display": job.device_display,
            "firewall_display": job.device_display,
            "error_message": job.error_message,
            "error_type": job.error_type,
            "error_stage": job.error_stage,
        }
    finally:
        db.close()


@router.get("/ingest/jobs/active")
def list_active_ingest_jobs(request: Request):
    """Return active (queued/uploading/processing) ingest jobs for UI status/queue viewer."""
    from sqlalchemy import select
    db = request.app.state.db_sessionmaker()
    try:
        stmt = (
            select(IngestJob)
            .where(IngestJob.status.in_(["queued", "uploading", "running"]))
            .order_by(IngestJob.created_at.desc())
        )
        jobs = db.execute(stmt).scalars().all()
        out = []
        for job in jobs:
            progress = _progress_from_job(job)
            device_key = getattr(job, "device_key", None) or _device_key_from_detected(job.device_detected)
            discarded = (job.filtered_id or 0) + (job.parse_err or 0)
            out.append({
                "job_id": job.id,
                "status": job.status,
                "phase": _phase_for_job(job),
                "progress": round(progress, 4),
                "filename": job.filename,
                "bytes_total": job.bytes_total,
                "bytes_received": job.bytes_received,
                "lines_processed": job.lines_processed,
                "lines_total": job.lines_total,
                "parse_ok": job.parse_ok,
                "parse_err": job.parse_err,
                "raw_logs_inserted": job.raw_logs_inserted,
                "events_inserted": job.events_inserted,
                "discarded": discarded,
                "device_key": device_key,
                "device_display": job.device_display,
                "created_at": job.created_at.isoformat() if job.created_at else None,
            })
        return {"jobs": out}
    finally:
        db.close()


@router.get("/ingest/jobs")
def list_ingest_jobs(
    request: Request,
    state: str | None = Query(None, description="Comma-separated: queued,running,done,error,canceled"),
    limit: int = Query(50, ge=1, le=200),
):
    """List ingest jobs with optional state filter. Returns job metadata, counters, device_key."""
    from sqlalchemy import select
    db = request.app.state.db_sessionmaker()
    try:
        stmt = select(IngestJob).order_by(IngestJob.created_at.desc()).limit(limit)
        if state:
            states = [s.strip() for s in state.split(",") if s.strip()]
            if states:
                stmt = stmt.where(IngestJob.status.in_(states))
        jobs = db.execute(stmt).scalars().all()
        out = []
        for job in jobs:
            progress = _progress_from_job(job)
            dk = getattr(job, "device_key", None) or _device_key_from_detected(job.device_detected)
            discarded = (job.filtered_id or 0) + (job.parse_err or 0)
            out.append({
                "job_id": job.id,
                "status": job.status,
                "phase": _phase_for_job(job),
                "progress": round(progress, 4),
                "filename": job.filename,
                "bytes_total": job.bytes_total,
                "bytes_received": job.bytes_received,
                "lines_processed": job.lines_processed,
                "lines_total": job.lines_total,
                "parse_ok": job.parse_ok,
                "parse_err": job.parse_err,
                "raw_logs_inserted": job.raw_logs_inserted,
                "events_inserted": job.events_inserted,
                "discarded": discarded,
                "device_key": dk,
                "device_display": job.device_display,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if getattr(job, "started_at", None) else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "error_message": job.error_message,
            })
        return {"jobs": out}
    finally:
        db.close()


@router.post("/ingest/jobs/{job_id}/cancel")
def cancel_ingest_job(request: Request, job_id: str):
    """Cancel a queued or running job. Queued: mark canceled and delete file. Running: set cancel_requested."""
    db = request.app.state.db_sessionmaker()
    try:
        job = db.get(IngestJob, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status == "queued":
            job.status = "canceled"
            job.finished_at = datetime.now(timezone.utc)
            job.updated_at = job.finished_at
            db.commit()
            file_path = UPLOAD_JOBS_DIR / f"{job_id}.log"
            file_path.unlink(missing_ok=True)
            return {"ok": True, "status": "canceled"}
        if job.status == "running":
            job.cancel_requested = True
            job.updated_at = datetime.now(timezone.utc)
            db.commit()
            return {"ok": True, "status": "cancel_requested"}
        raise HTTPException(
            status_code=400,
            detail=f"Job cannot be canceled (status={job.status})",
        )
    finally:
        db.close()


@router.delete("/ingest/jobs/{job_id}")
def delete_ingest_job(request: Request, job_id: str):
    """Delete a job record and its uploaded file. Allowed only if state in queued,done,error,canceled."""
    db = request.app.state.db_sessionmaker()
    try:
        job = db.get(IngestJob, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status not in ("queued", "done", "error", "canceled"):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete job while running or uploading (status={job.status})",
            )
        db.delete(job)
        db.commit()
        file_path = UPLOAD_JOBS_DIR / f"{job_id}.log"
        file_path.unlink(missing_ok=True)
        return {"ok": True}
    finally:
        db.close()
