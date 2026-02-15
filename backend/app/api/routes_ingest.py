from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

from ..api.routes_zones import HA_MASTER_SUFFIX, HA_SLAVE_SUFFIX
from ..ingest.job_processor import process_ingest_job
from ..ingest.stats import ingest_stats
from sqlalchemy import update

from ..storage.models import IngestJob

router = APIRouter(tags=["ingest"])

# Max upload size for syslog file (1 GB)
UPLOAD_MAX_BYTES = 1024 * 1024 * 1024


def mark_stale_ingest_jobs_error(session_factory) -> int:
    """Mark any jobs left as uploading/processing (e.g. after server restart) as error. Returns count updated."""
    db = session_factory()
    try:
        stmt = (
            update(IngestJob)
            .where(IngestJob.status.in_(["uploading", "processing"]))
            .values(
                status="error",
                error_message="Server restarted",
                updated_at=datetime.now(timezone.utc),
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
            j.status = "processing"
            j.updated_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()

    asyncio.create_task(
        process_ingest_job(
            job_id=job_id,
            file_path=file_path,
            session_factory=request.app.state.db_sessionmaker,
            ingestor=request.app.state.syslog_ingestor,
            config=request.app.state.app_config,
        )
    )
    return {"ok": True, "job_id": job_id}


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
        device_key = _device_key_from_detected(job.device_detected)
        return {
            "job_id": job.id,
            "status": job.status,
            "filename": job.filename,
            "bytes_total": job.bytes_total,
            "bytes_received": job.bytes_received,
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
            "error_message": job.error_message,
            "error_type": job.error_type,
            "error_stage": job.error_stage,
        }
    finally:
        db.close()

