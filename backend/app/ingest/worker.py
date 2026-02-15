"""Single-threaded import job queue: one job runs at a time, others stay queued."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from ..api.routes_ingest import UPLOAD_JOBS_DIR
from ..storage.models import IngestJob
from .job_processor import run_import_job

logger = logging.getLogger("netwall.ingest.worker")

POLL_INTERVAL_SEC = 1.5
STALL_THRESHOLD_MINUTES = 5


def _mark_stalled_running_jobs(session_factory) -> int:
    """Mark any job still 'running' with updated_at older than STALL_THRESHOLD_MINUTES as error. Returns count."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=STALL_THRESHOLD_MINUTES)
    db = session_factory()
    try:
        stmt = (
            update(IngestJob)
            .where(IngestJob.status == "running")
            .where(IngestJob.updated_at < cutoff)
            .values(
                status="error",
                error_message="job stalled",
                finished_at=now,
                updated_at=now,
            )
        )
        r = db.execute(stmt)
        db.commit()
        n = r.rowcount if hasattr(r, "rowcount") else 0
        if n:
            logger.warning("Marked %d stalled running job(s) as error", n)
        return n
    finally:
        db.close()


def run_worker_loop(session_factory, config, syslog_ingestor, stop_event, engine) -> None:
    """Run forever: pick oldest queued job, set running, process; repeat. Stop when stop_event is set."""
    while not stop_event.is_set():
        # Mark any job stuck in 'running' (e.g. crashed worker) as error
        _mark_stalled_running_jobs(session_factory)

        db = session_factory()
        job = None
        try:
            stmt = (
                select(IngestJob)
                .where(IngestJob.status == "queued")
                .where(IngestJob.cancel_requested == False)  # noqa: E712
                .order_by(IngestJob.created_at.asc())
                .limit(1)
            )
            row = db.execute(stmt).scalars().first()
            if row is None:
                db.close()
                stop_event.wait(POLL_INTERVAL_SEC)
                continue
            job = row
            job_id = job.id
            job_filename = job.filename
            file_path = UPLOAD_JOBS_DIR / f"{job_id}.log"
            now = datetime.now(timezone.utc)
            job.status = "running"
            job.started_at = now
            job.updated_at = now
            db.commit()
            db.close()
        except Exception as e:
            logger.exception("Worker failed to pick job: %s", e)
            try:
                db.close()
            except Exception:
                pass
            stop_event.wait(POLL_INTERVAL_SEC)
            continue

        logger.info("Job started job_id=%s filename=%s", job_id, job_filename)

        try:
            run_import_job(
                job_id=job_id,
                file_path=file_path,
                session_factory=session_factory,
                config=config,
                ingestor=syslog_ingestor,
                engine=engine,
            )
        except Exception as e:
            logger.exception("Worker run_import_job %s failed: %s", job_id, e)
            # Ensure job is not left as running
            db = session_factory()
            try:
                j = db.get(IngestJob, job_id)
                if j and j.status == "running":
                    now = datetime.now(timezone.utc)
                    j.status = "error"
                    j.error_message = (str(e)[:1000] if e else "Worker exception")
                    j.finished_at = now
                    j.updated_at = now
                    db.commit()
                    logger.info("Job finished state=error job_id=%s error=%s", job_id, j.error_message)
            finally:
                db.close()
        else:
            # Log final state (processor sets done/error/canceled)
            db = session_factory()
            try:
                j = db.get(IngestJob, job_id)
                if j:
                    logger.info(
                        "Job finished state=%s job_id=%s events_inserted=%s error=%s",
                        j.status, job_id, getattr(j, "events_inserted", None), getattr(j, "error_message", None),
                    )
            finally:
                db.close()

        time.sleep(0.1)
