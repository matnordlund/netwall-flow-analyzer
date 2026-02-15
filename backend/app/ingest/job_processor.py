"""Background processing for ingest upload jobs: read file, run pipeline, update job row."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import MultipleResultsFound

from ..api.device_resolve import get_device_display_label
from ..config import AppConfig
from ..storage.models import IngestJob
from ..storage.ha_canonical import canonical_firewall_key_import
from ..storage.firewall_source import upsert_firewall_import
from ..storage.writer import Writer as StorageWriter
from .reconstruct import SyslogIngestor, UploadCollector

logger = logging.getLogger("netwall.ingest.job")


def run_import_job(
    job_id: str,
    file_path: Path,
    session_factory: Any,
    config: AppConfig,
    ingestor: SyslogIngestor,
    engine: Any,
) -> None:
    """Sync entry point for background thread: run process_ingest_job in a new event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            process_ingest_job(
                job_id=job_id,
                file_path=file_path,
                session_factory=session_factory,
                ingestor=ingestor,
                config=config,
                engine=engine,
            )
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("run_import_job %s failed: %s", job_id, e)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:  # noqa: S110
            pass
        loop.close()

def _infer_error_stage(exc: BaseException) -> str:
    """Infer pipeline stage from exception type for clearer UI."""
    name = type(exc).__name__
    if "MultipleResultsFound" in name or "flow" in str(exc).lower():
        return "flow_aggregation"
    if "Integrity" in name or "Operational" in name or "Database" in name:
        return "persist"
    if "ValueError" in name or "KeyError" in name or "Parse" in name or "parse" in str(exc).lower():
        return "parse"
    return "processing"


def check_job_cancel_requested(session_factory: Any, job_id: str) -> bool:
    """Return True if job has cancel_requested set. Safe to call from worker."""
    db = session_factory()
    try:
        job = db.get(IngestJob, job_id)
        return job is not None and bool(job.cancel_requested)
    finally:
        db.close()


def _maybe_update_job_device(
    session_factory: Any,
    job_id: str,
    collector: UploadCollector,
) -> None:
    """If job has no device_key yet and collector has a primary device, set device_key/device_display and commit."""
    primary = collector.primary_device(None)
    if not primary or primary == "unknown":
        return
    db = session_factory()
    try:
        job = db.get(IngestJob, job_id)
        if not job or getattr(job, "device_key", None):
            return
        job.device_detected = primary
        job.device_key = canonical_firewall_key_import(primary)
        job.device_display = get_device_display_label(db, primary)
        job.updated_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Job detected firewall=%s job_id=%s", job.device_key, job_id)
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to update job device: %s", e)
    finally:
        db.close()


def _set_job_canceled(
    session_factory: sessionmaker,
    job_id: str,
    file_path: Path,
    lines_processed: int = 0,
    collector: UploadCollector | None = None,
) -> None:
    """Set job status to canceled, set finished_at and counters, delete file."""
    now = datetime.now(timezone.utc)
    db = session_factory()
    try:
        job = db.get(IngestJob, job_id)
        if job:
            job.status = "canceled"
            job.phase = None
            job.finished_at = now
            job.lines_processed = lines_processed
            if collector is not None:
                job.parse_ok = collector.parse_ok
                job.parse_err = collector.parse_err
                job.filtered_id = collector.filtered_id
                job.raw_logs_inserted = collector.raw_logs_inserted
                job.events_inserted = collector.events_inserted
            job.updated_at = now
            db.commit()
    except Exception as e:  # noqa: BLE001
        logger.exception("Failed to set job %s to canceled: %s", job_id, e)
    finally:
        db.close()
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        pass


def _set_job_error(
    session_factory: sessionmaker,
    job_id: str,
    error_message: str,
    lines_processed: int = 0,
    collector: UploadCollector | None = None,
    error_type: str | None = None,
    error_stage: str | None = None,
) -> None:
    """Set job status to error and persist; safe to call from anywhere."""
    now = datetime.now(timezone.utc)
    db = session_factory()
    try:
        job = db.get(IngestJob, job_id)
        if job:
            job.status = "error"
            job.phase = None
            job.error_message = (error_message or "Unknown error")[:1000]
            job.error_type = error_type
            job.error_stage = error_stage
            job.lines_processed = lines_processed
            job.finished_at = now
            if collector is not None:
                job.parse_ok = collector.parse_ok
                job.parse_err = collector.parse_err
                job.filtered_id = collector.filtered_id
                job.raw_logs_inserted = collector.raw_logs_inserted
                job.events_inserted = collector.events_inserted
            job.updated_at = now
            db.commit()
    except Exception as e:  # noqa: BLE001
        logger.exception("Failed to set job %s to error: %s", job_id, e)
    finally:
        db.close()


async def process_ingest_job(
    job_id: str,
    file_path: Path,
    session_factory: sessionmaker,
    ingestor: SyslogIngestor,
    config: AppConfig,
    engine: Any,
) -> None:
    """Read file at file_path, run through ingestor, update IngestJob row periodically and on completion."""
    collector = UploadCollector()
    lines_processed = 0
    try:
        db: Session = session_factory()
        try:
            job = db.get(IngestJob, job_id)
            if not job:
                logger.warning("IngestJob %s not found", job_id)
                return
            job.status = "running"
            job.updated_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()

        if not file_path.exists():
            _set_job_error(
                session_factory, job_id, f"Upload file not found: {file_path}",
                error_stage="upload",
            )
            return

        ingestor.upload_collector = collector

        # Batched ingest via storage Writer (Core upserts; one transaction per batch; SQLite writer lock).
        batch_writer = StorageWriter(engine)
        ingestor.upload_batch_writer = batch_writer
        ingestor.upload_raw_batch = []
        ingestor.upload_event_batch = []
        ingestor.upload_flow_events = []
        ingestor.upload_batch_size = 5000
        ingestor.upload_job_id = job_id
        ingestor.upload_get_lines_processed = lambda: lines_processed

        try:
            # Stream file from disk line-by-line (64 KB read chunks; no full-file read)
            CHECK_CANCEL_EVERY = 5000
            if check_job_cancel_requested(session_factory, job_id):
                _set_job_canceled(session_factory, job_id, file_path, 0, collector)
                return
            with open(file_path, "rb") as f:
                line_buffer = ""
                while True:
                    if lines_processed > 0 and lines_processed % CHECK_CANCEL_EVERY == 0:
                        _maybe_update_job_device(session_factory, job_id, collector)
                        if check_job_cancel_requested(session_factory, job_id):
                            await ingestor.flush()
                            _set_job_canceled(session_factory, job_id, file_path, lines_processed, collector)
                            return
                        logger.info("Job progress job_id=%s lines_processed=%s", job_id, lines_processed)
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    line_buffer += chunk.decode(errors="replace")
                    while "\n" in line_buffer or "\r" in line_buffer:
                        sep_str = "\n" if "\n" in line_buffer else "\r"
                        line, _, line_buffer = line_buffer.partition(sep_str)
                        if line.strip():
                            lines_processed += 1
                            await ingestor.handle_line(line)
                    await asyncio.sleep(0)
                if line_buffer.strip():
                    lines_processed += 1
                    await ingestor.handle_line(line_buffer)
            if check_job_cancel_requested(session_factory, job_id):
                await ingestor.flush()
                _set_job_canceled(session_factory, job_id, file_path, lines_processed, collector)
                return

            await ingestor.flush()

            # Set phase=finalizing so UI shows 100% + "Finalizing" before we set status=done
            now_utc = datetime.now(timezone.utc)
            db_fin = session_factory()
            try:
                j = db_fin.get(IngestJob, job_id)
                if j and j.status == "running":
                    j.phase = "finalizing"
                    j.updated_at = now_utc
                    db_fin.commit()
            finally:
                db_fin.close()
        finally:
            ingestor.upload_batch_writer = None
            ingestor.upload_raw_batch = None
            ingestor.upload_event_batch = None
            ingestor.upload_flow_events = None
            ingestor.upload_job_id = None
            ingestor.upload_get_lines_processed = None

        # Final job update and status=done on a new session (ingest session is closed, no lock)
        now = datetime.now(timezone.utc)
        db = session_factory()
        try:
            job = db.get(IngestJob, job_id)
            if not job:
                return
            job.status = "done"
            job.phase = None
            job.finished_at = now
            job.lines_total = lines_processed
            job.lines_processed = lines_processed
            job.parse_ok = collector.parse_ok
            job.parse_err = collector.parse_err
            job.filtered_id = collector.filtered_id
            job.raw_logs_inserted = collector.raw_logs_inserted
            job.events_inserted = collector.events_inserted
            job.time_min = collector.time_min_iso()
            job.time_max = collector.time_max_iso()
            job.device_detected = collector.primary_device(None)
            job.device_display = get_device_display_label(db, job.device_detected)
            job.updated_at = now
            if job.device_detected:
                device_key = canonical_firewall_key_import(job.device_detected)
                job.device_key = device_key
                first_ts = last_ts = None
                if job.time_min:
                    try:
                        first_ts = datetime.fromisoformat(job.time_min.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        pass
                if job.time_max:
                    try:
                        last_ts = datetime.fromisoformat(job.time_max.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        pass
                logger.info(
                    "Import marking firewall: job_id=%s device_detected=%s firewall_key=%s ingest_source=import events_inserted=%s target=firewall_inventory.device_key=%s",
                    job_id, job.device_detected, device_key, job.events_inserted, device_key,
                )
                upsert_firewall_import(db, device_key, first_ts=first_ts, last_ts=last_ts)
            db.commit()
            logger.info(
                "Job finished state=done job_id=%s events_inserted=%s device_key=%s",
                job_id, job.events_inserted, job.device_key,
            )
        finally:
            db.close()

    except MultipleResultsFound as exc:
        msg = "Flow table contains duplicates for flow identity; run scripts/dedup_flows_and_add_unique_index.py and see logs"
        logger.exception("Ingest job %s failed (MultipleResultsFound): %s", job_id, exc)
        _set_job_error(
            session_factory, job_id, msg, lines_processed, collector,
            error_type=type(exc).__name__, error_stage="flow_aggregation",
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ingest job %s failed: %s", job_id, exc)
        stage = _infer_error_stage(exc)
        _set_job_error(
            session_factory, job_id, str(exc)[:1000], lines_processed, collector,
            error_type=type(exc).__name__, error_stage=stage,
        )
    finally:
        ingestor.upload_collector = None
        # Delete file only if we did not already set canceled (which deletes it)
        db = session_factory()
        try:
            job = db.get(IngestJob, job_id)
            if job is None or job.status != "canceled":
                try:
                    file_path.unlink(missing_ok=True)
                except OSError:
                    pass
        finally:
            db.close()
