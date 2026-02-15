"""Background processing for ingest upload jobs: read file, run pipeline, update job row."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import MultipleResultsFound

from ..api.device_resolve import get_device_display_label
from ..config import AppConfig
from ..storage.models import IngestJob
from ..storage.firewall_source import get_canonical_device_key, upsert_firewall_import
from ..storage.event_writer import SQLiteEventWriter
from .reconstruct import SyslogIngestor, UploadCollector

logger = logging.getLogger("netwall.ingest.job")

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
    db = session_factory()
    try:
        job = db.get(IngestJob, job_id)
        if job:
            job.status = "error"
            job.error_message = (error_message or "Unknown error")[:1000]
            job.error_type = error_type
            job.error_stage = error_stage
            job.lines_processed = lines_processed
            if collector is not None:
                job.parse_ok = collector.parse_ok
                job.parse_err = collector.parse_err
                job.filtered_id = collector.filtered_id
                job.raw_logs_inserted = collector.raw_logs_inserted
                job.events_inserted = collector.events_inserted
            job.updated_at = datetime.now(timezone.utc)
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
            job.status = "processing"
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

        # Dedicated session + writer for batched ingest (WAL PRAGMAs, bulk inserts).
        # Job row is updated only on this session when we commit each batch to avoid SQLite "database is locked".
        ingest_session = session_factory()
        writer = SQLiteEventWriter()
        try:
            writer.configure_ingest_mode(ingest_session)
            ingestor.upload_session = ingest_session
            ingestor.upload_writer = writer
            ingestor.upload_raw_batch = []
            ingestor.upload_event_batch = []
            ingestor.upload_batch_size = 5000
            ingestor.upload_job_id = job_id
            ingestor.upload_get_lines_processed = lambda: lines_processed

            # Stream file from disk line-by-line (64 KB read chunks; no full-file read)
            with open(file_path, "rb") as f:
                line_buffer = ""
                while True:
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

            await ingestor.flush()
        finally:
            ingestor.upload_session = None
            ingestor.upload_writer = None
            ingestor.upload_raw_batch = None
            ingestor.upload_event_batch = None
            ingestor.upload_job_id = None
            ingestor.upload_get_lines_processed = None
            ingest_session.close()

        # Final job update and status=done on a new session (ingest session is closed, no lock)
        db = session_factory()
        try:
            job = db.get(IngestJob, job_id)
            if not job:
                return
            job.status = "done"
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
            job.updated_at = datetime.now(timezone.utc)
            if job.device_detected:
                device_key = get_canonical_device_key(db, job.device_detected)
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
                upsert_firewall_import(db, device_key, first_ts=first_ts, last_ts=last_ts)
            db.commit()
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
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            pass
