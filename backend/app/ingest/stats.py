"""Ingest pipeline statistics for troubleshooting (UDP packets, lines, records, DB writes)."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netwall.ingest.stats")

# Max length of sample line included in stats (to avoid huge payloads)
SAMPLE_RAW_LINE_MAX = 600


@dataclass
class IngestStats:
    """Counters updated by UDP receiver and SyslogIngestor. All mutable, no locking (single asyncio thread)."""

    # UDP layer
    udp_packets: int = 0
    udp_bytes: int = 0
    lines_received: int = 0

    # Reconstruction: complete records passed to _process_records
    records_processed: int = 0
    records_parse_ok: int = 0
    records_parse_error: int = 0
    records_filtered_id: int = 0  # id not startswith "0060"
    raw_logs_saved: int = 0
    events_saved: int = 0

    # Persistence errors (batch rollback)
    batch_errors: int = 0

    # Last received line (truncated), so you can see device format when records=0
    sample_raw_line: Optional[str] = None

    started_at: float = field(default_factory=time.monotonic)
    last_updated: Optional[datetime] = None

    def touch(self) -> None:
        """Update last_updated (call whenever counters change)."""
        self.last_updated = datetime.now(timezone.utc)

    def reset(self) -> None:
        self.udp_packets = 0
        self.udp_bytes = 0
        self.lines_received = 0
        self.records_processed = 0
        self.records_parse_ok = 0
        self.records_parse_error = 0
        self.records_filtered_id = 0
        self.raw_logs_saved = 0
        self.events_saved = 0
        self.batch_errors = 0
        self.sample_raw_line = None
        self.last_updated = None
        self.started_at = time.monotonic()

    def to_dict(self) -> dict:
        d: dict = {
            "udp_packets": self.udp_packets,
            "udp_bytes": self.udp_bytes,
            "lines_received": self.lines_received,
            "records_processed": self.records_processed,
            "records_parse_ok": self.records_parse_ok,
            "records_parse_error": self.records_parse_error,
            "records_filtered_id": self.records_filtered_id,
            "raw_logs_saved": self.raw_logs_saved,
            "events_saved": self.events_saved,
            "batch_errors": self.batch_errors,
            "uptime_seconds": round(time.monotonic() - self.started_at, 1),
        }
        if self.sample_raw_line is not None:
            d["sample_raw_line"] = self.sample_raw_line
        if self.last_updated is not None:
            d["last_updated"] = self.last_updated.isoformat()
        return d

    def snapshot(self) -> dict:
        """Lightweight snapshot for GET /api/stats (stable field names for frontend)."""
        return {
            "udp_packets": self.udp_packets,
            "udp_bytes": self.udp_bytes,
            "lines": self.lines_received,
            "records_total": self.records_processed,
            "records_ok": self.records_parse_ok,
            "parse_err": self.records_parse_error,
            "filtered_id": self.records_filtered_id,
            "db_raw_logs": self.raw_logs_saved,
            "db_events": self.events_saved,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }

    def log_summary(self) -> None:
        logger.info(
            "Ingest stats | UDP: %d packets, %d bytes | lines: %d | records: %d (ok=%d, parse_err=%d, filtered_id=%d) | DB: raw_logs=%d, events=%d | batch_errors=%d",
            self.udp_packets,
            self.udp_bytes,
            self.lines_received,
            self.records_processed,
            self.records_parse_ok,
            self.records_parse_error,
            self.records_filtered_id,
            self.raw_logs_saved,
            self.events_saved,
            self.batch_errors,
        )
        if self.lines_received > 0 and self.records_processed == 0 and self.sample_raw_line:
            logger.warning(
                "No records assembled (prefix mismatch?). Sample raw line (first %d chars): %s",
                SAMPLE_RAW_LINE_MAX,
                self.sample_raw_line,
            )


# Single global instance used by UDP server and SyslogIngestor
ingest_stats = IngestStats()
