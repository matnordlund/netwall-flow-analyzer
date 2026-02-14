#!/usr/bin/env python3
"""
One-time maintenance: deduplicate flows by identity key, then add unique index.

Run before or after deploying the Flow unique constraint so that:
1. Existing duplicate flow rows are merged (keep one row per identity, sum counts, merge top_rules/top_apps).
2. The unique index ux_flows_identity is created so future inserts use upsert.

Usage (from repo/backend):
  python -m scripts.dedup_flows_and_add_unique_index
  python -m scripts.dedup_flows_and_add_unique_index --database-url "sqlite:///./data/netwall.db"
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.config import parse_args
from app.storage.models import Flow

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

FLOW_IDENTITY_COLS = [
    "device", "basis", "from_value", "to_value",
    "proto", "dest_port", "src_endpoint_id", "dst_endpoint_id", "view_kind",
]


def run(config) -> None:
    engine = create_engine(config.database_url, future=True)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    session = Session()

    try:
        # 1) Find duplicate groups: (identity cols...) -> list of ids
        identity_list = ", ".join(FLOW_IDENTITY_COLS)
        dup_sql = f"""
        SELECT {identity_list}, GROUP_CONCAT(id) AS ids
        FROM flows
        GROUP BY {identity_list}
        HAVING COUNT(*) > 1
        """
        result = session.execute(text(dup_sql))
        groups = result.fetchall()
        if not groups:
            logger.info("No duplicate flow groups found.")
        else:
            for row in groups:
                ids_str = row[-1]
                ids = [int(x) for x in ids_str.split(",")]
                keep_id = max(ids)
                drop_ids = [i for i in ids if i != keep_id]
                # Load kept row and all duplicates
                keep = session.get(Flow, keep_id)
                if not keep:
                    continue
                for fid in drop_ids:
                    other = session.get(Flow, fid)
                    if not other:
                        continue
                    keep.count_open += other.count_open or 0
                    keep.count_close += other.count_close or 0
                    keep.bytes_src_to_dst += other.bytes_src_to_dst or 0
                    keep.bytes_dst_to_src += other.bytes_dst_to_src or 0
                    keep.duration_total_s += other.duration_total_s or 0
                    if other.first_seen and (keep.first_seen is None or other.first_seen < keep.first_seen):
                        keep.first_seen = other.first_seen
                    if other.last_seen and (keep.last_seen is None or other.last_seen > keep.last_seen):
                        keep.last_seen = other.last_seen
                    for k, v in (other.top_rules or {}).items():
                        keep.top_rules[k] = keep.top_rules.get(k, 0) + v
                    for k, v in (other.top_apps or {}).items():
                        keep.top_apps[k] = keep.top_apps.get(k, 0) + v
                    session.delete(other)
                session.flush()
            session.commit()
            logger.info("Merged and removed duplicates in %d flow group(s).", len(groups))

        # 2) Create unique index (idempotent; skip if using create_all and table already has constraint)
        with engine.connect() as conn:
            conn.execute(text(f"CREATE UNIQUE INDEX IF NOT EXISTS ux_flows_identity ON flows ({identity_list})"))
            conn.commit()
        logger.info("Created unique index ux_flows_identity (if not exists).")
    finally:
        session.close()

    logger.info("Done.")


def main() -> None:
    config = parse_args()
    run(config)


if __name__ == "__main__":
    main()
