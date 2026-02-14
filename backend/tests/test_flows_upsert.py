"""Regression tests for flows table unique index and upsert (ON CONFLICT)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.storage.flow_index import ensure_flows_unique_index
from app.storage.models import Base, Flow


@pytest.fixture
def sqlite_engine():
    """In-memory SQLite engine with flows table and unique index."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    ok = ensure_flows_unique_index(engine)
    assert ok, "flows unique index should be created on empty DB"
    return engine


def test_flows_upsert_same_identity_twice_aggregates(sqlite_engine):
    """Upserting the same flow identity twice should yield one row with incremented count_open."""
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from sqlalchemy import func

    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False, future=True)
    session = Session()

    identity = {
        "device": "fw1",
        "basis": "zone",
        "from_value": "inside",
        "to_value": "outside",
        "proto": "TCP",
        "dest_port": 443,
        "src_endpoint_id": 1,
        "dst_endpoint_id": 2,
        "view_kind": "original",
    }
    ts = datetime.now(timezone.utc)
    values = {
        **identity,
        "count_open": 1,
        "count_close": 0,
        "bytes_src_to_dst": 0,
        "bytes_dst_to_src": 0,
        "duration_total_s": 0,
        "first_seen": ts,
        "last_seen": ts,
        "top_rules": {},
        "top_apps": {},
    }
    ins = sqlite_insert(Flow)
    stmt = ins.values(**values).on_conflict_do_update(
        index_elements=list(identity.keys()),
        set_={
            Flow.count_open: Flow.count_open + 1,
            Flow.first_seen: func.min(Flow.first_seen, ins.excluded.first_seen),
            Flow.last_seen: func.max(Flow.last_seen, ins.excluded.last_seen),
        },
    )

    session.execute(stmt)
    session.execute(stmt)
    session.commit()

    rows = session.execute(select(Flow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].count_open == 2
    assert rows[0].device == "fw1"
    assert rows[0].basis == "zone"
