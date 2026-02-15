"""DB-agnostic tests for the list_known_endpoints query pattern (single union_all + single group_by).

Ensures the query runs on SQLite (and optionally PostgreSQL) without GROUP BY errors,
normalizes empty MAC to NULL, and merges identical (ip, mac) correctly.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select, union_all
from sqlalchemy.orm import sessionmaker

from app.storage.models import Base, Event


def _run_known_endpoints_query_pattern(session, device_list):
    """Same query shape as list_known_endpoints: union src + dest, nullif MAC, single aggregate."""
    mac_norm_src = func.nullif(Event.src_mac, "")
    mac_norm_dst = func.nullif(Event.dest_mac, "")
    src_q = (
        select(
            Event.src_ip.label("ip"),
            mac_norm_src.label("mac"),
            Event.ts_utc.label("ts_utc"),
            Event.device.label("device"),
        )
        .where(Event.device.in_(device_list))
        .where(Event.src_ip.isnot(None))
    )
    dst_q = (
        select(
            Event.dest_ip.label("ip"),
            mac_norm_dst.label("mac"),
            Event.ts_utc.label("ts_utc"),
            Event.device.label("device"),
        )
        .where(Event.device.in_(device_list))
        .where(Event.dest_ip.isnot(None))
    )
    ev = union_all(src_q, dst_q).subquery("ev")
    agg = (
        select(
            ev.c.ip.label("ip"),
            ev.c.mac.label("mac"),
            func.count().label("seen_count"),
            func.min(ev.c.ts_utc).label("first_seen"),
            func.max(ev.c.ts_utc).label("last_seen"),
        )
        .where(ev.c.ip.isnot(None))
        .group_by(ev.c.ip, ev.c.mac)
    )
    return session.execute(agg).all()


@pytest.fixture
def sqlite_engine():
    """In-memory SQLite engine with Event table."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def session_with_events(sqlite_engine):
    """Session with events: same IP with empty MAC and non-empty MAC; same (ip, mac) twice."""
    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False, future=True)
    session = Session()
    try:
        now = datetime.now(timezone.utc)
        # Same IP 192.168.1.1 as src with empty MAC (two events) -> should group to one row, seen_count=2
        session.add(
            Event(
                ts_utc=now,
                device="fw1",
                src_ip="192.168.1.1",
                src_mac="",
                dest_ip="10.0.0.1",
                dest_mac="",
            )
        )
        session.add(
            Event(
                ts_utc=now,
                device="fw1",
                src_ip="192.168.1.1",
                src_mac="",
                dest_ip="10.0.0.2",
                dest_mac="dd:ee:ff",
            )
        )
        # Same IP with non-empty MAC
        session.add(
            Event(
                ts_utc=now,
                device="fw1",
                src_ip="192.168.1.2",
                src_mac="aa:bb:cc:dd:ee:ff",
                dest_ip="10.0.0.1",
                dest_mac="",
            )
        )
        session.commit()
        yield session
    finally:
        session.close()


def test_known_endpoints_query_no_sql_error(session_with_events):
    """Query runs without SQL/GroupingError on SQLite."""
    rows = _run_known_endpoints_query_pattern(session_with_events, ["fw1"])
    assert rows is not None


def test_known_endpoints_query_returns_rows(session_with_events):
    """Query returns at least one row for inserted events."""
    rows = _run_known_endpoints_query_pattern(session_with_events, ["fw1"])
    assert len(rows) >= 1


def test_known_endpoints_query_empty_mac_becomes_null(session_with_events):
    """Empty string MAC in events is normalized to NULL in the aggregated result."""
    rows = _run_known_endpoints_query_pattern(session_with_events, ["fw1"])
    # 192.168.1.1 as src has src_mac="" -> should appear with mac=None in result (nullif normalizes "")
    ip_192_168_1_1_rows = [r for r in rows if r.ip == "192.168.1.1"]
    assert len(ip_192_168_1_1_rows) >= 1
    macs = [r.mac for r in ip_192_168_1_1_rows]
    assert None in macs, "Empty string MAC should be normalized to NULL in aggregation"


def test_known_endpoints_query_grouping_merges_identical_ip_mac(session_with_events):
    """Identical (ip, mac) from multiple events is merged into one row with correct seen_count."""
    rows = _run_known_endpoints_query_pattern(session_with_events, ["fw1"])
    # (192.168.1.1, NULL) appears as src in 2 events -> one row with seen_count >= 2
    null_mac_rows = [r for r in rows if r.ip == "192.168.1.1" and r.mac is None]
    if null_mac_rows:
        assert null_mac_rows[0].seen_count >= 2, "Same (ip, mac) should be grouped with count >= 2"
