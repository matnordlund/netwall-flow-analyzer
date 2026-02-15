"""Regression test: import flow aggregation must not perform flush inside an ongoing flush.

Ensures update_flows_for_events_batch and helpers (_get_or_create_endpoint, _update_flow_row)
do not call Session.flush() in a re-entrant way, which would raise
"Session is already flushing" and crash the worker.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.aggregation.flows import update_flows_for_events_batch
from app.config import AppConfig
from app.storage.flow_index import ensure_flows_unique_index
from app.storage.models import Base, Event


@pytest.fixture
def sqlite_engine():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    ensure_flows_unique_index(engine)
    return engine


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


def _make_event(
    device: str = "test-fw",
    src_ip: str = "10.0.0.1",
    dest_ip: str = "10.0.0.2",
    ts: datetime | None = None,
) -> Event:
    ts = ts or datetime.now(timezone.utc)
    return Event(
        ts_utc=ts,
        device=device,
        event_type="conn_open_natsat",
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_mac="AA-BB-CC-DD-EE-01",
        dest_mac="AA-BB-CC-DD-EE-02",
        recv_side="inside",
        dest_side="outside",
        recv_zone="lan",
        dest_zone="wan",
        recv_if="lan",
        dest_if="wan",
        proto="TCP",
        dest_port=443,
    )


def test_update_flows_for_events_batch_no_flush_in_flush(sqlite_engine, config):
    """Calling update_flows_for_events_batch must complete without 'Session is already flushing'."""
    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False, future=True)
    session = Session()
    try:
        events = [
            _make_event(src_ip="10.0.0.1", dest_ip="10.0.0.2"),
            _make_event(src_ip="10.0.0.3", dest_ip="10.0.0.4"),
        ]
        # Should not raise (e.g. InvalidRequestError: Session is already flushing)
        update_flows_for_events_batch(session, events, config)
        session.commit()
    finally:
        session.close()
