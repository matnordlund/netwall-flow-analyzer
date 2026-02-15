"""Regression tests for unclassified_endpoints UPSERT (no UNIQUE constraint on repeated ingest)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.enrichment.classification import _record_unclassified
from app.storage.models import Base, UnclassifiedEndpoint


@pytest.fixture
def sqlite_engine():
    """In-memory SQLite engine with unclassified_endpoints table."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return engine


def test_unclassified_endpoints_upsert_same_key_twice_one_row_count_two(sqlite_engine):
    """Recording the same (device, kind, name) twice via _record_unclassified yields one row with count=2."""
    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        _record_unclassified(db, device="gw1", kind="interface", name="ocvpn_if", inc=1)
        _record_unclassified(db, device="gw1", kind="interface", name="ocvpn_if", inc=1)
        db.commit()

        rows = db.execute(
            select(UnclassifiedEndpoint).where(
                UnclassifiedEndpoint.device == "gw1",
                UnclassifiedEndpoint.kind == "interface",
                UnclassifiedEndpoint.name == "ocvpn_if",
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].count == 2
    finally:
        db.close()


def test_unclassified_endpoints_upsert_increment_accumulates(sqlite_engine):
    """Multiple upserts with inc=1 accumulate count; no UNIQUE violation."""
    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        for _ in range(5):
            _record_unclassified(db, device="fw2", kind="zone", name="untrust", inc=1)
        db.commit()

        rows = db.execute(
            select(UnclassifiedEndpoint).where(
                UnclassifiedEndpoint.device == "fw2",
                UnclassifiedEndpoint.kind == "zone",
                UnclassifiedEndpoint.name == "untrust",
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].count == 5
    finally:
        db.close()
