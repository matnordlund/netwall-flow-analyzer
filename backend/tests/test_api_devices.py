"""Test GET /api/devices returns only distinct device names from ingested events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app.api.routes_zones import list_devices, list_endpoints
from app.config import AppConfig
from app.main import create_app
from app.storage import models


@pytest.fixture
def app_with_two_devices(tmp_path: Path):
    """App with SQLite and two events: device=gw-mand-slave, device=fw2."""
    db_file = tmp_path / "test_devices.db"
    config = AppConfig(database_url=f"sqlite:///{db_file}")
    app = create_app(config)
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    models.Base.metadata.create_all(bind=engine)
    app.state.db_engine = engine
    app.state.db_sessionmaker = session_factory

    session = session_factory()
    try:
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="gw-mand-slave",
            )
        )
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
            )
        )
        session.commit()
    finally:
        session.close()

    return app


def test_api_devices_returns_only_devices_from_ingested_events(app_with_two_devices):
    """GET /api/devices returns exactly the devices that have events; no default/hardcoded value."""
    # Call the route handler directly with our app so it uses the fixture's DB
    scope = {"type": "http", "method": "GET", "path": "/api/devices", "app": app_with_two_devices}
    request = Request(scope)
    devices = list_devices(request)
    assert isinstance(devices, list)
    assert sorted(devices) == ["fw2", "gw-mand-slave"], (
        f"list_devices returned {devices}; expected ['fw2', 'gw-mand-slave']."
    )
    # Regression: must not return any default/hardcoded device (e.g. "g", "fw1", "unknown").
    assert "g" not in devices
    assert "unknown" not in devices


def test_api_endpoints_returns_full_zone_and_interface_names_excludes_empty(app_with_two_devices):
    """GET /api/endpoints returns full zone/interface names; empty string is not included."""
    # Add events with zone and interface names (and one with empty zone)
    session_factory = app_with_two_devices.state.db_sessionmaker
    with session_factory() as session:
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_zone="dmz",
                dest_zone="trust",
            )
        )
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_zone="",
                dest_zone="trust",
            )
        )
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_if="eth0",
                dest_if="eth1",
            )
        )
        session.commit()

    scope = {"type": "http", "method": "GET", "path": "/api/endpoints", "app": app_with_two_devices}
    request = Request(scope)

    zones = list_endpoints(request, device="fw2", kind="zone")
    assert sorted(zones) == ["dmz", "trust"], f"zones: got {zones}; empty must not appear"
    assert "" not in zones

    interfaces = list_endpoints(request, device="fw2", kind="interface")
    assert sorted(interfaces) == ["eth0", "eth1"], f"interfaces: got {interfaces}; full names required"
    assert "" not in interfaces


def test_api_endpoints_excludes_malformed_zone_values(app_with_two_devices):
    """Zone dropdown must not include empty quote, leading-quote partials like \"LANZ, only clean names."""
    session_factory = app_with_two_devices.state.db_sessionmaker
    with session_factory() as session:
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_zone="LANZone",
                dest_zone="WANZone",
            )
        )
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_zone='"',
                dest_zone="WANZone",
            )
        )
        session.add(
            models.Event(
                ts_utc=datetime.now(timezone.utc),
                device="fw2",
                recv_zone='"LANZ',
                dest_zone='"LANZon',
            )
        )
        session.commit()

    scope = {"type": "http", "method": "GET", "path": "/api/endpoints", "app": app_with_two_devices}
    request = Request(scope)
    zones = list_endpoints(request, device="fw2", kind="zone")

    assert sorted(zones) == ["LANZone", "WANZone"], f"zones: got {zones}; expected only LANZone, WANZone"
    assert "" not in zones
    assert '"' not in zones
    assert '"LANZ' not in zones
    assert '"LANZon' not in zones
