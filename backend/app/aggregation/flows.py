from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..config import AppConfig
from ..storage.models import Endpoint, Event, Flow
from ..storage.upsert import upsert_endpoint_safe

logger = logging.getLogger("netwall.flows")


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Return dt as timezone-aware UTC; if naive, assume UTC. Enables safe comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _get_or_create_endpoint(
    db: Session,
    device: str,
    ip: Optional[str],
    mac: Optional[str],
    device_name: Optional[str],
) -> Optional[Endpoint]:
    """Upsert endpoint (Core ON CONFLICT DO NOTHING) then SELECT; no flush. Idempotent for concurrent/HA."""
    if not ip:
        return None

    mac_norm = mac or None
    upsert_endpoint_safe(db, device=device, ip=ip, mac=mac_norm, device_name=device_name)
    stmt = select(Endpoint).where(
        Endpoint.device == device,
        Endpoint.ip == ip,
        Endpoint.mac.is_(mac_norm) if mac_norm is None else Endpoint.mac == mac_norm,
    ).limit(1)
    ep = db.execute(stmt).scalars().first()
    if ep and device_name and not ep.device_name:
        ep.device_name = device_name
    return ep


# Identity columns for flow uniqueness (must match Flow.__table_args__ UniqueConstraint).
_FLOW_IDENTITY = [
    "device",
    "basis",
    "from_value",
    "to_value",
    "proto",
    "dest_port",
    "src_endpoint_id",
    "dst_endpoint_id",
    "view_kind",
]


def _update_flow_row(
    db: Session,
    *,
    device: str,
    basis: str,
    from_value: Optional[str],
    to_value: Optional[str],
    proto: Optional[str],
    dest_port: Optional[int],
    src_ep_id: Optional[int],
    dst_ep_id: Optional[int],
    view_kind: str,
    event: Event,
) -> None:
    if not from_value or not to_value or src_ep_id is None or dst_ep_id is None:
        return

    event_ts = _ensure_utc(event.ts_utc)
    values = {
        "device": device,
        "basis": basis,
        "from_value": from_value,
        "to_value": to_value,
        "proto": proto,
        "dest_port": dest_port,
        "src_endpoint_id": src_ep_id,
        "dst_endpoint_id": dst_ep_id,
        "view_kind": view_kind,
        "count_open": 1,
        "count_close": 0,
        "bytes_src_to_dst": 0,
        "bytes_dst_to_src": 0,
        "duration_total_s": 0,
        "first_seen": event_ts,
        "last_seen": event_ts,
        "top_rules": {},
        "top_apps": {},
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        ins = pg_insert(Flow).values(**values)
        update_set = {
            Flow.count_open: Flow.count_open + 1,
            Flow.first_seen: func.least(Flow.first_seen, ins.excluded.first_seen),
            Flow.last_seen: func.greatest(Flow.last_seen, ins.excluded.last_seen),
        }
        stmt = ins.on_conflict_do_update(constraint="ux_flows_identity", set_=update_set)
    else:
        ins = sqlite_insert(Flow).values(**values)
        update_set = {
            Flow.count_open: Flow.count_open + 1,
            Flow.first_seen: func.min(Flow.first_seen, ins.excluded.first_seen),
            Flow.last_seen: func.max(Flow.last_seen, ins.excluded.last_seen),
        }
        stmt = ins.on_conflict_do_update(index_elements=_FLOW_IDENTITY, set_=update_set)
    db.execute(stmt)
    # Do not flush here; let the outer transaction flush/commit once per batch.

    # Merge rule/app counts (not expressible in SQLite upsert). Limit 1 to avoid MultipleResultsFound if duplicates exist before dedup.
    flow = db.execute(
        select(Flow)
        .where(
            Flow.device == device,
            Flow.basis == basis,
            Flow.from_value == from_value,
            Flow.to_value == to_value,
            Flow.proto == proto,
            Flow.dest_port == dest_port,
            Flow.src_endpoint_id == src_ep_id,
            Flow.dst_endpoint_id == dst_ep_id,
            Flow.view_kind == view_kind,
        )
        .limit(1)
    ).scalars().first()
    if flow:
        if event.rule:
            flow.top_rules[event.rule] = flow.top_rules.get(event.rule, 0) + 1
        if event.app_name:
            flow.top_apps[event.app_name] = flow.top_apps.get(event.app_name, 0) + 1


def _ensure_endpoints_for_event(
    db: Session,
    event: Event,
) -> tuple:
    """Get or create (upsert + select, no flush) the four endpoints for an event. Returns (src_orig, dst_orig, src_nat, dst_nat).
    Uses event.firewall_key when available for HA (one device key per cluster).
    """
    device = event.firewall_key if getattr(event, "firewall_key", None) else event.device
    src_orig = _get_or_create_endpoint(
        db,
        device=device,
        ip=event.src_ip,
        mac=event.src_mac,
        device_name=event.src_device,
    )
    dst_orig = _get_or_create_endpoint(
        db,
        device=device,
        ip=event.dest_ip,
        mac=event.dest_mac,
        device_name=event.dest_device,
    )
    src_ip_nat = event.xlat_src_ip or event.src_ip
    dst_ip_nat = event.xlat_dest_ip or event.dest_ip
    src_nat = _get_or_create_endpoint(
        db,
        device=device,
        ip=src_ip_nat,
        mac=event.src_mac,
        device_name=event.src_device,
    )
    dst_nat = _get_or_create_endpoint(
        db,
        device=device,
        ip=dst_ip_nat,
        mac=event.dest_mac,
        device_name=event.dest_device,
    )
    return (src_orig, dst_orig, src_nat, dst_nat)


def _add_flow_rows_for_event(
    db: Session,
    event: Event,
    src_orig: Optional[Endpoint],
    dst_orig: Optional[Endpoint],
    src_nat: Optional[Endpoint],
    dst_nat: Optional[Endpoint],
) -> None:
    """Write flow rows for one event. Endpoints must have .id (from upsert+select, no flush)."""
    flow_device = event.firewall_key if getattr(event, "firewall_key", None) else event.device
    bases = [
        ("side", event.recv_side, event.dest_side),
        ("zone", event.recv_zone, event.dest_zone),
        ("interface", event.recv_if, event.dest_if),
    ]
    for view_kind, src_ep, dst_ep in [
        ("original", src_orig, dst_orig),
        ("translated", src_nat, dst_nat),
    ]:
        if src_ep is None or dst_ep is None:
            continue
        if src_ep.id is None or dst_ep.id is None:
            continue
        for basis, from_val, to_val in bases:
            _update_flow_row(
                db,
                device=flow_device,
                basis=basis,
                from_value=from_val,
                to_value=to_val,
                proto=event.proto,
                dest_port=event.dest_port,
                src_ep_id=src_ep.id,
                dst_ep_id=dst_ep.id,
                view_kind=view_kind,
                event=event,
            )


def update_flows_for_events_batch(
    db: Session,
    events: list[Event],
    config: AppConfig,
) -> None:
    """Update aggregated flows for a batch of events. No flush; endpoints from upsert+select. Safe for use from ingest batch."""
    if not events:
        return
    # 1) Get or create all endpoints (add only, no flush)
    endpoint_tuples = []
    for event in events:
        if event.event_type not in {"conn_open", "conn_open_natsat"}:
            endpoint_tuples.append(None)
            continue
        endpoint_tuples.append(_ensure_endpoints_for_event(db, event))
    # 2) No flush; endpoints already have IDs from upsert+select in _get_or_create_endpoint
    # 3) Add flow rows (no flush)
    for event, eps in zip(events, endpoint_tuples):
        if event.event_type not in {"conn_open", "conn_open_natsat"}:
            continue
        if eps is None:
            continue
        src_orig, dst_orig, src_nat, dst_nat = eps
        _add_flow_rows_for_event(db, event, src_orig, dst_orig, src_nat, dst_nat)


def update_flows_for_event(db: Session, event: Event, config: AppConfig) -> None:
    """Update aggregated flows for a single event. No flush; endpoints from upsert+select."""
    if event.event_type not in {"conn_open", "conn_open_natsat"}:
        return
    src_orig, dst_orig, src_nat, dst_nat = _ensure_endpoints_for_event(db, event)
    _add_flow_rows_for_event(db, event, src_orig, dst_orig, src_nat, dst_nat)

