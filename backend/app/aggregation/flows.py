from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy import func

from ..config import AppConfig
from ..storage.models import Endpoint, Event, Flow

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
    if not ip:
        return None

    mac_norm = mac or None
    stmt = select(Endpoint).where(
        Endpoint.device == device,
        Endpoint.ip == ip,
        Endpoint.mac.is_(mac_norm) if mac_norm is None else Endpoint.mac == mac_norm,
    )
    ep = db.execute(stmt).scalar_one_or_none()
    if ep is None:
        ep = Endpoint(device=device, ip=ip, mac=mac_norm, device_name=device_name)
        db.add(ep)
        db.flush()
    else:
        # Backfill device_name if we learn it later.
        if device_name and not ep.device_name:
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
    ins = sqlite_insert(Flow)
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
    stmt = ins.values(**values).on_conflict_do_update(
        index_elements=_FLOW_IDENTITY,
        set_={
            Flow.count_open: Flow.count_open + 1,
            Flow.first_seen: func.min(Flow.first_seen, ins.excluded.first_seen),
            Flow.last_seen: func.max(Flow.last_seen, ins.excluded.last_seen),
        },
    )
    db.execute(stmt)
    db.flush()

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


def update_flows_for_event(db: Session, event: Event, config: AppConfig) -> None:
    """Update aggregated flows for a single event.

    We currently only aggregate conn_open and conn_open_natsat events.
    """
    if event.event_type not in {"conn_open", "conn_open_natsat"}:
        return

    # Original vs translated endpoints.
    # Original
    src_orig = _get_or_create_endpoint(
        db,
        device=event.device,
        ip=event.src_ip,
        mac=event.src_mac,
        device_name=event.src_device,
    )
    dst_orig = _get_or_create_endpoint(
        db,
        device=event.device,
        ip=event.dest_ip,
        mac=event.dest_mac,
        device_name=event.dest_device,
    )

    # Translated (prefer NAT IPs when present).
    src_ip_nat = event.xlat_src_ip or event.src_ip
    dst_ip_nat = event.xlat_dest_ip or event.dest_ip
    src_nat = _get_or_create_endpoint(
        db,
        device=event.device,
        ip=src_ip_nat,
        mac=event.src_mac,
        device_name=event.src_device,
    )
    dst_nat = _get_or_create_endpoint(
        db,
        device=event.device,
        ip=dst_ip_nat,
        mac=event.dest_mac,
        device_name=event.dest_device,
    )

    # Basis values: side, zone, interface.
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
        for basis, from_val, to_val in bases:
            _update_flow_row(
                db,
                device=event.device,
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

