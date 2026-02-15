from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, or_, select, tuple_
from sqlalchemy.orm import Session

from ..api.device_resolve import resolve_device
from ..ingest.reconstruct import normalize_mac as _normalize_mac
from ..storage.models import DeviceIdentification, DeviceOverride, Endpoint, Event, Flow, RawLog, RouterMac

router = APIRouter(prefix="/graph", tags=["graph"])


def _segment_id_from_key(segment_key: str) -> str:
    """Stable node id for a segment (zone/interface hop)."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", (segment_key or "").strip()) or "unknown"
    return "segment-" + safe.strip("_")

# Default time range (minutes) when not provided for backward compat.
DEFAULT_TIME_MINUTES = 60


def get_db(request: Request) -> Session:
    SessionLocal = request.app.state.db_sessionmaker
    return SessionLocal()


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _canonical_endpoint_key(side: str, ip: Optional[str], mac: Optional[str]) -> str:
    """Stable node key for an endpoint when aggregating HA members. Same (ip, mac) => same key.
    Use for left/right nodes so the same endpoint from Master and Slave merges into one."""
    norm_mac = _normalize_mac(mac) if mac and str(mac).strip() else None
    if norm_mac:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", norm_mac)
        return f"{side}:mac:{safe}"
    ip_val = (ip or "").strip() or "unknown"
    safe_ip = re.sub(r"[^a-zA-Z0-9._-]", "_", ip_val)
    return f"{side}:ip:{safe_ip}"


def _endpoint_has_mac(ep: Optional[Endpoint]) -> bool:
    """True if endpoint has a non-empty MAC; such devices are always shown as direct next hop from the firewall, not via router."""
    if ep is None:
        return False
    if ep.mac is None:
        return False
    return bool(str(ep.mac).strip())


def _get_endpoint_by_device_ip_mac(
    db: Session, device: str, ip: Optional[str], mac: Optional[str]
) -> Optional[Endpoint]:
    if not ip:
        return None
    mac_norm = mac or None
    stmt = select(Endpoint).where(
        Endpoint.device == device,
        Endpoint.ip == ip,
        Endpoint.mac.is_(mac_norm) if mac_norm is None else Endpoint.mac == mac_norm,
    )
    return db.execute(stmt).scalar_one_or_none()


def _event_matches_src(
    event: Event,
    src_kind: str,
    src_value: str,
    src_endpoint: Optional[Endpoint] = None,
) -> bool:
    if src_kind == "side":
        return (event.recv_side or "") == src_value
    if src_kind == "zone":
        return (event.recv_zone or "") == src_value
    if src_kind == "interface":
        return (event.recv_if or "") == src_value
    if src_kind == "endpoint" and src_endpoint is not None:
        return (event.src_ip or "") == (src_endpoint.ip or "") and (
            (event.src_mac or "") == (src_endpoint.mac or "")
        )
    return False


def _event_matches_dst(
    event: Event,
    dst_kind: str,
    dst_value: str,
    dst_endpoint: Optional[Endpoint] = None,
) -> bool:
    if dst_kind == "any":
        return True
    if dst_kind == "side":
        return (event.dest_side or "") == dst_value
    if dst_kind == "zone":
        return (event.dest_zone or "") == dst_value
    if dst_kind == "interface":
        return (event.dest_if or "") == dst_value
    if dst_kind == "endpoint" and dst_endpoint is not None:
        return (event.dest_ip or "") == (dst_endpoint.ip or "") and (
            (event.dest_mac or "") == (dst_endpoint.mac or "")
        )
    return False


TOP_SERVICES_N = 10
TOP_SOURCES_N = 10
TOP_SERVICES_PER_SOURCE = 10


def _build_source_breakdown_per_dest(
    db: Session,
    device_list: List[str],
    filtered_open: List[Event],
    src_kind: str,
    src_value: str,
    dst_kind: str,
    dst_value: str,
    time_from: Optional[datetime],
    time_to: Optional[datetime],
    view: str,
    ep_cache: Dict[Tuple[str, str, Optional[str]], Optional[Endpoint]],
    src_endpoint: Optional[Endpoint],
    dst_endpoint: Optional[Endpoint],
    endpoints: Dict[int, Endpoint],
) -> Dict[int, List[Dict[str, Any]]]:
    """Per-destination list of sources with their services. Prefer conn_close for app_name; include conn_open when no close."""
    def get_ep(dev: str, ip: Optional[str], mac: Optional[str]) -> Optional[Endpoint]:
        if not ip:
            return None
        key = (dev, ip, mac or None)
        if key not in ep_cache:
            ep_cache[key] = _get_endpoint_by_device_ip_mac(db, dev, ip, mac)
        return ep_cache[key]

    # Key: (dst_ep_id, src_ep_id, proto, port) -> close_count, open_count, app_name_counts (for mode)
    # We store app_name -> count from close events to pick mode later
    merged: Dict[Tuple[int, int, str, int], Dict[str, Any]] = {}

    # 1) conn_close*: primary, have app_name
    stmt_close = (
        select(Event)
        .where(Event.device.in_(device_list))
        .where(Event.event_type.in_({"conn_close", "conn_close_natsat"}))
    )
    if time_from is not None:
        stmt_close = stmt_close.where(Event.ts_utc >= time_from)
    if time_to is not None:
        stmt_close = stmt_close.where(Event.ts_utc <= time_to)
    close_events: List[Event] = db.execute(stmt_close).scalars().all()
    close_filtered = [
        e
        for e in close_events
        if _event_matches_src(e, src_kind, src_value, src_endpoint)
        and _event_matches_dst(e, dst_kind, dst_value, dst_endpoint)
    ]
    for e in close_filtered:
        if view == "translated":
            src_ip = e.xlat_src_ip or e.src_ip
            dst_ip = e.xlat_dest_ip or e.dest_ip
            port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
        else:
            src_ip = e.src_ip
            dst_ip = e.dest_ip
            port = e.dest_port or 0
        src_ep = get_ep(e.device, src_ip, e.src_mac)
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if src_ep is None or dst_ep is None:
            continue
        proto = (e.proto or "").strip() or "ip"
        app_norm: Optional[str] = (e.app_name or "").strip() or None
        key = (dst_ep.id, src_ep.id, proto, port)
        if key not in merged:
            merged[key] = {"close_count": 0, "open_count": 0, "app_counts": {}}
        merged[key]["close_count"] += 1
        if app_norm is not None:
            merged[key]["app_counts"][app_norm] = merged[key]["app_counts"].get(app_norm, 0) + 1

    # 2) conn_open*: fallback, no app_name
    for e in filtered_open:
        if view == "translated":
            src_ip = e.xlat_src_ip or e.src_ip
            dst_ip = e.xlat_dest_ip or e.dest_ip
            port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
        else:
            src_ip = e.src_ip
            dst_ip = e.dest_ip
            port = e.dest_port or 0
        src_ep = get_ep(e.device, src_ip, e.src_mac)
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if src_ep is None or dst_ep is None:
            continue
        proto = (e.proto or "").strip() or "ip"
        key = (dst_ep.id, src_ep.id, proto, port)
        if key not in merged:
            merged[key] = {"close_count": 0, "open_count": 0, "app_counts": {}}
        merged[key]["open_count"] += 1

    # 3) Build output: choose app_name from close (mode or first non-empty)
    def choose_app(app_counts: Dict[str, int]) -> Optional[str]:
        if not app_counts:
            return None
        # Most frequent non-empty
        best_name: Optional[str] = None
        best_count = 0
        for name, cnt in app_counts.items():
            if name and cnt > best_count:
                best_count = cnt
                best_name = name
        return best_name

    # Group by (dst_ep_id, src_ep_id) -> list of services
    by_dst_src: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
    for (dst_ep_id, src_ep_id, proto, port), row in merged.items():
        close_count = row["close_count"]
        open_count = row["open_count"]
        count_total = close_count + open_count
        app_name = choose_app(row["app_counts"]) if close_count > 0 else None
        svc = {
            "proto": proto,
            "port": port,
            "app_name": app_name,
            "count": count_total,
            "count_total": count_total,
            "count_close": close_count,
            "count_open": open_count,
        }
        key_ds = (dst_ep_id, src_ep_id)
        if key_ds not in by_dst_src:
            by_dst_src[key_ds] = []
        by_dst_src[key_ds].append(svc)

    result: Dict[int, List[Dict[str, Any]]] = {}
    for (dst_ep_id, src_ep_id), services_list in by_dst_src.items():
        src_ep = endpoints.get(src_ep_id)
        if not src_ep:
            continue
        source_id = f"left-{src_ep_id}"
        source_label = src_ep.device_name or src_ep.ip or str(src_ep_id)
        src_ip = (src_ep.ip or "").strip()
        src_mac = (src_ep.mac or "").strip() or None
        services_list.sort(key=lambda x: -x["count_total"])
        services_list = services_list[:TOP_SERVICES_PER_SOURCE]
        entry = {
            "source_id": source_id,
            "source_label": source_label,
            "src_ip": src_ip,
            "src_mac": src_mac,
            "services": services_list,
        }
        if dst_ep_id not in result:
            result[dst_ep_id] = []
        result[dst_ep_id].append(entry)

    def _total_key(e: dict) -> int:
        return sum(s["count_total"] for s in e["services"])

    for dst_ep_id in result:
        result[dst_ep_id].sort(key=_total_key, reverse=True)
        result[dst_ep_id] = result[dst_ep_id][:TOP_SOURCES_N]

    return result


def _build_services_per_dest(
    db: Session,
    device_list: List[str],
    filtered_open: List[Event],
    src_kind: str,
    src_value: str,
    dst_kind: str,
    dst_value: str,
    time_from: Optional[datetime],
    time_to: Optional[datetime],
    view: str,
    ep_cache: Dict[Tuple[str, str, Optional[str]], Optional[Endpoint]],
    src_endpoint: Optional[Endpoint],
    dst_endpoint: Optional[Endpoint],
) -> Dict[int, List[Dict[str, Any]]]:
    """Build services list per destination endpoint (right-side). Prefer conn_close* for app_name."""
    def get_ep(dev: str, ip: Optional[str], mac: Optional[str]) -> Optional[Endpoint]:
        if not ip:
            return None
        key = (dev, ip, mac or None)
        if key not in ep_cache:
            ep_cache[key] = _get_endpoint_by_device_ip_mac(db, dev, ip, mac)
        return ep_cache[key]

    # Close events: better metadata (app_name)
    stmt_close = (
        select(Event)
        .where(Event.device.in_(device_list))
        .where(Event.event_type.in_({"conn_close", "conn_close_natsat"}))
    )
    if time_from is not None:
        stmt_close = stmt_close.where(Event.ts_utc >= time_from)
    if time_to is not None:
        stmt_close = stmt_close.where(Event.ts_utc <= time_to)
    close_events: List[Event] = db.execute(stmt_close).scalars().all()
    close_filtered = [
        e
        for e in close_events
        if _event_matches_src(e, src_kind, src_value, src_endpoint)
        and _event_matches_dst(e, dst_kind, dst_value, dst_endpoint)
    ]

    # Aggregate by (dst_ep_id, proto, port, app_name) for close events
    # app_name: treat empty/missing as None
    svc_close: Dict[Tuple[int, str, int, Optional[str]], Dict[str, Any]] = {}
    for e in close_filtered:
        if view == "translated":
            dst_ip = e.xlat_dest_ip or e.dest_ip
            port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
        else:
            dst_ip = e.dest_ip
            port = e.dest_port or 0
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if dst_ep is None:
            continue
        proto = (e.proto or "").strip() or "ip"
        app_norm: Optional[str] = (e.app_name or "").strip() or None
        key = (dst_ep.id, proto, port, app_norm)
        if key not in svc_close:
            svc_close[key] = {"count": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0}
        svc_close[key]["count"] += 1
        svc_close[key]["bytes_src_to_dst"] += e.bytes_orig or 0
        svc_close[key]["bytes_dst_to_src"] += e.bytes_term or 0

    # Aggregate by (dst_ep_id, proto, port) for open events (fallback when no close for that ep)
    svc_open_fallback: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
    for e in filtered_open:
        if view == "translated":
            dst_ip = e.xlat_dest_ip or e.dest_ip
            port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
        else:
            dst_ip = e.dest_ip
            port = e.dest_port or 0
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if dst_ep is None:
            continue
        proto = (e.proto or "").strip() or "ip"
        key = (dst_ep.id, proto, port)
        if key not in svc_open_fallback:
            svc_open_fallback[key] = {"count": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0}
        svc_open_fallback[key]["count"] += 1
        svc_open_fallback[key]["bytes_src_to_dst"] += e.bytes_orig or 0
        svc_open_fallback[key]["bytes_dst_to_src"] += e.bytes_term or 0

    # Build per-ep list: prefer close data; fallback to open (no app_name)
    dst_ep_ids_with_close = {k[0] for k in svc_close}
    result: Dict[int, List[Dict[str, Any]]] = {}

    for key, row in svc_close.items():
        dst_ep_id, proto, port, app_name = key
        if dst_ep_id not in result:
            result[dst_ep_id] = []
        result[dst_ep_id].append({
            "proto": proto,
            "port": port,
            "app_name": app_name,
            "count": row["count"],
            "bytes_src_to_dst": row["bytes_src_to_dst"],
            "bytes_dst_to_src": row["bytes_dst_to_src"],
        })

    for (dst_ep_id, proto, port), row in svc_open_fallback.items():
        if dst_ep_id in dst_ep_ids_with_close:
            continue
        if dst_ep_id not in result:
            result[dst_ep_id] = []
        result[dst_ep_id].append({
            "proto": proto,
            "port": port,
            "app_name": None,
            "count": row["count"],
            "bytes_src_to_dst": row["bytes_src_to_dst"],
            "bytes_dst_to_src": row["bytes_dst_to_src"],
        })

    # Sort by count desc, take top N; attach services_total on first item
    for ep_id in result:
        result[ep_id].sort(key=lambda x: (-x["count"], -((x.get("bytes_src_to_dst") or 0) + (x.get("bytes_dst_to_src") or 0))))
        total = len(result[ep_id])
        result[ep_id] = result[ep_id][:TOP_SERVICES_N]
        if result[ep_id]:
            result[ep_id][0]["services_total"] = total

    return result


@router.get("")
def get_graph(
    request: Request,
    device: Optional[str] = Query(None, description="Source firewall (required for Analyze)"),
    src_kind: Optional[str] = Query(None, pattern="^(side|zone|interface|endpoint)$"),
    src_value: Optional[str] = Query(None),
    dst_kind: Optional[str] = Query(None, pattern="^(side|zone|interface|endpoint|any)$"),
    dst_value: Optional[str] = Query(None),
    time_from: Optional[datetime] = Query(None, description="ISO8601"),
    time_to: Optional[datetime] = Query(None, description="ISO8601"),
    view: str = Query("original", pattern="^(original|translated)$"),
    dest_view: str = Query("endpoints", pattern="^(endpoints|services)$", description="Right side: endpoints (zones/interfaces/devices) or services (proto/port/app)"),
    basis: str = Query("side", pattern="^(side|zone|interface)$"),
    from_: str = Query("inside", alias="from"),
    to: str = Query("outside"),
    time_start: Optional[datetime] = None,
    time_end: Optional[datetime] = None,
    metric: str = Query("count", pattern="^(count|bytes)$"),
    split: str = Query("merged"),
) -> Dict[str, Any]:
    """Return aggregated graph. Use device/src_kind/src_value/dst_kind/dst_value/time_from/time_to for Dashboard Analyze."""
    db = get_db(request)
    try:
        use_event_query = (
            device is not None
            and src_kind is not None
            and src_value is not None
            and dst_kind is not None
            and (dst_value is not None or dst_kind == "any")
            and time_from is not None
            and time_to is not None
        )

        if use_event_query:
            device_list, device_label = resolve_device(db, device)
            if not device_list:
                return {
                    "meta": {
                        "device": device,
                        "device_label": device_label or device,
                        "src_kind": src_kind,
                        "src_value": src_value,
                        "dst_kind": dst_kind,
                        "dst_value": dst_value or "",
                        "time_from": time_from.isoformat() if time_from else None,
                        "time_to": time_to.isoformat() if time_to else None,
                        "view": view,
                        "left_count": 0,
                        "right_count": 0,
                        "unknown_endpoints": 0,
                        "router_mac_rules": 0,
                    },
                    "left_nodes": [],
                    "interface_groups": [],
                    "service_port_nodes": [],
                    "service_app_nodes": [],
                    "router_bucket_left": {"node_id": "router-left", "count": 0, "hidden_node_ids": [], "hidden_nodes": [], "hidden_edges": []},
                    "edges": [],
                    "dest_view": dest_view,
                }
            return _get_graph_from_events(
                db,
                device_list=device_list,
                device_label=device_label or device_list[0],
                src_kind=src_kind,
                src_value=src_value,
                dst_kind=dst_kind,
                dst_value=dst_value or "",
                time_from=_ensure_utc(time_from),
                time_to=_ensure_utc(time_to),
                view=view,
                dest_view=dest_view,
            )

        # Legacy: Flow-based query
        stmt = select(Flow).where(
            Flow.basis == basis,
            Flow.from_value == from_,
            Flow.to_value == to,
            Flow.view_kind == view,
        )
        if time_start is not None:
            stmt = stmt.where(Flow.last_seen >= _ensure_utc(time_start))
        if time_end is not None:
            stmt = stmt.where(Flow.first_seen <= _ensure_utc(time_end))
        flows: List[Flow] = db.execute(stmt).scalars().all()
        return _flows_to_response(flows, db, basis, from_, to, view, time_start, time_end, metric, split)
    finally:
        db.close()


def _is_valid_ip(s: str) -> bool:
    """Return True if s is a valid IPv4 or IPv6 address."""
    if not s or not str(s).strip():
        return False
    try:
        import ipaddress
        ipaddress.ip_address(str(s).strip())
        return True
    except ValueError:
        return False


@router.get("/inspect-logs")
def get_inspect_logs(
    request: Request,
    device: str = Query(..., description="Firewall device or ha:base"),
    time_from: Optional[datetime] = Query(None, description="ISO8601"),
    time_to: Optional[datetime] = Query(None, description="ISO8601"),
    view: str = Query("original", pattern="^(original|translated)$"),
    proto: str = Query(..., description="TCP or UDP"),
    dest_port: int = Query(..., ge=0, le=65535),
    app_name: Optional[str] = Query(None),
    src_ip: str = Query(..., description="Source IP (required; must be a valid IP address)"),
    dest_ip: str = Query(..., description="Destination IP (required; must be a valid IP address)"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Return raw event rows (and raw log line when available) for a given service + source + destination.
    Uses same view logic as graph: original = src_ip/dest_ip/dest_port, translated = xlat_* where present.
    """
    if not _is_valid_ip(src_ip):
        raise HTTPException(status_code=400, detail="src_ip must be a valid IP address")
    if not _is_valid_ip(dest_ip):
        raise HTTPException(status_code=400, detail="dest_ip must be a valid IP address")
    db = get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return {"rows": [], "total": 0}
        time_from = _ensure_utc(time_from)
        time_to = _ensure_utc(time_to)
        if time_from is None or time_to is None:
            return {"rows": [], "total": 0}

        proto_upper = (proto or "").strip().upper() or "TCP"
        stmt = (
            select(Event)
            .where(Event.device.in_(device_list))
            .where(Event.ts_utc >= time_from)
            .where(Event.ts_utc <= time_to)
            .where(Event.event_type.in_({"conn_open", "conn_open_natsat", "conn_close", "conn_close_natsat"}))
        )
        if view == "translated":
            stmt = stmt.where(
                or_(Event.xlat_src_ip == src_ip, Event.src_ip == src_ip),
                or_(Event.xlat_dest_ip == dest_ip, Event.dest_ip == dest_ip),
                or_(Event.xlat_dest_port == dest_port, Event.dest_port == dest_port),
            )
        else:
            stmt = stmt.where(Event.src_ip == src_ip, Event.dest_ip == dest_ip, Event.dest_port == dest_port)
        stmt = stmt.where((Event.proto == proto_upper) | (Event.proto.is_(None)))
        if app_name and str(app_name).strip():
            stmt = stmt.where((Event.app_name == app_name) | (Event.app_name == str(app_name).strip()))
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total: int = db.execute(count_stmt).scalar() or 0
        stmt = stmt.order_by(Event.ts_utc.desc()).offset(offset).limit(limit)
        events: List[Event] = db.execute(stmt).scalars().all()

        # Optional: attach raw_record from raw_logs by (device, ts_utc)
        raw_by_key: Dict[Tuple[str, datetime], str] = {}
        if events:
            keys = [(e.device, e.ts_utc) for e in events]
            raw_stmt = select(RawLog.device, RawLog.ts_utc, RawLog.raw_record).where(
                tuple_(RawLog.device, RawLog.ts_utc).in_(keys)
            )
            for row in db.execute(raw_stmt).all():
                if row[2]:
                    raw_by_key[(row[0], row[1])] = row[2]

        def _iso(dt: Optional[datetime]) -> Optional[str]:
            if dt is None:
                return None
            if hasattr(dt, "isoformat"):
                return dt.isoformat()
            return str(dt)

        rows: List[Dict[str, Any]] = []
        for e in events:
            raw_line = raw_by_key.get((e.device, e.ts_utc))
            rows.append({
                "ts_utc": _iso(e.ts_utc),
                "device": e.device,
                "event_type": e.event_type or "",
                "proto": (e.proto or "").upper(),
                "src_ip": e.src_ip,
                "src_port": e.src_port,
                "dest_ip": e.dest_ip,
                "dest_port": e.dest_port,
                "recv_if": e.recv_if,
                "recv_zone": e.recv_zone,
                "dest_if": e.dest_if,
                "dest_zone": e.dest_zone,
                "rule": e.rule,
                "app_name": e.app_name,
                "bytes_orig": e.bytes_orig,
                "bytes_term": e.bytes_term,
                "duration_s": e.duration_s,
                "raw_line": raw_line,
            })
        return {"rows": rows, "total": total}
    finally:
        db.close()


def _app_name_by_flow_from_close(
    db: Session,
    device_list: List[str],
    time_from: Optional[datetime],
    time_to: Optional[datetime],
    view: str,
    get_ep: Any,
    _event_matches_src: Any,
    _event_matches_dst: Any,
    src_kind: str,
    src_value: str,
    dst_kind: str,
    dst_value: str,
    src_endpoint: Optional[Endpoint],
    dst_endpoint: Optional[Endpoint],
) -> Dict[Tuple[int, int, str, int], str]:
    """(src_ep_id, dst_ep_id, proto, port) -> app_name from conn_close events. Used for services view."""
    stmt = (
        select(Event)
        .where(Event.device.in_(device_list))
        .where(Event.event_type.in_({"conn_close", "conn_close_natsat"}))
    )
    if time_from is not None:
        stmt = stmt.where(Event.ts_utc >= time_from)
    if time_to is not None:
        stmt = stmt.where(Event.ts_utc <= time_to)
    close_events: List[Event] = db.execute(stmt).scalars().all()
    out: Dict[Tuple[int, int, str, int], str] = {}
    for e in close_events:
        if not _event_matches_src(e, src_kind, src_value, src_endpoint) or not _event_matches_dst(e, dst_kind, dst_value, dst_endpoint):
            continue
        if view == "translated":
            src_ip = e.xlat_src_ip or e.src_ip
            dst_ip = e.xlat_dest_ip or e.dest_ip
            port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
        else:
            src_ip = e.src_ip
            dst_ip = e.dest_ip
            port = e.dest_port or 0
        src_ep = get_ep(e.device, src_ip, e.src_mac)
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if src_ep is None or dst_ep is None:
            continue
        proto = ((e.proto or "").strip() or "ip").upper()
        app = (e.app_name or "").strip() or "-"
        key = (src_ep.id, dst_ep.id, proto, port)
        if key not in out:
            out[key] = app
    return out


def _get_graph_from_events(
    db: Session,
    *,
    device_list: List[str],
    device_label: str,
    src_kind: str,
    src_value: str,
    dst_kind: str,
    dst_value: str,
    time_from: Optional[datetime],
    time_to: Optional[datetime],
    view: str,
    dest_view: str = "endpoints",
) -> Dict[str, Any]:
    """Query events by filters and build graph. When dest_view=services, right side is service nodes; else interface/zone/endpoints."""
    stmt = (
        select(Event)
        .where(Event.device.in_(device_list))
        .where(Event.event_type.in_({"conn_open", "conn_open_natsat"}))
    )
    if time_from is not None:
        stmt = stmt.where(Event.ts_utc >= time_from)
    if time_to is not None:
        stmt = stmt.where(Event.ts_utc <= time_to)
    events: List[Event] = db.execute(stmt).scalars().all()

    # Resolve endpoint filters (endpoint may belong to any member device in HA)
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    if src_kind == "endpoint" and src_value:
        try:
            ep_id = int(src_value)
            src_endpoint = db.execute(
                select(Endpoint).where(Endpoint.id == ep_id, Endpoint.device.in_(device_list))
            ).scalar_one_or_none()
        except (ValueError, TypeError):
            pass
    if dst_kind == "endpoint" and dst_value:
        try:
            ep_id = int(dst_value)
            dst_endpoint = db.execute(
                select(Endpoint).where(Endpoint.id == ep_id, Endpoint.device.in_(device_list))
            ).scalar_one_or_none()
        except (ValueError, TypeError):
            pass

    # Filter in Python
    filtered = [
        e
        for e in events
        if _event_matches_src(e, src_kind, src_value, src_endpoint) and _event_matches_dst(e, dst_kind, dst_value or "", dst_endpoint)
    ]

    AggKey = Tuple[int, int]
    agg: Dict[AggKey, Dict[str, Any]] = {}
    ep_cache: Dict[Tuple[str, str, Optional[str]], Optional[Endpoint]] = {}

    def get_ep(dev: str, ip: Optional[str], mac: Optional[str]) -> Optional[Endpoint]:
        if not ip:
            return None
        key = (dev, ip, mac or None)
        if key not in ep_cache:
            ep_cache[key] = _get_endpoint_by_device_ip_mac(db, dev, ip, mac)
        return ep_cache[key]

    def _event_has_dest_mac(ev: Event) -> bool:
        return bool((ev.dest_mac or "").strip())

    def _event_has_src_mac(ev: Event) -> bool:
        return bool((ev.src_mac or "").strip())

    # ── Per-destination interface-group tracking ──
    # ig_key = "dest_if|dest_zone"
    dest_ep_ids_with_mac: set[int] = set()
    src_ep_ids_with_mac: set[int] = set()
    ig_key_by_dst_ep: Dict[int, str] = {}            # dst_ep.id -> ig_key
    ig_meta: Dict[str, Dict[str, str]] = {}           # ig_key -> { id, dest_if, dest_zone, label }
    ig_local_ep_ids: Dict[str, set[int]] = {}         # ig_key -> set of local (has mac) ep ids
    ig_router_ep_ids: Dict[str, set[int]] = {}        # ig_key -> set of router (no mac) ep ids

    for e in filtered:
        if view == "translated":
            src_ip = e.xlat_src_ip or e.src_ip
            dst_ip = e.xlat_dest_ip or e.dest_ip
        else:
            src_ip = e.src_ip
            dst_ip = e.dest_ip
        src_ep = get_ep(e.device, src_ip, e.src_mac)
        dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
        if src_ep is None or dst_ep is None:
            continue
        if _event_has_src_mac(e):
            src_ep_ids_with_mac.add(src_ep.id)
        if _event_has_dest_mac(e):
            dest_ep_ids_with_mac.add(dst_ep.id)

        # Aggregate (src, dst)
        key: AggKey = (src_ep.id, dst_ep.id)
        if key not in agg:
            agg[key] = {
                "count_open": 0, "count_close": 0,
                "bytes_src_to_dst": 0, "bytes_dst_to_src": 0,
                "top_ports": {}, "top_rules": {}, "top_apps": {},
                "last_seen": None,
            }
        row = agg[key]
        row["count_open"] += 1
        row["bytes_src_to_dst"] += (e.bytes_orig or 0) or 0
        row["bytes_dst_to_src"] += (e.bytes_term or 0) or 0
        if e.dest_port is not None:
            row["top_ports"][str(e.dest_port)] = row["top_ports"].get(str(e.dest_port), 0) + 1
        if e.rule:
            row["top_rules"][e.rule] = row["top_rules"].get(e.rule, 0) + 1
        if e.app_name:
            row["top_apps"][e.app_name] = row["top_apps"].get(e.app_name, 0) + 1
        if e.ts_utc:
            et = _ensure_utc(e.ts_utc)
            if et and (row["last_seen"] is None or et > row["last_seen"]):
                row["last_seen"] = et

        # Interface-group for every destination (both local and remote)
        dest_if_val = (e.dest_if or "").strip()
        dest_zone_val = (e.dest_zone or "").strip()
        ig_key = f"{dest_if_val}|{dest_zone_val}"
        ig_key_by_dst_ep.setdefault(dst_ep.id, ig_key)
        if ig_key not in ig_meta:
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", ig_key) or "unknown"
            ig_id = f"ig-{safe}"
            parts: List[str] = []
            if dest_if_val:
                parts.append(f"If: {dest_if_val}")
            if dest_zone_val:
                parts.append(f"Zone: {dest_zone_val}")
            label = " / ".join(parts) or "unknown"
            ig_meta[ig_key] = {"id": ig_id, "dest_if": dest_if_val, "dest_zone": dest_zone_val, "label": label}
        if _event_has_dest_mac(e):
            ig_local_ep_ids.setdefault(ig_key, set()).add(dst_ep.id)
        else:
            ig_router_ep_ids.setdefault(ig_key, set()).add(dst_ep.id)

    # ── Fetch endpoints ──
    all_ep_ids: set[int] = set()
    for (sid, did) in agg:
        all_ep_ids.add(sid)
        all_ep_ids.add(did)
    endpoints: Dict[int, Endpoint] = {}
    if all_ep_ids:
        for ep in db.execute(select(Endpoint).where(Endpoint.id.in_(all_ep_ids))).scalars().all():
            endpoints[ep.id] = ep

    # ── Services view: aggregate by (proto, port, app) with by_pair (src, dst) -> count ──
    svc_agg: Dict[Tuple[str, int, str], Dict[str, Any]] = {}  # (proto, port, app) -> count, bytes, by_pair
    if dest_view == "services":
        app_by_key = _app_name_by_flow_from_close(
            db, device_list, time_from, time_to, view, get_ep,
            _event_matches_src, _event_matches_dst,
            src_kind, src_value, dst_kind, dst_value, src_endpoint, dst_endpoint,
        )
        for e in filtered:
            if view == "translated":
                src_ip = e.xlat_src_ip or e.src_ip
                dst_ip = e.xlat_dest_ip or e.dest_ip
                port = e.xlat_dest_port if e.xlat_dest_port is not None else (e.dest_port or 0)
            else:
                src_ip = e.src_ip
                dst_ip = e.dest_ip
                port = e.dest_port or 0
            src_ep = get_ep(e.device, src_ip, e.src_mac)
            dst_ep = get_ep(e.device, dst_ip, e.dest_mac)
            if src_ep is None or dst_ep is None:
                continue
            proto = ((e.proto or "").strip() or "ip").upper()
            app = app_by_key.get((src_ep.id, dst_ep.id, proto, port), "-") or "-"
            svc_key: Tuple[str, int, str] = (proto, port, app)
            if svc_key not in svc_agg:
                svc_agg[svc_key] = {"count_open": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "by_pair": {}, "dest_ips": set()}
            row = svc_agg[svc_key]
            row["count_open"] += 1
            row["bytes_src_to_dst"] += (e.bytes_orig or 0) or 0
            row["bytes_dst_to_src"] += (e.bytes_term or 0) or 0
            if dst_ip:
                row["dest_ips"].add(dst_ip)
            pair_key = (src_ep.id, dst_ep.id)
            row["by_pair"][pair_key] = row["by_pair"].get(pair_key, 0) + 1

    services_by_ep = _build_services_per_dest(
        db, device_list=device_list, filtered_open=filtered,
        src_kind=src_kind, src_value=src_value, dst_kind=dst_kind, dst_value=dst_value or "",
        time_from=time_from, time_to=time_to, view=view,
        ep_cache=ep_cache, src_endpoint=src_endpoint, dst_endpoint=dst_endpoint,
    )
    source_breakdown_by_ep = _build_source_breakdown_per_dest(
        db, device_list=device_list, filtered_open=filtered,
        src_kind=src_kind, src_value=src_value, dst_kind=dst_kind, dst_value=dst_value or "",
        time_from=time_from, time_to=time_to, view=view,
        ep_cache=ep_cache, src_endpoint=src_endpoint, dst_endpoint=dst_endpoint,
        endpoints=endpoints,
    )

    # ── Load device identifications for enrichment (keyed by normalized MAC) ──
    devid_by_mac: Dict[str, DeviceIdentification] = {}
    all_macs_in_eps = {ep.mac for ep in endpoints.values() if ep.mac and ep.mac.strip()}
    if all_macs_in_eps:
        for di in db.execute(
            select(DeviceIdentification).where(
                DeviceIdentification.firewall_device.in_(device_list),
                DeviceIdentification.srcmac.in_(all_macs_in_eps),
            )
        ).scalars().all():
            devid_by_mac[di.srcmac] = di

    # ── Load manual overrides (override wins if non-empty) ──
    override_by_mac: Dict[str, DeviceOverride] = {}
    if all_macs_in_eps:
        for ov in db.execute(
            select(DeviceOverride).where(
                DeviceOverride.firewall_device.in_(device_list),
                DeviceOverride.mac.in_(all_macs_in_eps),
            )
        ).scalars().all():
            override_by_mac[ov.mac] = ov

    def _enrich_node(out: Dict[str, Any], ep: Endpoint) -> None:
        """Attach device identification: auto from endpoint/devid, then override wins if set."""
        auto: Dict[str, Optional[str]] = {}
        if ep.device_vendor:
            auto["device_vendor"] = ep.device_vendor
        if ep.device_type:
            auto["device_type"] = ep.device_type
        if ep.device_type_name:
            auto["device_type_name"] = ep.device_type_name
        if ep.device_os_name:
            auto["device_os_name"] = ep.device_os_name
        if ep.device_brand:
            auto["device_brand"] = ep.device_brand
        if ep.device_model:
            auto["device_model"] = ep.device_model
        if ep.hostname:
            auto["hostname"] = ep.hostname
        if not auto and ep.mac and ep.mac in devid_by_mac:
            di = devid_by_mac[ep.mac]
            if di.device_vendor:
                auto["device_vendor"] = di.device_vendor
            if di.device_type:
                auto["device_type"] = di.device_type
            if di.device_type_name:
                auto["device_type_name"] = di.device_type_name
            if di.device_os_name:
                auto["device_os_name"] = di.device_os_name
            if di.device_brand:
                auto["device_brand"] = di.device_brand
            if di.device_model:
                auto["device_model"] = di.device_model
            if di.hostname:
                auto["hostname"] = di.hostname

        ov = override_by_mac.get(ep.mac) if ep.mac else None
        enrichment: Dict[str, Any] = {}
        if ov:
            enrichment["device_vendor"] = (ov.override_vendor or auto.get("device_vendor")) or None
            enrichment["device_type"] = auto.get("device_type")  # no override column for short type
            enrichment["device_type_name"] = (ov.override_type_name or auto.get("device_type_name")) or None
            enrichment["device_os_name"] = (ov.override_os_name or auto.get("device_os_name")) or None
            enrichment["device_brand"] = (ov.override_brand or auto.get("device_brand")) or None
            enrichment["device_model"] = (ov.override_model or auto.get("device_model")) or None
            enrichment["hostname"] = auto.get("hostname")  # override table has no hostname
            if ov.comment:
                enrichment["comment"] = ov.comment
        else:
            enrichment = dict(auto)

        enrichment = {k: v for k, v in enrichment.items() if v is not None and v != ""}
        if enrichment:
            out["identification"] = enrichment
        # Flat fields for Dashboard node header badges and expanded Identification (omit empty)
        v = enrichment.get("device_vendor")
        if v:
            out["vendor"] = v
        v = enrichment.get("device_type_name")
        if v:
            out["type_name"] = v
        v = enrichment.get("device_os_name")
        if v:
            out["os_name"] = v
        v = enrichment.get("device_brand")
        if v:
            out["brand"] = v
        v = enrichment.get("device_model")
        if v:
            out["model"] = v

    def build_node(ep: Endpoint, side: str) -> Dict[str, Any]:
        node_id = f"{side}-{ep.id}"
        label = ep.device_name or ep.ip
        out: Dict[str, Any] = {
            "id": node_id, "side": side, "label": label,
            "ip": ep.ip, "mac": ep.mac, "device_name": ep.device_name,
            "is_router_bucket": False, "hidden_count": 0, "details": {},
        }
        if side == "right":
            out["services"] = services_by_ep.get(ep.id, [])
            out["source_breakdown"] = source_breakdown_by_ep.get(ep.id, [])
        _enrich_node(out, ep)
        return out

    # ── Load Router MAC rules (source side) ──
    router_src_macs: set[str] = set()
    for rm in db.execute(
        select(RouterMac).where(
            RouterMac.device.in_(device_list),
            RouterMac.direction.in_(("src", "both")),
        )
    ).scalars().all():
        router_src_macs.add(rm.mac)

    def _is_src_router_mac(ep: Endpoint) -> bool:
        """True if this endpoint's MAC is flagged as a router MAC on source side."""
        mac = (ep.mac or "").strip()
        return bool(mac and mac in router_src_macs)

    # ── Compute seen_count per source endpoint (same metric as Endpoints "Seen") ──
    src_seen_count: Dict[int, int] = {}
    for (src_id, dst_id), row in agg.items():
        src_seen_count[src_id] = src_seen_count.get(src_id, 0) + row["count_open"]

    ha_mode = len(device_list) > 1
    canonical_by_src_id: Dict[int, str] = {}
    rep_left_by_canonical: Dict[str, Endpoint] = {}
    left_hidden_canonical_keys: set[str] = set()

    if ha_mode:
        for (src_id, dst_id), _ in agg.items():
            src_ep = endpoints.get(src_id)
            if not src_ep:
                continue
            ck = _canonical_endpoint_key("left", src_ep.ip, src_ep.mac)
            canonical_by_src_id[src_id] = ck
            if ck not in rep_left_by_canonical:
                rep_left_by_canonical[ck] = src_ep
            if _is_src_router_mac(src_ep) or src_ep.id not in src_ep_ids_with_mac:
                left_hidden_canonical_keys.add(ck)

    # ── Left nodes ──
    left_nodes: List[Dict[str, Any]] = []
    left_seen: Dict[int, str] = {}
    left_hidden_ep_ids: set[int] = set()
    router_left_hidden: List[str] = []
    left_hidden_edges: List[Dict[str, Any]] = []

    if ha_mode:
        for ck, rep_ep in rep_left_by_canonical.items():
            if ck in left_hidden_canonical_keys:
                continue
            node = build_node(rep_ep, "left")
            node["id"] = ck
            node["seen_count"] = sum(
                src_seen_count.get(sid, 0)
                for sid, key in canonical_by_src_id.items()
                if key == ck
            )
            left_nodes.append(node)
        for src_id in canonical_by_src_id:
            left_seen[src_id] = canonical_by_src_id[src_id]
        router_left_hidden = list(left_hidden_canonical_keys)
        hidden_nodes_left = []
        for ck in left_hidden_canonical_keys:
            rep = rep_left_by_canonical.get(ck)
            if rep:
                n = build_node(rep, "left")
                n["id"] = ck
                hidden_nodes_left.append(n)
        left_hidden_ep_ids = set()  # unused when ha_mode for "if src_ep.id in left_hidden_ep_ids"; we use canonical
    else:
        for (src_id, dst_id), _ in agg.items():
            src_ep = endpoints.get(src_id)
            if not src_ep:
                continue
            if _is_src_router_mac(src_ep) or src_ep.id not in src_ep_ids_with_mac:
                if src_ep.id not in left_hidden_ep_ids:
                    router_left_hidden.append(f"left-{src_ep.id}")
                    left_hidden_ep_ids.add(src_ep.id)
            elif src_ep.id not in left_seen:
                node = build_node(src_ep, "left")
                node["seen_count"] = src_seen_count.get(src_ep.id, 0)
                left_nodes.append(node)
                left_seen[src_ep.id] = f"left-{src_ep.id}"

        hidden_nodes_left = [build_node(endpoints[eid], "left") for eid in left_hidden_ep_ids if eid in endpoints]

    def _iso(dt: Any) -> Optional[str]:
        return dt.isoformat() if dt and hasattr(dt, "isoformat") else None

    # ── Services view v2: hierarchical Firewall → Port → App (port_nodes + app_nodes) ──
    if dest_view == "services":
        TOP_BY_PAIR = 50
        # 1) Port-level aggregation: (proto, port) -> totals + distinct dest IPs
        port_agg: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for (proto, port, app), row in svc_agg.items():
            key = (proto, port)
            if key not in port_agg:
                port_agg[key] = {"count_open": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "dest_ips": set()}
            port_agg[key]["count_open"] += row["count_open"]
            port_agg[key]["bytes_src_to_dst"] += row.get("bytes_src_to_dst", 0)
            port_agg[key]["bytes_dst_to_src"] += row.get("bytes_dst_to_src", 0)
            port_agg[key]["dest_ips"].update(row.get("dest_ips") or set())
        # 2) Port nodes: svcport:proto:port (count + dest_ip_count); sort by port asc, then TCP before UDP
        def _proto_rank(p: str) -> int:
            s = (p or "").strip().upper()
            if s == "TCP":
                return 0
            if s == "UDP":
                return 1
            return 2

        service_port_nodes: List[Dict[str, Any]] = []
        for (proto, port), row in sorted(
            port_agg.items(),
            key=lambda x: (x[0][1], _proto_rank(x[0][0]), x[0][0], x[0][1]),
        ):
            port_id = f"svcport:{proto}:{port}"
            dest_ips = row.get("dest_ips") or set()
            service_port_nodes.append({
                "id": port_id,
                "side": "right",
                "type": "servicePortNode",
                "data": {
                    "label": f"{proto}/{port}",
                    "proto": proto,
                    "port": port,
                    "count": row["count_open"],
                    "dest_ip_count": len(dest_ips),
                },
            })
        # 3) App nodes: svcapp:proto:port:appKey (appKey = app or "-"); include by_pair
        service_app_nodes: List[Dict[str, Any]] = []
        for (proto, port, app), row in svc_agg.items():
            app_key = app if app != "-" else "-"
            app_id = f"svcapp:{proto}:{port}:{app_key}"
            port_id = f"svcport:{proto}:{port}"
            by_pair_agg = row["by_pair"]
            pairs_sorted = sorted(by_pair_agg.items(), key=lambda p: -p[1])[:TOP_BY_PAIR]
            by_pair: List[Dict[str, Any]] = []
            for (src_id, dst_id), cnt in pairs_sorted:
                src_ep = endpoints.get(src_id)
                dst_ep = endpoints.get(dst_id)
                src_label = (src_ep.device_name or src_ep.ip or str(src_id)) if src_ep else str(src_id)
                dst_label = (dst_ep.device_name or dst_ep.ip or str(dst_id)) if dst_ep else str(dst_id)
                src_ip = (src_ep.ip or "").strip() if src_ep else ""
                src_mac = (src_ep.mac or "").strip() if src_ep else ""
                dest_ip = (dst_ep.ip or "").strip() if dst_ep else ""
                by_pair.append({
                    "source_label": src_label,
                    "dest_label": dst_label,
                    "src_ip": src_ip,
                    "src_mac": src_mac or None,
                    "dest_ip": dest_ip,
                    "count": cnt,
                })
            app_label = app if app != "-" else "—"
            dest_ips = row.get("dest_ips") or set()
            service_app_nodes.append({
                "id": app_id,
                "side": "right",
                "type": "serviceAppNode",
                "data": {
                    "label": app_label,
                    "proto": proto,
                    "port": port,
                    "app": app if app != "-" else None,
                    "appKey": app_key,
                    "count": row["count_open"],
                    "dest_ip_count": len(dest_ips),
                    "by_pair": by_pair,
                    "parent_port_id": port_id,
                },
            })
        # 4) Edges: left->fw, fw->svcport, svcport->svcapp
        edges_svc: List[Dict[str, Any]] = []
        left_to_fw: Dict[str, Dict[str, Any]] = {}
        for (src_id, dst_id), row in agg.items():
            src_ep = endpoints.get(src_id)
            if not src_ep:
                continue
            if ha_mode:
                ck = canonical_by_src_id.get(src_id)
                source_id = "router-left" if (ck and ck in left_hidden_canonical_keys) else (ck or left_seen.get(src_id, f"left-{src_ep.id}"))
            else:
                source_id = "router-left" if (src_ep.id in left_hidden_ep_ids) else left_seen.get(src_ep.id, f"left-{src_ep.id}")
            if source_id not in left_to_fw:
                left_to_fw[source_id] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None}
            into = left_to_fw[source_id]
            into["count_open"] += row["count_open"]
            into["count_close"] += row.get("count_close", 0)
            into["bytes_src_to_dst"] += row.get("bytes_src_to_dst", 0)
            into["bytes_dst_to_src"] += row.get("bytes_dst_to_src", 0)
            if row.get("last_seen") and (into.get("last_seen") is None or row["last_seen"] > into["last_seen"]):
                into["last_seen"] = row["last_seen"]
        for source_id, payload in left_to_fw.items():
            p = dict(payload)
            p["last_seen"] = _iso(p.get("last_seen"))
            edges_svc.append({"source_node_id": source_id, "target_node_id": "fw", **p})
        for (proto, port), row in port_agg.items():
            port_id = f"svcport:{proto}:{port}"
            p = {
                "count_open": row["count_open"],
                "count_close": 0,
                "bytes_src_to_dst": row.get("bytes_src_to_dst", 0),
                "bytes_dst_to_src": row.get("bytes_dst_to_src", 0),
                "top_ports": {},
                "top_rules": {},
                "top_apps": {},
                "last_seen": None,
            }
            edges_svc.append({"source_node_id": "fw", "target_node_id": port_id, **p})
        for (proto, port, app), row in svc_agg.items():
            app_key = app if app != "-" else "-"
            app_id = f"svcapp:{proto}:{port}:{app_key}"
            port_id = f"svcport:{proto}:{port}"
            p = {
                "count_open": row["count_open"],
                "count_close": 0,
                "bytes_src_to_dst": row.get("bytes_src_to_dst", 0),
                "bytes_dst_to_src": row.get("bytes_dst_to_src", 0),
                "top_ports": {},
                "top_rules": {},
                "top_apps": {},
                "last_seen": None,
            }
            edges_svc.append({"source_node_id": port_id, "target_node_id": app_id, **p})
        left_hidden_edges_svc: List[Dict[str, Any]] = []
        if ha_mode:
            hidden_to_fw: Dict[str, Dict[str, Any]] = {}
            for (src_id, dst_id), row in agg.items():
                ck = canonical_by_src_id.get(src_id)
                if not ck or ck not in left_hidden_canonical_keys:
                    continue
                if ck not in hidden_to_fw:
                    hidden_to_fw[ck] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None}
                into = hidden_to_fw[ck]
                into["count_open"] += row["count_open"]
                into["count_close"] += row.get("count_close", 0)
                into["bytes_src_to_dst"] += row.get("bytes_src_to_dst", 0)
                into["bytes_dst_to_src"] += row.get("bytes_dst_to_src", 0)
                for k, v in (row.get("top_ports") or {}).items():
                    into["top_ports"][k] = into["top_ports"].get(k, 0) + v
                for k, v in (row.get("top_rules") or {}).items():
                    into["top_rules"][k] = into["top_rules"].get(k, 0) + v
                for k, v in (row.get("top_apps") or {}).items():
                    into["top_apps"][k] = into["top_apps"].get(k, 0) + v
                if row.get("last_seen") and (into.get("last_seen") is None or row["last_seen"] > into["last_seen"]):
                    into["last_seen"] = row["last_seen"]
            for ck, payload in hidden_to_fw.items():
                p = dict(payload)
                p["last_seen"] = _iso(p.get("last_seen"))
                edge_row = {"source_node_id": ck, "target_node_id": "fw", **p}
                edges_svc.append(edge_row)
                left_hidden_edges_svc.append(edge_row)
        else:
            for (src_id, dst_id), row in agg.items():
                src_ep = endpoints.get(src_id)
                if not src_ep or src_ep.id not in left_hidden_ep_ids:
                    continue
                edge_row = {
                    "source_node_id": f"left-{src_ep.id}",
                    "target_node_id": "fw",
                    "count_open": row["count_open"], "count_close": row.get("count_close", 0),
                    "bytes_src_to_dst": row.get("bytes_src_to_dst", 0), "bytes_dst_to_src": row.get("bytes_dst_to_src", 0),
                    "top_ports": row.get("top_ports", {}), "top_rules": row.get("top_rules", {}), "top_apps": row.get("top_apps", {}),
                    "last_seen": _iso(row.get("last_seen")),
                }
                edges_svc.append(edge_row)
                left_hidden_edges_svc.append(edge_row)
        right_count = len(service_port_nodes) + len(service_app_nodes)
        return {
            "meta": {
                "device": device_label,
                "device_label": device_label,
                "src_kind": src_kind, "src_value": src_value,
                "dst_kind": dst_kind, "dst_value": dst_value or "",
                "time_from": time_from.isoformat() if time_from else None,
                "time_to": time_to.isoformat() if time_to else None,
                "view": view,
                "dest_view": dest_view,
                "left_count": len(left_nodes),
                "right_count": right_count,
                "unknown_endpoints": 0,
                "router_mac_rules": len(router_src_macs),
            },
            "left_nodes": left_nodes,
            "interface_groups": [],
            "service_port_nodes": service_port_nodes,
            "service_app_nodes": service_app_nodes,
            "router_bucket_left": {
                "node_id": "router-left",
                "count": len(router_left_hidden),
                "hidden_node_ids": router_left_hidden,
                "hidden_nodes": hidden_nodes_left,
                "hidden_edges": left_hidden_edges_svc,
            },
            "edges": edges_svc,
        }

    # ── Build interface groups with per-group local devices and router buckets ──
    interface_groups: List[Dict[str, Any]] = []
    # Also track all right-side endpoint counts for meta
    total_right_count = 0

    for ig_key, meta in ig_meta.items():
        ig_id = meta["id"]
        local_ids = ig_local_ep_ids.get(ig_key, set())
        router_ids = ig_router_ep_ids.get(ig_key, set())
        # Remove any endpoint that is also local from the router set (strict rule: local wins)
        router_ids = router_ids - dest_ep_ids_with_mac

        local_devices = []
        for eid in local_ids:
            ep = endpoints.get(eid)
            if ep:
                local_devices.append(build_node(ep, "right"))
        local_devices.sort(key=lambda n: (n.get("label") or "").lower())

        router_hidden_nodes = []
        router_hidden_edges: List[Dict[str, Any]] = []
        router_node_id = f"router-{ig_id}"
        for eid in router_ids:
            ep = endpoints.get(eid)
            if ep:
                router_hidden_nodes.append(build_node(ep, "right"))
        router_hidden_nodes.sort(key=lambda n: (n.get("label") or "").lower())

        # Build router hidden edges (router -> device, per (src, dst) pair)
        for (src_id, dst_id), row_data in agg.items():
            if dst_id not in router_ids:
                continue
            dst_ep = endpoints.get(dst_id)
            if not dst_ep:
                continue
            ls = row_data.get("last_seen")
            router_hidden_edges.append({
                "source_node_id": router_node_id,
                "target_node_id": f"right-{dst_ep.id}",
                "count_open": row_data["count_open"],
                "count_close": row_data["count_close"],
                "bytes_src_to_dst": row_data["bytes_src_to_dst"],
                "bytes_dst_to_src": row_data["bytes_dst_to_src"],
                "top_ports": row_data["top_ports"],
                "top_rules": row_data["top_rules"],
                "top_apps": row_data["top_apps"],
                "last_seen": ls.isoformat() if ls and hasattr(ls, "isoformat") else None,
                "top_services": services_by_ep.get(dst_id, [])[:3],
            })

        total_right_count += len(local_devices) + len(router_ids)

        group_entry: Dict[str, Any] = {
            "id": ig_id,
            "dest_if": meta["dest_if"],
            "dest_zone": meta["dest_zone"],
            "label": meta["label"],
            "local_devices": local_devices,
        }
        if router_ids:
            group_entry["router"] = {
                "node_id": router_node_id,
                "count": len(router_ids),
                "hidden_nodes": router_hidden_nodes,
                "hidden_edges": router_hidden_edges,
            }
        else:
            group_entry["router"] = None
        interface_groups.append(group_entry)

    # Sort: groups with only local devices first, then groups with routers
    interface_groups.sort(key=lambda g: (0 if g["router"] is None else 1, (g.get("label") or "").lower()))

    # ── Edges ──
    def merge_row(into: Dict[str, Any], row: Dict[str, Any]) -> None:
        into["count_open"] = into.get("count_open", 0) + row["count_open"]
        into["count_close"] = into.get("count_close", 0) + row["count_close"]
        into["bytes_src_to_dst"] = into.get("bytes_src_to_dst", 0) + row["bytes_src_to_dst"]
        into["bytes_dst_to_src"] = into.get("bytes_dst_to_src", 0) + row["bytes_dst_to_src"]
        for k, v in (row.get("top_ports") or {}).items():
            into.setdefault("top_ports", {})[k] = into["top_ports"].get(k, 0) + v
        for k, v in (row.get("top_rules") or {}).items():
            into.setdefault("top_rules", {})[k] = into["top_rules"].get(k, 0) + v
        for k, v in (row.get("top_apps") or {}).items():
            into.setdefault("top_apps", {})[k] = into["top_apps"].get(k, 0) + v
        last = row.get("last_seen")
        if last and (into.get("last_seen") is None or (hasattr(last, "__gt__") and last > into["last_seen"])):
            into["last_seen"] = last

    def _iso(dt: Any) -> Optional[str]:
        return dt.isoformat() if dt and hasattr(dt, "isoformat") else None

    edges: List[Dict[str, Any]] = []

    # Left -> Firewall (aggregate per source node)
    left_to_fw: Dict[str, Dict[str, Any]] = {}
    for (src_id, dst_id), row in agg.items():
        src_ep = endpoints.get(src_id)
        if not src_ep:
            continue
        if ha_mode:
            ck = canonical_by_src_id.get(src_id)
            source_id = "router-left" if (ck and ck in left_hidden_canonical_keys) else (ck or left_seen.get(src_id, f"left-{src_ep.id}"))
        else:
            source_id = "router-left" if (src_ep.id in left_hidden_ep_ids) else left_seen.get(src_ep.id, f"left-{src_ep.id}")
        if source_id not in left_to_fw:
            left_to_fw[source_id] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None}
        merge_row(left_to_fw[source_id], row)
    for source_id, payload in left_to_fw.items():
        p = dict(payload)
        p["last_seen"] = _iso(p.get("last_seen"))
        edges.append({"source_node_id": source_id, "target_node_id": "fw", **p})

    # Firewall -> InterfaceGroup (aggregate per group)
    fw_to_ig: Dict[str, Dict[str, Any]] = {}
    for (src_id, dst_id), row in agg.items():
        dst_ep = endpoints.get(dst_id)
        if not dst_ep:
            continue
        ig_key = ig_key_by_dst_ep.get(dst_ep.id)
        if not ig_key or ig_key not in ig_meta:
            continue
        ig_id = ig_meta[ig_key]["id"]
        if ig_id not in fw_to_ig:
            fw_to_ig[ig_id] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None}
        merge_row(fw_to_ig[ig_id], row)
    for ig_id, payload in fw_to_ig.items():
        p = dict(payload)
        p["last_seen"] = _iso(p.get("last_seen"))
        edges.append({"source_node_id": "fw", "target_node_id": ig_id, **p})

    # InterfaceGroup -> Router (per group that has router, aggregate over router devices)
    for group in interface_groups:
        if not group["router"]:
            continue
        ig_id = group["id"]
        router_node_id = group["router"]["node_id"]
        router_ep_ids_set = set()
        for hn in group["router"]["hidden_nodes"]:
            eid_str = hn["id"].replace("right-", "")
            try:
                router_ep_ids_set.add(int(eid_str))
            except ValueError:
                pass
        ig_to_router_agg: Dict[str, Any] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None}
        for (src_id, dst_id), row in agg.items():
            if dst_id in router_ep_ids_set:
                merge_row(ig_to_router_agg, row)
        if ig_to_router_agg.get("count_open") or ig_to_router_agg.get("bytes_src_to_dst"):
            p = dict(ig_to_router_agg)
            p["last_seen"] = _iso(p.get("last_seen"))
            edges.append({"source_node_id": ig_id, "target_node_id": router_node_id, **p})

    # Left hidden edges (for router-left bucket: no src_mac OR flagged router MAC)
    if ha_mode:
        left_hidden_agg: Dict[str, Dict[str, Any]] = {}
        for (src_id, dst_id), row in agg.items():
            ck = canonical_by_src_id.get(src_id)
            if not ck or ck not in left_hidden_canonical_keys:
                continue
            if ck not in left_hidden_agg:
                left_hidden_agg[ck] = {"count_open": 0, "count_close": 0, "bytes_src_to_dst": 0, "bytes_dst_to_src": 0, "top_ports": {}, "top_rules": {}, "top_apps": {}, "last_seen": None, "top_services": []}
            into = left_hidden_agg[ck]
            into["count_open"] += row["count_open"]
            into["count_close"] += row.get("count_close", 0)
            into["bytes_src_to_dst"] += row.get("bytes_src_to_dst", 0)
            into["bytes_dst_to_src"] += row.get("bytes_dst_to_src", 0)
            for k, v in (row.get("top_ports") or {}).items():
                into["top_ports"][k] = into["top_ports"].get(k, 0) + v
            for k, v in (row.get("top_rules") or {}).items():
                into["top_rules"][k] = into["top_rules"].get(k, 0) + v
            for k, v in (row.get("top_apps") or {}).items():
                into["top_apps"][k] = into["top_apps"].get(k, 0) + v
            if row.get("last_seen") and (into.get("last_seen") is None or row["last_seen"] > into["last_seen"]):
                into["last_seen"] = row["last_seen"]
            into["top_services"] = (into.get("top_services") or []) + services_by_ep.get(dst_id, [])[:3]
        for ck, payload in left_hidden_agg.items():
            top_svc = payload.get("top_services") or []
            left_hidden_edges.append({
                "source_node_id": ck,
                "target_node_id": "fw",
                "count_open": payload["count_open"], "count_close": payload["count_close"],
                "bytes_src_to_dst": payload["bytes_src_to_dst"], "bytes_dst_to_src": payload["bytes_dst_to_src"],
                "top_ports": payload.get("top_ports", {}), "top_rules": payload.get("top_rules", {}), "top_apps": payload.get("top_apps", {}),
                "last_seen": _iso(payload.get("last_seen")),
                "top_services": top_svc[:3],
            })
    else:
        for (src_id, dst_id), row in agg.items():
            src_ep = endpoints.get(src_id)
            if not src_ep or src_ep.id not in left_hidden_ep_ids:
                continue
            ls = row.get("last_seen")
            left_hidden_edges.append({
                "source_node_id": f"left-{src_ep.id}",
                "target_node_id": "fw",
                "count_open": row["count_open"], "count_close": row["count_close"],
                "bytes_src_to_dst": row["bytes_src_to_dst"], "bytes_dst_to_src": row["bytes_dst_to_src"],
                "top_ports": row["top_ports"], "top_rules": row["top_rules"], "top_apps": row["top_apps"],
                "last_seen": _iso(ls),
                "top_services": services_by_ep.get(dst_id, [])[:3],
            })

    return {
        "meta": {
            "device": device_label,
            "device_label": device_label,
            "src_kind": src_kind, "src_value": src_value,
            "dst_kind": dst_kind, "dst_value": dst_value or "",
            "time_from": time_from.isoformat() if time_from else None,
            "time_to": time_to.isoformat() if time_to else None,
            "view": view,
            "left_count": len(left_nodes),
            "right_count": total_right_count,
            "unknown_endpoints": 0,
            "router_mac_rules": len(router_src_macs),
        },
        "left_nodes": left_nodes,
        "interface_groups": interface_groups,
        "router_bucket_left": {
            "node_id": "router-left",
            "count": len(router_left_hidden),
            "hidden_node_ids": router_left_hidden,
            "hidden_nodes": hidden_nodes_left,
            "hidden_edges": left_hidden_edges,
        },
        "edges": edges,
    }


def _flows_to_response(
    flows: List[Flow],
    db: Session,
    basis: str,
    from_: str,
    to: str,
    view: str,
    time_start: Optional[datetime],
    time_end: Optional[datetime],
    metric: str,
    split: str,
) -> Dict[str, Any]:
    """Build graph response from Flow rows (legacy)."""
    src_ids = {f.src_endpoint_id for f in flows}
    dst_ids = {f.dst_endpoint_id for f in flows}
    ep_ids = src_ids.union(dst_ids)
    endpoints: Dict[int, Endpoint] = {}
    if ep_ids:
        for ep in db.execute(select(Endpoint).where(Endpoint.id.in_(ep_ids))).scalars().all():
            endpoints[ep.id] = ep

    left_nodes = []
    right_nodes = []
    router_left_hidden = []
    router_right_hidden = []
    left_seen: Dict[int, str] = {}
    right_seen: Dict[int, str] = {}

    def build_node(ep: Endpoint, side: str) -> Dict[str, Any]:
        node_id = f"{side}-{ep.id}"
        label = ep.device_name or ep.ip
        return {
            "id": node_id,
            "side": side,
            "label": label,
            "ip": ep.ip,
            "mac": ep.mac,
            "device_name": ep.device_name,
            "is_router_bucket": False,
            "hidden_count": 0,
            "details": {},
        }

    for f in flows:
        src_ep = endpoints.get(f.src_endpoint_id)
        dst_ep = endpoints.get(f.dst_endpoint_id)
        if not src_ep or not dst_ep:
            continue
        if not _endpoint_has_mac(src_ep):
            router_left_hidden.append(f"left-{src_ep.id}")
        elif src_ep.id not in left_seen:
            left_nodes.append(build_node(src_ep, "left"))
            left_seen[src_ep.id] = f"left-{src_ep.id}"
        if not _endpoint_has_mac(dst_ep):
            router_right_hidden.append(f"right-{dst_ep.id}")
        elif dst_ep.id not in right_seen:
            right_nodes.append(build_node(dst_ep, "right"))
            right_seen[dst_ep.id] = f"right-{dst_ep.id}"

    edges = []
    for f in flows:
        src_ep = endpoints.get(f.src_endpoint_id)
        dst_ep = endpoints.get(f.dst_endpoint_id)
        if not src_ep or not dst_ep:
            continue
        source_id = "router-left" if not _endpoint_has_mac(src_ep) else left_seen.get(src_ep.id, f"left-{src_ep.id}")
        target_id = "router-right" if not _endpoint_has_mac(dst_ep) else right_seen.get(dst_ep.id, f"right-{dst_ep.id}")
        edges.append({
            "source_node_id": source_id,
            "target_node_id": target_id,
            "count_open": f.count_open,
            "count_close": f.count_close,
            "bytes_src_to_dst": f.bytes_src_to_dst,
            "bytes_dst_to_src": f.bytes_dst_to_src,
            "top_ports": {str(f.dest_port): f.count_open} if f.dest_port is not None else {},
            "top_rules": f.top_rules or {},
            "top_apps": f.top_apps or {},
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        })

    return {
        "meta": {
            "basis": basis,
            "from": from_,
            "to": to,
            "view": view,
            "metric": metric,
            "split": split,
            "time_start": time_start.isoformat() if time_start else None,
            "time_end": time_end.isoformat() if time_end else None,
            "left_count": len(left_nodes),
            "right_count": len(right_nodes),
            "unknown_endpoints": 0,
        },
        "left_nodes": left_nodes,
        "right_nodes": right_nodes,
        "router_bucket_left": {"node_id": "router-left", "count": len(router_left_hidden), "hidden_node_ids": router_left_hidden},
        "router_bucket_right": {"node_id": "router-right", "count": len(router_right_hidden), "hidden_node_ids": router_right_hidden},
        "edges": edges,
    }
