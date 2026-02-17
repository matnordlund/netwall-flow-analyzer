"""Read-only endpoints for Security Zones Mapping: distinct devices and zone/interface names from logs."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Request
from sqlalchemy import func, or_, select, union, union_all
from sqlalchemy.orm import Session

from ..api.device_resolve import resolve_device
from ..storage.models import DeviceIdentification, DeviceOverride, Endpoint, Event, FirewallOverride, HaCluster, RouterMac
from ..storage.settings import get_setting

router = APIRouter(tags=["zones"])

# HA detection: suffix (case-sensitive) and suggested label
HA_MASTER_SUFFIX = "_Master"
HA_SLAVE_SUFFIX = "_Slave"


def _ha_candidates_from_device_set(devices: List[str]) -> List[Dict[str, Any]]:
    """Given a list of device names, return HA candidates (both _Master and _Slave present)."""
    device_set = set(devices)
    bases_with_both: set[str] = set()
    for d in devices:
        if not d:
            continue
        if d.endswith(HA_MASTER_SUFFIX):
            base = d[: -len(HA_MASTER_SUFFIX)]
            if base and (base + HA_SLAVE_SUFFIX) in device_set:
                bases_with_both.add(base)
        elif d.endswith(HA_SLAVE_SUFFIX):
            base = d[: -len(HA_SLAVE_SUFFIX)]
            if base and (base + HA_MASTER_SUFFIX) in device_set:
                bases_with_both.add(base)
    out: List[Dict[str, Any]] = []
    for base in sorted(bases_with_both):
        master = base + HA_MASTER_SUFFIX
        slave = base + HA_SLAVE_SUFFIX
        if master in device_set and slave in device_set:
            out.append({
                "base": base,
                "master": master,
                "slave": slave,
                "suggested_label": f"{base} (HA)",
            })
    return out


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def get_db(request: Request) -> Session:
    SessionLocal = request.app.state.db_sessionmaker
    return SessionLocal()


def _normalize_single_column_strings(rows: list) -> List[str]:
    """Return sorted unique non-empty trimmed strings from single-column result rows.

    Handles rows that may be (value,) or in some backends the raw value (e.g. str).
    Excludes null, empty, and whitespace-only; trims leading/trailing whitespace.
    """
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, (list, tuple)):
            r = row[0] if row else None
        elif hasattr(row, "__getitem__") and not isinstance(row, str):
            r = row[0]
        else:
            r = row
        if r is None:
            continue
        s = str(r).strip()
        if not s:
            continue
        seen.add(s)
    return sorted(seen)


def _normalize_endpoint_names(rows: list) -> List[str]:
    """Normalize zone/interface names: strip quotes, drop empty and malformed values.

    Log values may be stored with surrounding double-quotes or truncated/malformed
    (e.g. leading quote without trailing, or empty ""). We return only clean names.
    """
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, (list, tuple)):
            r = row[0] if row else None
        elif hasattr(row, "__getitem__") and not isinstance(row, str):
            r = row[0]
        else:
            r = row
        if r is None:
            continue
        s = str(r).strip()
        if not s:
            continue
        # Malformed: leading quote without matching trailing quote (partial/corrupted)
        if s.startswith('"') and not s.endswith('"'):
            continue
        s = s.strip('"').strip()
        if not s:
            continue
        seen.add(s)
    return sorted(seen)


@router.get("/devices", response_model=List[str])
def list_devices(request: Request):
    """Return distinct device names (syslog hostnames) observed in ingested events.

    Only returns devices that appear in the events table (parsed CONN logs).
    Excludes null, empty, and whitespace-only; trims leading/trailing whitespace.
    """
    db: Session = get_db(request)
    try:
        # Source of truth: events table only (device = syslog hostname from parsed header).
        stmt = select(Event.device).where(Event.device.isnot(None)).distinct()
        rows = db.execute(stmt).scalars().all()
        # Exclude empty/whitespace and trim (required behavior).
        return _normalize_single_column_strings(rows)
    finally:
        db.close()


@router.get("/devices/ha-candidates", response_model=List[Dict[str, Any]])
def list_ha_candidates(request: Request):
    """Return detected HA pairs from syslog-only devices: both <base>_Master and <base>_Slave (case-sensitive).
    Import firewalls are never HA candidates."""
    db: Session = get_db(request)
    try:
        stmt = (
            select(Event.device)
            .where(Event.device.isnot(None))
            .where((Event.ingest_source == "syslog") | (Event.ingest_source.is_(None)))
            .where(or_(Event.device.endswith(HA_MASTER_SUFFIX), Event.device.endswith(HA_SLAVE_SUFFIX)))
            .distinct()
        )
        rows = db.execute(stmt).scalars().all()
        devices = _normalize_single_column_strings(rows)
        return _ha_candidates_from_device_set(devices)
    finally:
        db.close()


@router.get("/devices/groups", response_model=List[Dict[str, Any]])
def list_device_groups(request: Request):
    """Return selectable Source Firewall entries: single devices + enabled HA clusters.

    Each item: { id, label, kind: "single"|"ha", members: [device names] }.
    HA entry only included when ha_clusters.is_enabled is true for that base.
    Label uses firewall_overrides.display_name when set, else HA label or raw device.
    """
    db: Session = get_db(request)
    try:
        stmt = select(Event.device).where(Event.device.isnot(None)).distinct()
        rows = db.execute(stmt).scalars().all()
        raw_devices = _normalize_single_column_strings(rows)
        enabled_clusters: List[HaCluster] = db.execute(
            select(HaCluster).where(HaCluster.is_enabled.is_(True))
        ).scalars().all()
        enabled_bases = {c.base for c in enabled_clusters}
        # Load display name overrides (device_key = device for single, base for HA)
        overrides: Dict[str, str] = {}
        for o in db.execute(select(FirewallOverride)).scalars().all():
            overrides[o.device_key] = (o.display_name or "").strip()
        result: List[Dict[str, Any]] = []
        for d in raw_devices:
            if not d:
                continue
            if d.endswith(HA_MASTER_SUFFIX):
                base = d[: -len(HA_MASTER_SUFFIX)]
                if base in enabled_bases:
                    continue
            if d.endswith(HA_SLAVE_SUFFIX):
                base = d[: -len(HA_SLAVE_SUFFIX)]
                if base in enabled_bases:
                    continue
            label = overrides.get(d, d) or d
            result.append({
                "id": d,
                "label": label,
                "kind": "single",
                "members": [d],
            })
        for c in enabled_clusters:
            ha_id = f"ha:{c.base}"
            label = overrides.get(ha_id) or overrides.get(c.base) or c.label or f"{c.base} (HA)"
            result.append({
                "id": ha_id,
                "label": label,
                "kind": "ha",
                "members": list(c.members) if isinstance(c.members, list) else [],
            })
        result.sort(key=lambda x: (x["label"].lower(), x["id"]))
        return result
    finally:
        db.close()


@router.post("/devices/groups/enable")
def enable_ha_cluster(
    request: Request,
    body: Dict[str, Any],
):
    """Enable or disable an HA cluster. body: { base: str, enabled: bool }."""
    base = (body.get("base") or "").strip()
    if not base:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="base is required")
    enabled = bool(body.get("enabled"))
    db: Session = get_db(request)
    try:
        cluster = db.execute(select(HaCluster).where(HaCluster.base == base)).scalar_one_or_none()
        if cluster:
            cluster.is_enabled = enabled
        else:
            if not enabled:
                return {"ok": True, "base": base, "enabled": False}
            master = base + HA_MASTER_SUFFIX
            slave = base + HA_SLAVE_SUFFIX
            cluster = HaCluster(
                base=base,
                label=f"{base} (HA)",
                members=[master, slave],
                is_enabled=True,
            )
            db.add(cluster)
        db.commit()
        return {"ok": True, "base": base, "enabled": cluster.is_enabled}
    except Exception as e:
        db.rollback()
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.post("/devices/groups/rename")
def rename_ha_cluster(
    request: Request,
    body: Dict[str, Any],
):
    """Set custom label for an HA cluster. body: { base: str, label: str }."""
    base = (body.get("base") or "").strip()
    label = (body.get("label") or "").strip()
    if not base:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="base is required")
    db: Session = get_db(request)
    try:
        cluster = db.execute(select(HaCluster).where(HaCluster.base == base)).scalar_one_or_none()
        if not cluster:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="HA cluster not found")
        if label:
            cluster.label = label
        db.commit()
        return {"ok": True, "base": base, "label": cluster.label}
    except Exception as e:
        db.rollback()
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/endpoints", response_model=List[str])
def list_endpoints(
    request: Request,
    device: str = Query(..., description="Device (syslog hostname) or ha:base for HA cluster"),
    kind: str = Query(..., pattern="^(zone|interface)$", description="zone or interface"),
    time_from: Optional[datetime] = Query(None, description="ISO8601 start of time range (optional; when set, only zones/interfaces seen in range)"),
    time_to: Optional[datetime] = Query(None, description="ISO8601 end of time range (optional)"),
):
    """Return distinct zone or interface names observed in logs for the given device.

    - kind=zone: distinct values from connrecvzone and conndestzone.
    - kind=interface: distinct values from connrecvif and conndestif.
    - device can be a single device name or ha:base for HA cluster.
    - When time_from/time_to are provided, only values from events in that range are returned.
    """
    db: Session = get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return []
        base = [Event.device.in_(device_list)]
        if time_from is not None:
            base.append(Event.ts_utc >= _ensure_utc(time_from))
        if time_to is not None:
            base.append(Event.ts_utc <= _ensure_utc(time_to))
        if kind == "zone":
            q1 = select(Event.recv_zone).where(
                *base,
                Event.recv_zone.isnot(None),
                Event.recv_zone != "",
            )
            q2 = select(Event.dest_zone).where(
                *base,
                Event.dest_zone.isnot(None),
                Event.dest_zone != "",
            )
        else:
            q1 = select(Event.recv_if).where(
                *base,
                Event.recv_if.isnot(None),
                Event.recv_if != "",
            )
            q2 = select(Event.dest_if).where(
                *base,
                Event.dest_if.isnot(None),
                Event.dest_if != "",
            )
        stmt = union(q1, q2)
        rows = db.execute(stmt).all()
        # Strip quotes, exclude empty and malformed (e.g. leading " without trailing ").
        return _normalize_endpoint_names(rows)
    finally:
        db.close()


@router.get("/users", response_model=List[str])
def list_users(
    request: Request,
    device: str = Query(..., description="Device or ha:base for HA cluster"),
    time_from: Optional[datetime] = Query(None, description="ISO8601 start of time range"),
    time_to: Optional[datetime] = Query(None, description="ISO8601 end of time range"),
):
    """Return distinct srcusername from events for the given device and time range.
    Only returns non-empty usernames. Used for Dashboard Source Type = User."""
    db: Session = get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return []
        stmt = (
            select(Event.srcusername)
            .where(Event.device.in_(device_list))
            .where(Event.srcusername.isnot(None))
            .where(Event.srcusername != "")
        )
        if time_from is not None:
            stmt = stmt.where(Event.ts_utc >= _ensure_utc(time_from))
        if time_to is not None:
            stmt = stmt.where(Event.ts_utc <= _ensure_utc(time_to))
        stmt = stmt.distinct().order_by(Event.srcusername)
        rows = db.execute(stmt).scalars().all()
        return _normalize_single_column_strings(rows)
    finally:
        db.close()


@router.get("/endpoints/list", response_model=List[Dict[str, Any]])
def list_endpoints_with_mac(
    request: Request,
    device: str = Query(..., description="Device (syslog hostname) or ha:base for HA cluster"),
    time_from: Optional[datetime] = Query(None, description="ISO8601 start of range"),
    time_to: Optional[datetime] = Query(None, description="ISO8601 end of range"),
    has_mac: bool = Query(True, description="Only endpoints with non-empty MAC"),
    local_only: Optional[str] = Query(None, description="true/false — filter to local CIDRs; when omitted uses settings"),
):
    """Return distinct endpoints (device+ip+mac) observed in events in the time range.

    Each item has: id (Endpoint.id), ip, mac, device_name, label (device_name or ip).
    When has_mac=true, only endpoints with non-empty MAC are included (same rule as expandable nodes).
    When local_only=true (or settings local_networks.enabled), only endpoints whose IP is in configured CIDRs are returned.
    device can be a single device name or ha:base for HA cluster.
    """
    db: Session = get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return []
        stmt = (
            select(Event.src_ip, Event.src_mac)
            .where(Event.device.in_(device_list))
            .where(Event.src_ip.isnot(None))
            .where(Event.src_ip != "")
        )
        if has_mac:
            stmt = stmt.where(Event.src_mac.isnot(None)).where(Event.src_mac != "")
        if time_from is not None:
            stmt = stmt.where(Event.ts_utc >= _ensure_utc(time_from))
        if time_to is not None:
            stmt = stmt.where(Event.ts_utc <= _ensure_utc(time_to))
        q1 = stmt.distinct()

        stmt2 = (
            select(Event.dest_ip, Event.dest_mac)
            .where(Event.device.in_(device_list))
            .where(Event.dest_ip.isnot(None))
            .where(Event.dest_ip != "")
        )
        if has_mac:
            stmt2 = stmt2.where(Event.dest_mac.isnot(None)).where(Event.dest_mac != "")
        if time_from is not None:
            stmt2 = stmt2.where(Event.ts_utc >= _ensure_utc(time_from))
        if time_to is not None:
            stmt2 = stmt2.where(Event.ts_utc <= _ensure_utc(time_to))
        q2 = stmt2.distinct()

        rows_src = db.execute(q1).all()
        rows_dst = db.execute(q2).all()
        seen: set[tuple[Optional[str], Optional[str]]] = set()
        for row in rows_src:
            ip, mac = (row[0], row[1]) if len(row) >= 2 else (row.src_ip, row.src_mac)
            if ip and str(ip).strip():
                seen.add((ip, mac or None))
        for row in rows_dst:
            ip, mac = (row[0], row[1]) if len(row) >= 2 else (row.dest_ip, row.dest_mac)
            if ip and str(ip).strip():
                seen.add((ip, mac or None))

        # Load NAT-translated IPs to exclude
        nat_sq = _nat_translated_ips_subquery(device_list)
        nat_ip_col = list(nat_sq.c)[0]
        nat_ips: set[str] = {
            row[0] for row in db.execute(select(nat_ip_col)).all() if row[0]
        }

        # Load Router MAC rules – exclude endpoints whose MAC is flagged (any member device)
        router_macs_all: set[str] = set()
        for rm in db.execute(select(RouterMac).where(RouterMac.device.in_(device_list))).scalars().all():
            router_macs_all.add(rm.mac)

        # Load device identifications for enrichment (any member device)
        devid_by_mac: dict[str, DeviceIdentification] = {}
        for di in db.execute(
            select(DeviceIdentification).where(DeviceIdentification.firewall_device.in_(device_list))
        ).scalars().all():
            devid_by_mac[di.srcmac] = di

        result: List[Dict[str, Any]] = []
        for ip, mac in sorted(seen, key=lambda x: (x[0] or "", x[1] or "")):
            # Skip NAT-translated IPs (these are not real endpoints)
            if ip and ip in nat_ips:
                continue
            # Skip if this MAC is flagged as a router MAC
            if mac and mac in router_macs_all:
                continue
            ep = db.execute(
                select(Endpoint).where(
                    Endpoint.device.in_(device_list),
                    Endpoint.ip == ip,
                    Endpoint.mac.is_(mac) if mac is None else Endpoint.mac == mac,
                ).limit(1)
            ).scalars().first()
            if ep is None:
                continue
            label = (ep.device_name or ep.ip) if ep.device_name and str(ep.device_name).strip() else (ep.ip or "")
            entry: Dict[str, Any] = {
                "id": ep.id,
                "ip": ep.ip,
                "mac": ep.mac,
                "device_name": ep.device_name,
                "label": label,
            }
            # Enrich with device identification: prefer endpoint's stored device_* (from DEVICE logs), else device_identifications by MAC
            ident: Dict[str, Any] = {}
            if ep.device_vendor:
                ident["device_vendor"] = ep.device_vendor
            if ep.device_type:
                ident["device_type"] = ep.device_type
            if ep.device_type_name:
                ident["device_type_name"] = ep.device_type_name
            if ep.device_os_name:
                ident["device_os_name"] = ep.device_os_name
            if ep.device_brand:
                ident["device_brand"] = ep.device_brand
            if ep.device_model:
                ident["device_model"] = ep.device_model
            if ep.hostname:
                ident["hostname"] = ep.hostname
            if not ident and mac:
                di = devid_by_mac.get(mac)
                if di:
                    if di.device_vendor:
                        ident["device_vendor"] = di.device_vendor
                    if di.device_type:
                        ident["device_type"] = di.device_type
                    if di.device_type_name:
                        ident["device_type_name"] = di.device_type_name
                    if di.device_os_name:
                        ident["device_os_name"] = di.device_os_name
                    if di.device_brand:
                        ident["device_brand"] = di.device_brand
                    if di.device_model:
                        ident["device_model"] = di.device_model
                    if di.hostname:
                        ident["hostname"] = di.hostname
            if ident:
                entry["identification"] = ident
            result.append(entry)

        # Local-only filter: when enabled (param or settings), keep only IPs in configured CIDRs
        ln_setting = get_setting(db, "local_networks")
        apply_local_filter = False
        if local_only is not None:
            apply_local_filter = local_only.lower() in ("true", "1", "yes")
        elif ln_setting and ln_setting.get("enabled"):
            apply_local_filter = True
        if apply_local_filter:
            cidr_strs: list = (ln_setting or {}).get("cidrs", [])
            if not cidr_strs:
                cidr_strs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            networks = []
            for c in cidr_strs:
                try:
                    networks.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
            if networks:
                local_result: List[Dict[str, Any]] = []
                for entry in result:
                    ip_str = entry.get("ip")
                    if not ip_str:
                        continue
                    try:
                        addr = ipaddress.ip_address(ip_str)
                        if any(addr in net for net in networks):
                            local_result.append(entry)
                    except ValueError:
                        pass
                result = local_result
        return result
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Helper: set of NAT-translated IPs for a device list
# ---------------------------------------------------------------------------

def _nat_translated_ips_subquery(device_list: List[str]):
    """Return a scalar subquery of DISTINCT IPs that appear as NAT translated
    addresses (xlat_src_ip or xlat_dest_ip) for the given device(s).

    Usage:  .where(Endpoint.ip.notin_(_nat_translated_ips_subquery(device_list)))
    """
    q1 = (
        select(Event.xlat_src_ip)
        .where(
            Event.device.in_(device_list),
            Event.xlat_src_ip.isnot(None),
            Event.xlat_src_ip != "",
        )
        .distinct()
    )
    q2 = (
        select(Event.xlat_dest_ip)
        .where(
            Event.device.in_(device_list),
            Event.xlat_dest_ip.isnot(None),
            Event.xlat_dest_ip != "",
        )
        .distinct()
    )
    return union(q1, q2).subquery("nat_ips")


# ---------------------------------------------------------------------------
# GET /api/endpoints/known — paginated endpoint listing with enrichment,
#   search, sorting, and HA deduplication
# ---------------------------------------------------------------------------


@router.get("/endpoints/known")
def list_known_endpoints(
    request: Request,
    device: str = Query(..., description="Firewall device name or ha:base"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=10, le=200),
    q: str = Query("", description="Case-insensitive search across name/ip/mac/vendor/type/os"),
    sort_by: str = Query("", description="Column to sort by"),
    sort_dir: str = Query("asc", description="asc or desc"),
    local_only: Optional[str] = Query(None, description="true/false — filter to local CIDRs"),
) -> Dict[str, Any]:
    """Return a paginated, de-duplicated list of known endpoints.

    For HA selections the same (ip, mac) seen on multiple member devices is
    merged into one row with aggregated stats.  Sorting, search, and
    pagination all operate on the merged result.
    """
    import logging
    _log = logging.getLogger(__name__)
    db: Session = get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return {"page": page, "page_size": page_size, "total": 0, "items": []}

        direction = "desc" if sort_dir not in ("asc", "desc") else sort_dir
        _log.info("endpoints/known sort_by=%r sort_dir=%r direction=%r devices=%r",
                   sort_by, sort_dir, direction, device_list)

        # ── Exclude NAT-translated IPs ──
        nat_sq = _nat_translated_ips_subquery(device_list)
        nat_ip_col = list(nat_sq.c)[0]

        # ── Single endpoint-candidates view: union src + dest from events, normalize MAC (empty -> NULL) ──
        mac_norm_src = func.nullif(Event.src_mac, "")
        mac_norm_dst = func.nullif(Event.dest_mac, "")
        _ev_where = [
            Event.device.in_(device_list),
            Event.src_ip.isnot(None),
        ]
        _ev_where_dst = [
            Event.device.in_(device_list),
            Event.dest_ip.isnot(None),
        ]
        src_q = (
            select(
                Event.src_ip.label("ip"),
                mac_norm_src.label("mac"),
                Event.ts_utc.label("ts_utc"),
                Event.device.label("device"),
            )
            .where(*_ev_where)
            .where(Event.src_ip.notin_(select(nat_ip_col)))
        )
        dst_q = (
            select(
                Event.dest_ip.label("ip"),
                mac_norm_dst.label("mac"),
                Event.ts_utc.label("ts_utc"),
                Event.device.label("device"),
            )
            .where(*_ev_where_dst)
            .where(Event.dest_ip.notin_(select(nat_ip_col)))
        )
        ev = union_all(src_q, dst_q).subquery("ev")

        # ── Single aggregation over union: GROUP BY (ip, mac) only; safe on SQLite and PostgreSQL ──
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
        ).subquery("agg")

        # ── Endpoint enrichment: one row per (ip, mac) from endpoints table ──
        ep_mac_norm = func.nullif(Endpoint.mac, "")
        ep_name_expr = func.max(func.coalesce(Endpoint.hostname, Endpoint.device_name)).label("ep_name")
        ep_hostname_expr = func.max(Endpoint.hostname).label("ep_hostname")
        ep_device_name_expr = func.max(Endpoint.device_name).label("ep_device_name")
        ep_vendor_expr = func.max(Endpoint.device_vendor).label("ep_vendor")
        ep_type_name_expr = func.max(Endpoint.device_type_name).label("ep_type_name")
        ep_os_name_expr = func.max(Endpoint.device_os_name).label("ep_os_name")
        ep_brand_expr = func.max(Endpoint.device_brand).label("ep_brand")
        ep_model_expr = func.max(Endpoint.device_model).label("ep_model")
        ep_id_expr = func.min(Endpoint.id).label("ep_id")
        base_where = [
            Endpoint.device.in_(device_list),
            Endpoint.ip.notin_(select(nat_ip_col)),
        ]
        ep_agg = (
            select(
                Endpoint.ip.label("ep_ip"),
                ep_mac_norm.label("mac_norm"),
                ep_id_expr,
                ep_name_expr,
                ep_hostname_expr,
                ep_device_name_expr,
                ep_vendor_expr,
                ep_type_name_expr,
                ep_os_name_expr,
                ep_brand_expr,
                ep_model_expr,
            )
            .where(*base_where)
            .group_by(Endpoint.ip, ep_mac_norm)
        ).subquery("ep_agg")

        # ── Join event-driven list to endpoint enrichment (same column names as before for search/sort/response) ──
        seen_count_col = agg.c.seen_count.label("seen_count")
        first_seen_col = agg.c.first_seen.label("first_seen")
        last_seen_col = agg.c.last_seen.label("last_seen")
        _join_on = (agg.c.ip == ep_agg.c.ep_ip) & (
            (agg.c.mac == ep_agg.c.mac_norm)
            | (agg.c.mac.is_(None) & ep_agg.c.mac_norm.is_(None))
        )
        joined = (
            select(
                ep_agg.c.ep_id,
                agg.c.ip.label("ep_ip"),
                agg.c.mac.label("mac_norm"),
                ep_agg.c.ep_name,
                ep_agg.c.ep_hostname,
                ep_agg.c.ep_device_name,
                ep_agg.c.ep_vendor,
                ep_agg.c.ep_type_name,
                ep_agg.c.ep_os_name,
                ep_agg.c.ep_brand,
                ep_agg.c.ep_model,
                seen_count_col,
                first_seen_col,
                last_seen_col,
            )
            .select_from(agg)
            .outerjoin(ep_agg, _join_on)
        )

        # ── Search filter (applied to aggregated columns + enriched vendor/type/os from device_identifications and overrides) ──
        search = q.strip()
        if search:
            like_pat = f"%{search}%"
            search_conditions = [
                ep_agg.c.ep_hostname.ilike(like_pat),
                ep_agg.c.ep_device_name.ilike(like_pat),
                agg.c.ip.ilike(like_pat),
                agg.c.mac.ilike(like_pat),
                ep_agg.c.ep_vendor.ilike(like_pat),
                ep_agg.c.ep_type_name.ilike(like_pat),
                ep_agg.c.ep_os_name.ilike(like_pat),
                ep_agg.c.ep_brand.ilike(like_pat),
                ep_agg.c.ep_model.ilike(like_pat),
            ]
            # Include MACs that match via device_identifications or device_overrides (enriched vendor/type/os)
            di_macs = [
                r[0] for r in db.execute(
                    select(DeviceIdentification.srcmac).where(
                        DeviceIdentification.firewall_device.in_(device_list),
                        or_(
                            DeviceIdentification.device_vendor.ilike(like_pat),
                            DeviceIdentification.device_type_name.ilike(like_pat),
                            DeviceIdentification.device_os_name.ilike(like_pat),
                            DeviceIdentification.device_brand.ilike(like_pat),
                            DeviceIdentification.device_model.ilike(like_pat),
                        ),
                    ).distinct()
                ).all()
                if r[0]
            ]
            ov_macs = [
                r[0] for r in db.execute(
                    select(DeviceOverride.mac).where(
                        DeviceOverride.firewall_device.in_(device_list),
                        or_(
                            DeviceOverride.override_vendor.ilike(like_pat),
                            DeviceOverride.override_type_name.ilike(like_pat),
                            DeviceOverride.override_os_name.ilike(like_pat),
                            DeviceOverride.override_brand.ilike(like_pat),
                            DeviceOverride.override_model.ilike(like_pat),
                            DeviceOverride.comment.ilike(like_pat),
                        ),
                    ).distinct()
                ).all()
                if r[0]
            ]
            enriched_macs = list(dict.fromkeys(di_macs + ov_macs))
            if enriched_macs:
                search_conditions.append(agg.c.mac.in_(enriched_macs))
            joined = joined.where(or_(*search_conditions))

        # ── Local-only CIDR filter ──
        # Resolve whether to apply: explicit param > stored setting
        ln_setting = get_setting(db, "local_networks")
        apply_local_filter = False
        if local_only is not None:
            apply_local_filter = local_only.lower() in ("true", "1", "yes")
        elif ln_setting and ln_setting.get("enabled"):
            apply_local_filter = True

        if apply_local_filter:
            cidr_strs: list[str] = (ln_setting or {}).get("cidrs", [])
            if not cidr_strs:
                cidr_strs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            networks = []
            for c in cidr_strs:
                try:
                    networks.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
            if networks:
                # Fetch all distinct IPs from current joined set, check in Python, build allowlist
                jsub = joined.subquery()
                ip_sq = select(jsub.c.ep_ip).select_from(jsub).distinct()
                all_ips = [row[0] for row in db.execute(ip_sq).all()]
                local_ips: set[str] = set()
                for ip_str in all_ips:
                    if not ip_str:
                        continue
                    try:
                        addr = ipaddress.ip_address(ip_str)
                        if any(addr in net for net in networks):
                            local_ips.add(ip_str)
                    except ValueError:
                        pass
                if local_ips:
                    joined = joined.where(agg.c.ip.in_(local_ips))
                else:
                    return {"page": page, "page_size": page_size, "total": 0, "items": []}

        # ── Count total (on joined, after search) ──
        count_stmt = select(func.count()).select_from(joined.subquery("cnt_sq"))
        total: int = db.execute(count_stmt).scalar() or 0

        if total == 0:
            return {"page": page, "page_size": page_size, "total": 0, "items": []}

        # ── Sorting ──
        _SORT_MAP = {
            "name": ep_agg.c.ep_name,
            "ip": agg.c.ip,
            "mac": agg.c.mac,
            "vendor": ep_agg.c.ep_vendor,
            "type": ep_agg.c.ep_type_name,
            "os": ep_agg.c.ep_os_name,
            "seen_count": seen_count_col,
            "first_seen": first_seen_col,
            "last_seen": last_seen_col,
        }
        # String columns: nulls last when asc, nulls first when desc
        _SORT_NULLS_LAST = {"vendor", "type", "os", "name"}

        order_clauses = []
        if sort_by in _SORT_MAP:
            col = _SORT_MAP[sort_by]
            if direction == "desc":
                order_clauses.append(col.desc().nulls_first() if sort_by in _SORT_NULLS_LAST else col.desc())
            else:
                order_clauses.append(col.asc().nulls_last() if sort_by in _SORT_NULLS_LAST else col.asc())

        if not order_clauses:
            order_clauses.append(ep_agg.c.ep_id.desc().nulls_last())

        # Tie-breaker
        order_clauses.append(agg.c.ip.asc())
        order_clauses.append(ep_agg.c.ep_id.asc().nulls_last())

        offset = (page - 1) * page_size
        rows = db.execute(
            joined.order_by(*order_clauses).offset(offset).limit(page_size)
        ).all()

        if not rows:
            return {"page": page, "page_size": page_size, "total": total, "items": []}

        # ── Enrichment fallback from device_identifications ──
        all_macs = {r.mac_norm for r in rows if r.mac_norm and r.mac_norm.strip()}
        devid_by_mac: Dict[str, DeviceIdentification] = {}
        if all_macs:
            for di in db.execute(
                select(DeviceIdentification).where(
                    DeviceIdentification.firewall_device.in_(device_list),
                    DeviceIdentification.srcmac.in_(all_macs),
                )
            ).scalars().all():
                devid_by_mac[di.srcmac] = di

        # ── Manual overrides (override wins if non-empty) ──
        override_by_mac: Dict[str, DeviceOverride] = {}
        if all_macs:
            for ov in db.execute(
                select(DeviceOverride).where(
                    DeviceOverride.firewall_device.in_(device_list),
                    DeviceOverride.mac.in_(all_macs),
                )
            ).scalars().all():
                override_by_mac[ov.mac] = ov

        def _iso(dt: Any) -> Optional[str]:
            if dt is None:
                return None
            if hasattr(dt, "isoformat"):
                return dt.isoformat()
            return str(dt)

        items: List[Dict[str, Any]] = []
        for r in rows:
            vendor = r.ep_vendor
            type_name = r.ep_type_name
            os_name = r.ep_os_name
            brand = r.ep_brand
            model = r.ep_model
            mac = r.mac_norm
            if not vendor and not type_name and mac and mac in devid_by_mac:
                di = devid_by_mac[mac]
                vendor = vendor or di.device_vendor
                type_name = type_name or di.device_type_name
                os_name = os_name or di.device_os_name
                brand = brand or di.device_brand
                model = model or di.device_model

            ov = override_by_mac.get(mac) if mac else None
            if ov:
                vendor = (ov.override_vendor or vendor) or None
                type_name = (ov.override_type_name or type_name) or None
                os_name = (ov.override_os_name or os_name) or None
                brand = (ov.override_brand or brand) or None
                model = (ov.override_model or model) or None

            has_override = bool(
                ov and (
                    ov.override_vendor or ov.override_type_name or ov.override_os_name
                    or ov.override_brand or ov.override_model or (ov.comment and ov.comment.strip())
                )
            )

            items.append({
                "endpoint_id": r.ep_id,
                "ip": r.ep_ip,
                "mac": mac,
                "device_name": r.ep_device_name,
                "hostname": r.ep_hostname,
                "first_seen": _iso(r.first_seen),
                "last_seen": _iso(r.last_seen),
                "seen_count": r.seen_count or 0,
                "vendor": (vendor or "").strip() if vendor else "",
                "type_name": (type_name or "").strip() if type_name else "",
                "os_name": (os_name or "").strip() if os_name else "",
                "brand": (brand or "").strip() if brand else "",
                "model": (model or "").strip() if model else "",
                "has_override": has_override,
                "comment": (ov.comment or None) if ov else None,
            })

        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "items": items,
        }
    finally:
        db.close()
