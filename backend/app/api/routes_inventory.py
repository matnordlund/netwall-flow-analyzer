"""Device Inventory: MAC-to-IP mapping analysis, Router MAC management, and device override CRUD."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .device_resolve import resolve_device
from ..ingest.reconstruct import normalize_mac
from ..storage.models import DeviceIdentification, DeviceOverride, Endpoint, Event, RouterMac

router = APIRouter(tags=["inventory"])

ROUTER_MAC_SUGGESTION_THRESHOLD = 10


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _get_db(request: Request) -> Session:
    return request.app.state.db_sessionmaker()


# ---------------------------------------------------------------------------
# GET /api/inventory/macs  –  MAC inventory with IP counts
# ---------------------------------------------------------------------------

@router.get("/inventory/macs")
def list_mac_inventory(
    request: Request,
    device: str = Query(..., description="Firewall device name"),
    time_from: Optional[datetime] = Query(None),
    time_to: Optional[datetime] = Query(None),
    threshold: int = Query(ROUTER_MAC_SUGGESTION_THRESHOLD, ge=1,
                           description="Distinct-IP count above which a MAC is suggested as router"),
) -> List[Dict[str, Any]]:
    """Return source-side MACs with their distinct IP counts for the selected device/time range.
    device can be a single device name or ha:base for HA cluster.
    """
    db = _get_db(request)
    try:
        device_list, _ = resolve_device(db, device)
        if not device_list:
            return []
        time_from = _ensure_utc(time_from)
        time_to = _ensure_utc(time_to)

        # Query: group by src_mac, count distinct src_ip, sample IPs, max ts
        stmt = (
            select(
                Event.src_mac,
                func.count(func.distinct(Event.src_ip)).label("distinct_ip_count"),
                func.max(Event.ts_utc).label("last_seen"),
            )
            .where(Event.device.in_(device_list))
            .where(Event.src_mac.isnot(None))
            .where(Event.src_mac != "")
        )
        if time_from is not None:
            stmt = stmt.where(Event.ts_utc >= time_from)
        if time_to is not None:
            stmt = stmt.where(Event.ts_utc <= time_to)
        stmt = stmt.group_by(Event.src_mac).order_by(func.count(func.distinct(Event.src_ip)).desc())

        rows = db.execute(stmt).all()

        # Fetch currently flagged router MACs for this device (any member)
        flagged_macs: set[str] = set()
        for rm in db.execute(select(RouterMac).where(RouterMac.device.in_(device_list))).scalars().all():
            flagged_macs.add(rm.mac)

        result: List[Dict[str, Any]] = []
        for row in rows:
            mac = row.src_mac
            ip_count = row.distinct_ip_count
            last_seen = row.last_seen

            # Fetch up to 3 sample IPs for this MAC
            sample_stmt = (
                select(func.distinct(Event.src_ip))
                .where(Event.device.in_(device_list))
                .where(Event.src_mac == mac)
            )
            if time_from is not None:
                sample_stmt = sample_stmt.where(Event.ts_utc >= time_from)
            if time_to is not None:
                sample_stmt = sample_stmt.where(Event.ts_utc <= time_to)
            sample_stmt = sample_stmt.limit(3)
            sample_ips = [r[0] for r in db.execute(sample_stmt).all() if r[0]]

            result.append({
                "mac": mac,
                "distinct_ip_count": ip_count,
                "sample_ips": sample_ips,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "suggested_router": ip_count >= threshold,
                "flagged": mac in flagged_macs,
            })

        return result
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Router MAC CRUD
# ---------------------------------------------------------------------------

class RouterMacPayload(BaseModel):
    device: str
    mac: str
    direction: str = "src"  # src | dest | both


@router.get("/router-macs")
def get_router_macs(
    request: Request,
    device: Optional[str] = Query(None, description="Filter by firewall device or ha:base"),
) -> List[Dict[str, Any]]:
    db = _get_db(request)
    try:
        stmt = select(RouterMac)
        if device:
            device_list, _ = resolve_device(db, device)
            if device_list:
                stmt = stmt.where(RouterMac.device.in_(device_list))
            else:
                stmt = stmt.where(RouterMac.device == device)
        macs = db.execute(stmt).scalars().all()
        return [
            {
                "id": rm.id,
                "device": rm.device,
                "mac": rm.mac,
                "direction": rm.direction,
                "created_at": rm.created_at.isoformat() if rm.created_at else None,
            }
            for rm in macs
        ]
    finally:
        db.close()


@router.post("/router-macs")
def upsert_router_mac(
    request: Request,
    payload: RouterMacPayload,
) -> Dict[str, Any]:
    if payload.direction not in ("src", "dest", "both"):
        raise HTTPException(status_code=400, detail="direction must be src, dest, or both")
    db = _get_db(request)
    try:
        device_list, _ = resolve_device(db, payload.device)
        if not device_list:
            device_list = [payload.device]
        # When HA cluster: ensure MAC is flagged for all member devices
        first_rm: Optional[RouterMac] = None
        any_created = False
        for dev in device_list:
            existing = db.execute(
                select(RouterMac).where(
                    RouterMac.device == dev,
                    RouterMac.mac == payload.mac,
                    RouterMac.direction == payload.direction,
                )
            ).scalar_one_or_none()
            if existing:
                if first_rm is None:
                    first_rm = existing
                continue
            rm = RouterMac(
                device=dev,
                mac=payload.mac,
                direction=payload.direction,
            )
            db.add(rm)
            any_created = True
            if first_rm is None:
                first_rm = rm
        db.commit()
        if first_rm is not None:
            db.refresh(first_rm)
        return {
            "id": first_rm.id,
            "device": first_rm.device,
            "mac": first_rm.mac,
            "direction": first_rm.direction,
            "created_at": first_rm.created_at.isoformat() if first_rm.created_at else None,
            "status": "created" if any_created else "already_exists",
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@router.delete("/router-macs/{mac_id}")
def delete_router_mac(
    request: Request,
    mac_id: int,
) -> Dict[str, str]:
    db = _get_db(request)
    try:
        rm = db.execute(select(RouterMac).where(RouterMac.id == mac_id)).scalar_one_or_none()
        if rm is None:
            raise HTTPException(status_code=404, detail="Router MAC not found")
        db.delete(rm)
        db.commit()
        return {"status": "deleted"}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Device details + manual overrides (GET / PUT device-inventory/{mac})
# ---------------------------------------------------------------------------

def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


@router.get("/device-inventory/{mac}")
def get_device_inventory_details(
    request: Request,
    mac: str,
    device: str = Query(..., description="Firewall device or ha:base"),
) -> Dict[str, Any]:
    """Return device details for a given MAC: identity, auto-detection, and overrides."""
    db = _get_db(request)
    try:
        normalized = normalize_mac(mac)
        if not normalized:
            raise HTTPException(status_code=400, detail="Invalid or empty MAC")
        device_list, _ = resolve_device(db, device)
        if not device_list:
            raise HTTPException(status_code=400, detail="Unknown device")

        # One representative IP for this (device_list, mac): pick from endpoints
        ep_row = db.execute(
            select(Endpoint.ip, Endpoint.device_name)
            .where(Endpoint.device.in_(device_list))
            .where(Endpoint.mac == normalized)
            .order_by(Endpoint.id.desc())
            .limit(1)
        ).first()
        if not ep_row:
            raise HTTPException(status_code=404, detail="Device not found for this MAC")
        rep_ip = ep_row[0]
        device_name = ep_row[1]

        # first_seen, last_seen, seen_count from events (src or dest with this mac)
        src_agg = (
            select(
                func.count(Event.id).label("cnt"),
                func.min(Event.ts_utc).label("first"),
                func.max(Event.ts_utc).label("last"),
            )
            .where(Event.device.in_(device_list))
            .where(Event.src_mac == normalized)
        )
        dst_agg = (
            select(
                func.count(Event.id).label("cnt"),
                func.min(Event.ts_utc).label("first"),
                func.max(Event.ts_utc).label("last"),
            )
            .where(Event.device.in_(device_list))
            .where(Event.dest_mac == normalized)
        )
        src_row = db.execute(src_agg).first()
        dst_row = db.execute(dst_agg).first()
        seen_count = (src_row[0] or 0) + (dst_row[0] or 0)
        first_src = src_row[1] if src_row else None
        first_dst = dst_row[1] if dst_row else None
        last_src = src_row[2] if src_row else None
        last_dst = dst_row[2] if dst_row else None
        first_seen = min((x for x in (first_src, first_dst) if x is not None), default=None)
        last_seen = max((x for x in (last_src, last_dst) if x is not None), default=None)

        # Auto: from device_identifications (any member)
        auto: Dict[str, Optional[str]] = {
            "vendor": None,
            "type_name": None,
            "os_name": None,
            "brand": None,
            "model": None,
        }
        for di in db.execute(
            select(DeviceIdentification).where(
                DeviceIdentification.firewall_device.in_(device_list),
                DeviceIdentification.srcmac == normalized,
            )
        ).scalars().all():
            if di.device_vendor:
                auto["vendor"] = di.device_vendor
            if di.device_type_name:
                auto["type_name"] = di.device_type_name
            if di.device_os_name:
                auto["os_name"] = di.device_os_name
            if di.device_brand:
                auto["brand"] = di.device_brand
            if di.device_model:
                auto["model"] = di.device_model
            break

        # Override: from device_overrides (any member; first wins)
        override: Dict[str, Optional[str]] = {
            "vendor": None,
            "type_name": None,
            "os_name": None,
            "brand": None,
            "model": None,
            "comment": None,
        }
        for ov in db.execute(
            select(DeviceOverride).where(
                DeviceOverride.firewall_device.in_(device_list),
                DeviceOverride.mac == normalized,
            )
        ).scalars().all():
            override["vendor"] = ov.override_vendor
            override["type_name"] = ov.override_type_name
            override["os_name"] = ov.override_os_name
            override["brand"] = ov.override_brand
            override["model"] = ov.override_model
            override["comment"] = ov.comment
            break

        return {
            "ip": rep_ip,
            "mac": normalized,
            "device_name": device_name,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
            "seen_count": seen_count,
            "auto": auto,
            "override": override,
        }
    finally:
        db.close()


class DeviceOverridePayload(BaseModel):
    device: str
    override: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="vendor, type_name, os_name, brand, model, comment",
    )


@router.put("/device-inventory/{mac}")
def put_device_inventory_override(
    request: Request,
    mac: str,
    payload: DeviceOverridePayload,
) -> Dict[str, Any]:
    """Upsert manual override for a device (by MAC). For HA, writes to all members."""
    db = _get_db(request)
    try:
        normalized = normalize_mac(mac)
        if not normalized:
            raise HTTPException(status_code=400, detail="Invalid or empty MAC")
        device_list, _ = resolve_device(db, payload.device)
        if not device_list:
            raise HTTPException(status_code=400, detail="Unknown device")

        o = payload.override or {}
        vendor = (o.get("vendor") or "").strip() or None
        type_name = (o.get("type_name") or "").strip() or None
        os_name = (o.get("os_name") or "").strip() or None
        brand = (o.get("brand") or "").strip() or None
        model = (o.get("model") or "").strip() or None
        raw_comment = (o.get("comment") or "").strip() or None
        if raw_comment is not None and len(raw_comment) > 2000:
            raise HTTPException(
                status_code=400,
                detail="Comment must be 2000 characters or fewer",
            )
        comment = raw_comment

        now = datetime.now(timezone.utc)
        for dev in device_list:
            existing = db.execute(
                select(DeviceOverride).where(
                    DeviceOverride.firewall_device == dev,
                    DeviceOverride.mac == normalized,
                )
            ).scalar_one_or_none()
            if existing:
                existing.override_vendor = vendor
                existing.override_type_name = type_name
                existing.override_os_name = os_name
                existing.override_brand = brand
                existing.override_model = model
                existing.comment = comment
                existing.updated_at = now
            else:
                db.add(
                    DeviceOverride(
                        firewall_device=dev,
                        mac=normalized,
                        override_vendor=vendor,
                        override_type_name=type_name,
                        override_os_name=os_name,
                        override_brand=brand,
                        override_model=model,
                        comment=comment,
                        updated_at=now,
                    )
                )
        db.commit()
        return {"ok": True, "mac": normalized}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
