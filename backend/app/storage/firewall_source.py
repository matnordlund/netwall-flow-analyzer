"""Track firewall data source (syslog vs import) for retention and UI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import FirewallInventory, HaCluster


def get_canonical_device_key(db: Session, device_name: str) -> str:
    """Return canonical device_key for a device (e.g. gw-mand_Master -> ha:gw-mand, fw1 -> fw1)."""
    if not device_name or not device_name.strip():
        return device_name or ""
    device_name = device_name.strip()
    clusters = db.execute(select(HaCluster).where(HaCluster.is_enabled.is_(True))).scalars().all()
    for c in clusters:
        members = list(c.members) if isinstance(c.members, list) else []
        if device_name in members:
            return f"ha:{c.base}"
    return device_name


def upsert_firewall_syslog(db: Session, device_key: str, ts_utc: datetime) -> None:
    """Mark firewall as having received live syslog; update first/last seen."""
    now = datetime.now(timezone.utc)
    if ts_utc.tzinfo is None:
        ts_utc = ts_utc.replace(tzinfo=timezone.utc)
    row = db.get(FirewallInventory, device_key)
    if not row:
        db.add(FirewallInventory(
            device_key=device_key,
            source_syslog=1,
            source_import=0,
            first_seen_ts=ts_utc,
            last_seen_ts=ts_utc,
            last_import_ts=None,
            updated_at=now,
        ))
    else:
        row.source_syslog = 1
        first = _ensure_utc(row.first_seen_ts)
        last = _ensure_utc(row.last_seen_ts)
        if first is None or ts_utc < first:
            row.first_seen_ts = ts_utc
        if last is None or ts_utc > last:
            row.last_seen_ts = ts_utc
        row.updated_at = now


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def upsert_firewall_import(
    db: Session,
    device_key: str,
    first_ts: Optional[datetime] = None,
    last_ts: Optional[datetime] = None,
) -> None:
    """Mark firewall as having imported data; set last_import_ts and optionally first/last seen."""
    now = datetime.now(timezone.utc)
    first_ts = _ensure_utc(first_ts)
    last_ts = _ensure_utc(last_ts)
    row = db.get(FirewallInventory, device_key)
    if not row:
        db.add(FirewallInventory(
            device_key=device_key,
            source_syslog=0,
            source_import=1,
            first_seen_ts=first_ts,
            last_seen_ts=last_ts,
            last_import_ts=now,
            updated_at=now,
        ))
    else:
        row.source_import = 1
        row.last_import_ts = now
        first = _ensure_utc(row.first_seen_ts)
        last = _ensure_utc(row.last_seen_ts)
        if first_ts is not None:
            if first is None or first_ts < first:
                row.first_seen_ts = first_ts
        if last_ts is not None:
            if last is None or last_ts > last:
                row.last_seen_ts = last_ts
        row.updated_at = now


def get_syslog_device_keys(db: Session) -> list[str]:
    """Return list of device_keys where source_syslog=1 (for retention: only these are purged)."""
    rows = db.execute(
        select(FirewallInventory.device_key).where(FirewallInventory.source_syslog == 1)
    ).scalars().all()
    return list(rows)


def expand_device_keys_to_member_devices(db: Session, device_keys: list[str]) -> list[str]:
    """Expand device_keys to concrete device names (for events/raw_logs device column). HA -> members, else [key]."""
    out: list[str] = []
    for key in device_keys:
        if key.startswith("ha:"):
            base = key[3:].strip()
            cluster = db.execute(select(HaCluster).where(HaCluster.base == base)).scalars().one_or_none()
            if cluster and cluster.members:
                out.extend(list(cluster.members) if isinstance(cluster.members, list) else [])
            else:
                out.append(key)
        else:
            out.append(key)
    return out
