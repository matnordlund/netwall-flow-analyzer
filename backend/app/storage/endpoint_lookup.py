"""Shared endpoint lookup by (device, ip, mac). Tolerant of duplicates: returns newest row."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Endpoint


def get_endpoint_by_device_ip_mac(
    db: Session, device: str, ip: Optional[str], mac: Optional[str]
) -> Optional[Endpoint]:
    """Return one endpoint for (device, ip, mac). When multiple rows exist (e.g. NULL mac),
    returns the newest by id. Prevents MultipleResultsFound in API."""
    if not ip:
        return None
    mac_norm = (mac or "").strip() or None
    stmt = (
        select(Endpoint)
        .where(
            Endpoint.device == device,
            Endpoint.ip == ip,
            Endpoint.mac.is_(mac_norm) if mac_norm is None else Endpoint.mac == mac_norm,
        )
        .order_by(Endpoint.id.desc())
    )
    return db.execute(stmt).scalars().first()
