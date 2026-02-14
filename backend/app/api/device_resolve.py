"""Resolve device parameter (single or ha:base) to list of device names and display label."""

from __future__ import annotations

from typing import List, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..storage.models import FirewallOverride, HaCluster

HA_PREFIX = "ha:"
HA_MASTER_SUFFIX = "_Master"
HA_SLAVE_SUFFIX = "_Slave"


def _apply_firewall_override(db: Session, device_key: str, default_label: str) -> str:
    """Return firewall_overrides.display_name if set, else default_label."""
    row = db.execute(
        select(FirewallOverride).where(FirewallOverride.device_key == device_key)
    ).scalar_one_or_none()
    if row and (row.display_name or "").strip():
        return (row.display_name or "").strip()
    return default_label


def get_device_display_label(db: Session, device: str) -> str:
    """Return display label for a device (override > HA label > raw device)."""
    if not device or not device.strip():
        return device or ""
    device = device.strip()
    if device.endswith(HA_MASTER_SUFFIX):
        base = device[: -len(HA_MASTER_SUFFIX)]
    elif device.endswith(HA_SLAVE_SUFFIX):
        base = device[: -len(HA_SLAVE_SUFFIX)]
    else:
        return _apply_firewall_override(db, device, device)
    if not base:
        return device
    cluster = db.execute(select(HaCluster).where(HaCluster.base == base)).scalar_one_or_none()
    if cluster and cluster.is_enabled:
        default = cluster.label or f"{base} (HA)"
        return _apply_firewall_override(db, base, default)
    return device


def resolve_device(db: Session, device: str) -> Tuple[List[str], str]:
    """Resolve device param to (list of device names for Event.device IN, display label).

    - If device is "ha:base": look up HaCluster by base; return (members, label) or ([base_Master, base_Slave], "base (HA)").
    - Otherwise: return ([device], device).
    """
    if not device or not device.strip():
        return [], ""
    device = device.strip()
    if device.startswith(HA_PREFIX):
        base = device[len(HA_PREFIX) :].strip()
        if not base:
            return [], ""
        cluster = db.execute(select(HaCluster).where(HaCluster.base == base)).scalar_one_or_none()
        if cluster and cluster.is_enabled and cluster.members:
            members = list(cluster.members) if isinstance(cluster.members, list) else []
            default_label = cluster.label or f"{base} (HA)"
            label = _apply_firewall_override(db, base, default_label)
            return members, label
        # Fallback: not configured yet, still resolve to expected members
        label = _apply_firewall_override(db, base, f"{base} (HA)")
        return [base + "_Master", base + "_Slave"], label
    label = _apply_firewall_override(db, device, device)
    return [device], label
