"""Pure HA canonicalization: device_raw -> firewall_key. No DB dependency."""

from __future__ import annotations

# Must match routes_zones / device_resolve
HA_MASTER_SUFFIX = "_Master"
HA_SLAVE_SUFFIX = "_Slave"


def canonical_firewall_key(device_raw: str | None) -> tuple[str, dict]:
    """Return (firewall_key, meta) for a raw device name.

    - gw-foo_Master / gw-foo_Slave -> ("ha:gw-foo", {"member": device_raw})
    - Standalone device -> (device_raw, {})

    Use firewall_key for inventory, endpoints, flows. Use device_member for display/raw.
    """
    if not device_raw or not (d := device_raw.strip()):
        return (d or "", {})

    if d.endswith(HA_MASTER_SUFFIX):
        base = d[: -len(HA_MASTER_SUFFIX)].strip()
        key = f"ha:{base}" if base else d
        return (key, {"member": d})
    if d.endswith(HA_SLAVE_SUFFIX):
        base = d[: -len(HA_SLAVE_SUFFIX)].strip()
        key = f"ha:{base}" if base else d
        return (key, {"member": d})
    return (d, {})


def canonical_firewall_key_syslog(device_raw: str | None) -> str:
    """Canonical key for syslog-only: _Master/_Slave -> ha:base. Use only in syslog ingestion paths."""
    key, _ = canonical_firewall_key(device_raw)
    return key


def canonical_firewall_key_import(device_raw: str | None) -> str:
    """Canonical key for import: no HA logic; import firewalls are always single-node. Use only in import path."""
    if not device_raw:
        return ""
    return device_raw.strip()
