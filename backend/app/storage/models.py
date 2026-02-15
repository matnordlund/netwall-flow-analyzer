from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    raw_record: Mapped[str] = mapped_column(Text)
    parse_status: Mapped[str] = mapped_column(String(32), default="ok", index=True)
    parse_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    ts_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    device: Mapped[str] = mapped_column(String(255), index=True)  # kept for backward compat; prefer firewall_key for HA
    device_member: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)  # raw hostname / member
    firewall_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)  # canonical (ha:base or device)
    event_type: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    action: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    rule: Mapped[Optional[str]] = mapped_column(String(255))
    satsrcrule: Mapped[Optional[str]] = mapped_column(String(255))
    satdestrule: Mapped[Optional[str]] = mapped_column(String(255))
    srcusername: Mapped[Optional[str]] = mapped_column(String(255))
    destusername: Mapped[Optional[str]] = mapped_column(String(255))

    # Original tuple
    proto: Mapped[Optional[str]] = mapped_column(String(16), index=True)
    recv_if: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    recv_zone: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    src_mac: Mapped[Optional[str]] = mapped_column(String(64))
    src_device: Mapped[Optional[str]] = mapped_column(String(255))
    dest_if: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    dest_zone: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    dest_port: Mapped[Optional[int]] = mapped_column(Integer)
    dest_mac: Mapped[Optional[str]] = mapped_column(String(64))
    dest_device: Mapped[Optional[str]] = mapped_column(String(255))

    # Translated (NAT/SAT)
    xlat_src_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    xlat_src_port: Mapped[Optional[int]] = mapped_column(Integer)
    xlat_dest_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    xlat_dest_port: Mapped[Optional[int]] = mapped_column(Integer)

    bytes_orig: Mapped[Optional[int]] = mapped_column(Integer)
    bytes_term: Mapped[Optional[int]] = mapped_column(Integer)
    duration_s: Mapped[Optional[int]] = mapped_column(Integer)

    app_name: Mapped[Optional[str]] = mapped_column(String(255))
    app_risk: Mapped[Optional[str]] = mapped_column(String(64))
    app_family: Mapped[Optional[str]] = mapped_column(String(255))

    # IP reputation (flattened for convenience)
    iprep_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    iprep_score: Mapped[Optional[int]] = mapped_column(Integer)
    iprep_categories: Mapped[Optional[str]] = mapped_column(String(255))
    iprep_src: Mapped[Optional[str]] = mapped_column(String(64))
    iprep_dest: Mapped[Optional[str]] = mapped_column(String(64))
    iprep_src_score: Mapped[Optional[int]] = mapped_column(Integer)
    iprep_dest_score: Mapped[Optional[int]] = mapped_column(Integer)

    recv_side: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    dest_side: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    direction_bucket: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    extra_json: Mapped[dict] = mapped_column(JSON, default=dict)


class ClassificationKind(str):
    ZONE = "zone"
    INTERFACE = "interface"


class ClassificationSide(str):
    INSIDE = "inside"
    OUTSIDE = "outside"
    REMOTE = "remote"
    UNKNOWN = "unknown"


class Classification(Base):
    __tablename__ = "classifications"
    __table_args__ = (
        UniqueConstraint("device", "kind", "name", name="uq_classification_device_kind_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    side: Mapped[str] = mapped_column(String(16), default=ClassificationSide.UNKNOWN, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)


class UnclassifiedEndpoint(Base):
    __tablename__ = "unclassified_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "device",
            "kind",
            "name",
            name="uq_unclassified_device_kind_name",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # "zone" or "interface"
    name: Mapped[str] = mapped_column(String(255), index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    mac: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Enriched from DEVICE logs (id=08900001) when device_ip4 + srcmac match this endpoint's ip + mac
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_ip4: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_ip6: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    device_vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type_group_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_brand: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_rank: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("device", "ip", "mac", name="uq_endpoint_device_ip_mac"),
    )


class Flow(Base):
    """Aggregated flow (direction/zone/interface). One row per (device, basis, from_value, to_value, proto, dest_port, src_ep, dst_ep, view_kind)."""
    __tablename__ = "flows"
    __table_args__ = (
        UniqueConstraint(
            "device",
            "basis",
            "from_value",
            "to_value",
            "proto",
            "dest_port",
            "src_endpoint_id",
            "dst_endpoint_id",
            "view_kind",
            name="ux_flows_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device: Mapped[str] = mapped_column(String(255), index=True)
    basis: Mapped[str] = mapped_column(String(16), index=True)  # side|zone|interface
    from_value: Mapped[str] = mapped_column(String(255), index=True)
    to_value: Mapped[str] = mapped_column(String(255), index=True)

    proto: Mapped[Optional[str]] = mapped_column(String(16), index=True)
    dest_port: Mapped[Optional[int]] = mapped_column(Integer, index=True)

    src_endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    dst_endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)

    view_kind: Mapped[str] = mapped_column(String(16), default="original", index=True)  # original|translated

    count_open: Mapped[int] = mapped_column(Integer, default=0)
    count_close: Mapped[int] = mapped_column(Integer, default=0)
    bytes_src_to_dst: Mapped[int] = mapped_column(Integer, default=0)
    bytes_dst_to_src: Mapped[int] = mapped_column(Integer, default=0)
    duration_total_s: Mapped[int] = mapped_column(Integer, default=0)

    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)

    top_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    top_apps: Mapped[dict] = mapped_column(JSON, default=dict)


class DeviceIdentification(Base):
    """Persisted DEVICE identification info, keyed by (firewall_device, srcmac)."""
    __tablename__ = "device_identifications"
    __table_args__ = (
        UniqueConstraint("firewall_device", "srcmac", name="uq_devid_device_mac"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    firewall_device: Mapped[str] = mapped_column(String(255), index=True)
    srcmac: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    if_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    zone: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_ip4: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_ip6: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    device_vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type_group_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_brand: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_rank: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_event_json: Mapped[dict] = mapped_column(JSON, default=dict)


class HaCluster(Base):
    """User-confirmed HA cluster: Master + Slave combined for display and aggregation."""
    __tablename__ = "ha_clusters"
    __table_args__ = (UniqueConstraint("base", name="uq_ha_cluster_base"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    base: Mapped[str] = mapped_column(String(255), index=True, unique=True)
    label: Mapped[str] = mapped_column(String(255))
    members: Mapped[list] = mapped_column(JSON, default=list)  # ["gw-mand_Master", "gw-mand_Slave"]
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class FirewallInventory(Base):
    """Tracks firewall source (syslog vs import) and timestamps. Used for retention (only syslog data is purged by retention)."""
    __tablename__ = "firewalls"

    device_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    source_syslog: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 1 if ever seen from live syslog
    source_import: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 1 if ever imported from file
    first_seen_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_import_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class FirewallOverride(Base):
    """Display name and comment overrides per firewall (canonical device_key: standalone device or HA base)."""
    __tablename__ = "firewall_overrides"

    device_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class AppSetting(Base):
    """Key-value settings store with JSON values."""
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value_json: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DeviceOverride(Base):
    """Manual overrides for device metadata (vendor, type, OS, brand, model, comment).
    Keyed by (firewall_device, mac). Override wins over auto-detection when non-empty.
    """
    __tablename__ = "device_overrides"
    __table_args__ = (
        UniqueConstraint("firewall_device", "mac", name="uq_device_override_device_mac"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    firewall_device: Mapped[str] = mapped_column(String(255), index=True)
    mac: Mapped[str] = mapped_column(String(64), index=True)
    override_os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    override_type_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    override_vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    override_brand: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    override_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class RouterMac(Base):
    """MACs flagged as router next-hop addresses.

    Traffic behind these MACs is grouped behind a Router bucket instead of
    spawning a separate endpoint node per IP.
    """
    __tablename__ = "router_macs"
    __table_args__ = (
        UniqueConstraint("device", "mac", "direction", name="uq_router_mac_device_mac_dir"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    mac: Mapped[str] = mapped_column(String(64), index=True)
    direction: Mapped[str] = mapped_column(String(8), default="src")  # src | dest | both
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )


class IngestJob(Base):
    """Async upload/ingest job for syslog file imports. Status: queued | uploading | running | done | error | canceled."""
    __tablename__ = "ingest_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    status: Mapped[str] = mapped_column(String(32), index=True, default="queued")
    phase: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # parsing | finalizing (optional override)
    filename: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    bytes_total: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    device_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)  # canonical firewall key (HA)

    lines_total: Mapped[int] = mapped_column(Integer, default=0)
    lines_processed: Mapped[int] = mapped_column(Integer, default=0)
    parse_ok: Mapped[int] = mapped_column(Integer, default=0)
    parse_err: Mapped[int] = mapped_column(Integer, default=0)
    filtered_id: Mapped[int] = mapped_column(Integer, default=0)
    raw_logs_inserted: Mapped[int] = mapped_column(Integer, default=0)
    events_inserted: Mapped[int] = mapped_column(Integer, default=0)

    time_min: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    time_max: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_detected: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_display: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # e.g. IntegrityError, OperationalError
    error_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # upload | parse | persist | flow_aggregation

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class MaintenanceJob(Base):
    """Background maintenance job (e.g. purge_firewall). Status: queued | running | done | error."""
    __tablename__ = "maintenance_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    type: Mapped[str] = mapped_column(String(64), index=True)  # purge_firewall
    status: Mapped[str] = mapped_column(String(32), index=True, default="queued")
    device_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    result_counts: Mapped[dict] = mapped_column(JSON, default=dict)  # events_deleted, raw_logs_deleted, etc.
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

