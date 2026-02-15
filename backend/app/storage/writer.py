"""Single-writer batch persist: raw_logs, events, firewalls, endpoints, flows. Core only; one transaction per batch."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from .models import Endpoint, Event, FirewallInventory, Flow, RawLog

logger = logging.getLogger("netwall.writer")

ENDPOINT_UQ = ["device", "ip", "mac"]
FLOW_IDENTITY = [
    "device", "basis", "from_value", "to_value", "proto", "dest_port",
    "src_endpoint_id", "dst_endpoint_id", "view_kind",
]


@dataclass
class ParsedBatch:
    """One batch of parsed records to persist. All lists are dicts keyed by column names (omit id)."""
    raw_logs: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def firewall_keys(self) -> set[str]:
        out: set[str] = set()
        for e in self.events:
            fk = e.get("firewall_key") or e.get("device")
            if fk:
                out.add(fk)
        return out


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)  # type: ignore
    return dt


class Writer:
    """One-writer-per-engine. For SQLite, serializes write_batch with a lock. Uses Core + upserts only."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._is_sqlite = engine.dialect.name == "sqlite"
        self._lock = threading.Lock() if self._is_sqlite else threading.RLock()  # RLock no-op for single writer

    def write_batch(self, batch: ParsedBatch, job_id: str | None = None) -> None:
        """Persist one batch in a single transaction. No flush() inside; Core/raw SQL only."""
        if self._is_sqlite:
            with self._lock:
                self._write_batch_inner(batch, job_id)
        else:
            self._write_batch_inner(batch, job_id)

    def _configure_sqlite_connection(self, session: Session) -> None:
        """Apply ingest-friendly PRAGMAs for SQLite (WAL, busy_timeout, etc.)."""
        if session.get_bind().dialect.name != "sqlite":
            return
        for stmt in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA busy_timeout=10000",
            "PRAGMA temp_store=MEMORY",
        ):
            session.execute(text(stmt))

    def _write_batch_inner(self, batch: ParsedBatch, job_id: str | None) -> None:
        session_factory = sessionmaker(bind=self._engine, autoflush=False, autocommit=False, expire_on_commit=False)
        session = session_factory()
        try:
            self._configure_sqlite_connection(session)
            with session.begin():
                if batch.raw_logs:
                    session.bulk_insert_mappings(RawLog, batch.raw_logs)
                if batch.events:
                    session.bulk_insert_mappings(Event, batch.events)
                for fk in batch.firewall_keys:
                    self._upsert_firewall_inventory(session, fk)
                ep_key_to_id = self._upsert_endpoints_from_events(session, batch.events)
                self._upsert_flows_from_events(session, batch.events, ep_key_to_id)
        finally:
            session.close()

    def _upsert_firewall_inventory(self, session: Session, device_key: str) -> None:
        now = datetime.now(timezone.utc)
        table = FirewallInventory.__table__
        dialect = session.get_bind().dialect.name
        values = {
            "device_key": device_key,
            "source_syslog": 0,
            "source_import": 1,
            "first_seen_ts": now,
            "last_seen_ts": now,
            "last_import_ts": now,
            "updated_at": now,
        }
        if dialect == "postgresql":
            ins = pg_insert(table).values(**values)
            stmt = ins.on_conflict_do_update(
                index_elements=["device_key"],
                set_={
                    "source_import": 1,
                    "last_import_ts": now,
                    "updated_at": now,
                },
            )
        else:
            ins = sqlite_insert(table).values(**values)
            stmt = ins.on_conflict_do_update(
                index_elements=["device_key"],
                set_={
                    "source_import": 1,
                    "last_import_ts": now,
                    "updated_at": now,
                },
            )
        session.execute(stmt)

    def _upsert_endpoints_from_events(
        self, session: Session, events: list[dict]
    ) -> dict[tuple[str, str, Optional[str]], int]:
        """Upsert all unique (device=firewall_key, ip, mac) from events; return (device, ip, mac) -> id."""
        seen: set[tuple[str, str, Optional[str]]] = set()
        rows: list[tuple[str, str, Optional[str], Optional[str]]] = []
        for e in events:
            fk = (e.get("firewall_key") or e.get("device") or "").strip()
            if not fk:
                continue
            for ip_key, mac_key, name_key in [
                ("src_ip", "src_mac", "src_device"),
                ("dest_ip", "dest_mac", "dest_device"),
                ("xlat_src_ip", "src_mac", "src_device"),
                ("xlat_dest_ip", "dest_mac", "dest_device"),
            ]:
                ip_val = (e.get(ip_key) or "").strip() or None
                if not ip_val:
                    continue
                mac_val = (e.get(mac_key) or "").strip() or None
                name_val = (e.get(name_key) or "").strip() or None
                key = (fk, ip_val, mac_val)
                if key not in seen:
                    seen.add(key)
                    rows.append((fk, ip_val, mac_val, name_val))

        for (device, ip, mac, device_name) in rows:
            self._upsert_one_endpoint(session, device, ip, mac, device_name)

        # Resolve ids
        id_map: dict[tuple[str, str, Optional[str]], int] = {}
        if not rows:
            return id_map
        for (device, ip, mac, _) in rows:
            r = session.execute(
                select(Endpoint.id).where(
                    Endpoint.device == device,
                    Endpoint.ip == ip,
                    Endpoint.mac.is_(mac) if mac is None else Endpoint.mac == mac,
                ).limit(1)
            ).scalar_one_or_none()
            if r is not None:
                id_map[(device, ip, mac)] = r
        return id_map

    def _upsert_one_endpoint(
        self,
        session: Session,
        device: str,
        ip: str,
        mac: Optional[str],
        device_name: Optional[str],
    ) -> None:
        table = Endpoint.__table__
        dialect = session.get_bind().dialect.name
        values = {
            "device": device,
            "ip": ip,
            "mac": mac,
            "device_name": device_name,
        }
        if dialect == "postgresql":
            ins = pg_insert(table).values(**values)
            stmt = ins.on_conflict_do_update(
                constraint="uq_endpoint_device_ip_mac",
                set_={"device_name": device_name} if device_name else {},
            )
        else:
            ins = sqlite_insert(table).values(**values)
            stmt = ins.on_conflict_do_update(
                index_elements=ENDPOINT_UQ,
                set_={"device_name": device_name} if device_name else {},
            )
        session.execute(stmt)

    def _upsert_flows_from_events(
        self,
        session: Session,
        events: list[dict],
        ep_key_to_id: dict[tuple[str, str, Optional[str]], int],
    ) -> None:
        dialect = session.get_bind().dialect.name

        for ev_dict in events:
            if ev_dict.get("event_type") not in {"conn_open", "conn_open_natsat"}:
                continue
            fk = (ev_dict.get("firewall_key") or ev_dict.get("device") or "").strip()
            if not fk:
                continue

            def ep_id(ip: Optional[str], mac: Optional[str]) -> Optional[int]:
                if not ip:
                    return None
                key = (fk, ip.strip(), (mac or "").strip() or None)
                return ep_key_to_id.get(key)

            src_orig_id = ep_id(ev_dict.get("src_ip"), ev_dict.get("src_mac"))
            dst_orig_id = ep_id(ev_dict.get("dest_ip"), ev_dict.get("dest_mac"))
            xlat_src = ev_dict.get("xlat_src_ip") or ev_dict.get("src_ip")
            xlat_dst = ev_dict.get("xlat_dest_ip") or ev_dict.get("dest_ip")
            src_nat_id = ep_id(xlat_src, ev_dict.get("src_mac"))
            dst_nat_id = ep_id(xlat_dst, ev_dict.get("dest_mac"))
            if src_orig_id is None or dst_orig_id is None:
                continue

            ts = ev_dict.get("ts_utc")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            if ts and getattr(ts, "tzinfo", None) is None:
                ts = ts.replace(tzinfo=timezone.utc)  # type: ignore
            event_ts = ts or datetime.now(timezone.utc)

            bases = [
                ("side", ev_dict.get("recv_side"), ev_dict.get("dest_side")),
                ("zone", ev_dict.get("recv_zone"), ev_dict.get("dest_zone")),
                ("interface", ev_dict.get("recv_if"), ev_dict.get("dest_if")),
            ]
            proto = ev_dict.get("proto")
            dest_port = ev_dict.get("dest_port")

            for view_kind, sid, did in [
                ("original", src_orig_id, dst_orig_id),
                ("translated", src_nat_id, dst_nat_id),
            ]:
                if sid is None or did is None:
                    continue
                for basis, from_val, to_val in bases:
                    if not from_val or not to_val:
                        continue
                    values = {
                        "device": fk,
                        "basis": basis,
                        "from_value": from_val,
                        "to_value": to_val,
                        "proto": proto,
                        "dest_port": dest_port,
                        "src_endpoint_id": sid,
                        "dst_endpoint_id": did,
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
                    if dialect == "postgresql":
                        ins = pg_insert(Flow).values(**values)
                        stmt = ins.on_conflict_do_update(
                            constraint="ux_flows_identity",
                            set_={
                                Flow.count_open: Flow.count_open + 1,
                                Flow.first_seen: func.least(Flow.first_seen, ins.excluded.first_seen),
                                Flow.last_seen: func.greatest(Flow.last_seen, ins.excluded.last_seen),
                            },
                        )
                    else:
                        ins = sqlite_insert(Flow).values(**values)
                        stmt = ins.on_conflict_do_update(
                            index_elements=FLOW_IDENTITY,
                            set_={
                                Flow.count_open: Flow.count_open + 1,
                                Flow.first_seen: func.min(Flow.first_seen, ins.excluded.first_seen),
                                Flow.last_seen: func.max(Flow.last_seen, ins.excluded.last_seen),
                            },
                        )
                    session.execute(stmt)
