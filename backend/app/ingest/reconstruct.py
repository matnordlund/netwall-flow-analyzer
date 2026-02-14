from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session, sessionmaker

from ..config import AppConfig
from ..storage.models import DeviceIdentification, Endpoint, Event, IngestJob, RawLog
from ..storage.event_writer import EventWriter
from ..storage.firewall_source import get_canonical_device_key, upsert_firewall_syslog
from ..enrichment.classification import apply_direction_classification
from ..aggregation.flows import update_flows_for_event
from .stats import ingest_stats

logger = logging.getLogger("netwall.ingest")


# BSD-style: optional <priority> then "Feb 10 17:37:13 hostname [optional] EFW: EVENTTYPE:"
SYSLOG_PREFIX_RE = re.compile(
    r'^(?:<\d+>\s*)?'
    r'(?P<month>[A-Z][a-z]{2})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)'
    r'(?:\s+\[[^\]]+\])?\s+'  # optional bracketed timestamp chunk
    r'EFW:\s+[A-Z][A-Z0-9_]*:\s+'
)

# Device/relay format: "<priority>[YYYY-MM-DD HH:MM:SS] EFW: EVENTTYPE:" (no BSD header)
SYSLOG_PREFIX_ALT_RE = re.compile(
    r'^(?:<\d+>\s*)?'
    r'\[(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\]\s+'
    r'EFW:\s+[A-Z][A-Z0-9_]*:\s+'
)

# RFC 5424: "<priority>1 ISO-TIMESTAMP HOSTNAME EFW - - - EVENTTYPE: kv..."
SYSLOG_PREFIX_RFC5424_RE = re.compile(
    r'^(?:<\d+>\s*)?'
    r'1\s+'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+'
    r'(?P<host>\S+)\s+'
    r'EFW\s+(?:-\s+){3}'
    r'[A-Z][A-Z0-9_]*:\s+'
)

# InControl export: "<PRI>VERSION TIMESTAMP HOST APP-NAME : id=... event=... [structured data]"
# e.g. <1>1 2026-02-09T07:32:47Z 15c8cb06-... CONN : id=600004 event=conn_open_natsat [message=...]
INCONTROL_RFC5424_RE = re.compile(
    r'^<\d+>\d\s+'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>[A-Z_]+)\s*:\s*'
    r'(?P<msg>.*)$',
    re.DOTALL,
)

# Parse key=value where value can be "quoted string" (may contain spaces) or unquoted non-space token.
# This regex is applied to the full rest-of-line string, NOT per-token, so quoted values with spaces work.
KV_PAIR_RE = re.compile(r'(?P<key>\w+)=(?:"(?P<qval>[^"]*)"|(?P<uval>\S+))')

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


INT_FIELDS = {
    "prio",
    "rev",
    "origsent",
    "termsent",
    "conntime",
    "score",
    "iprep_src_score",
    "iprep_dest_score",
    "connsrcport",
    "conndestport",
    "connnewsrcport",
    "connnewdestport",
    "devicerank",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address to uppercase hyphen-separated AA-BB-CC-DD-EE-FF format.

    Handles colon-separated (aa:bb:cc:dd:ee:ff), hyphen-separated (aa-bb-cc-dd-ee-ff),
    dot-separated (aabb.ccdd.eeff), and bare hex (aabbccddeeff).
    Returns None for empty / invalid input.
    """
    if not mac:
        return None
    cleaned = mac.strip().upper().replace(":", "").replace("-", "").replace(".", "")
    if not cleaned:
        return None
    if len(cleaned) != 12 or not all(c in "0123456789ABCDEF" for c in cleaned):
        # Not a valid 6-byte MAC – return original stripped/uppercased as fallback
        fallback = mac.strip().upper().replace(":", "-")
        return fallback if fallback else None
    return "-".join(cleaned[i : i + 2] for i in range(0, 12, 2))


@dataclass
class ParsedRecord:
    ts_utc: datetime
    device: str
    kv: Dict[str, object]
    extra: Dict[str, object]
    parse_status: str = "ok"
    parse_error: Optional[str] = None


def _parse_iso_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp (e.g. ``2026-02-10T18:57:45.970+01:00``) to UTC.

    Handles timezone offsets across all Python 3.7+ versions (``fromisoformat``
    only gained full offset support in Python 3.11).
    """
    try:
        dt = datetime.fromisoformat(ts_str)
    except ValueError:
        # Python <3.11 can't handle tz offsets like +01:00 in fromisoformat
        tz_match = re.search(r'([+-])(\d{2}):(\d{2})$', ts_str)
        if tz_match:
            base = ts_str[: tz_match.start()]
            sign = 1 if tz_match.group(1) == '+' else -1
            offset = timedelta(hours=int(tz_match.group(2)), minutes=int(tz_match.group(3)))
            dt = datetime.fromisoformat(base).replace(tzinfo=timezone(sign * offset))
        elif ts_str.endswith('Z'):
            dt = datetime.fromisoformat(ts_str[:-1]).replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
    # Normalise to UTC
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc)
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _extract_bracket_inner_parts(s: str) -> List[str]:
    """Extract all strings that are inside matching [ ] (including nested)."""
    parts: List[str] = []
    i = 0
    while i < len(s):
        if s[i] == "[":
            depth = 1
            j = i + 1
            while j < len(s) and depth > 0:
                if s[j] == "[":
                    depth += 1
                elif s[j] == "]":
                    depth -= 1
                j += 1
            if depth == 0:
                inner = s[i + 1 : j - 1]
                parts.append(inner)
                parts.extend(_extract_bracket_inner_parts(inner))
            i = j
        else:
            i += 1
    return parts


def _parse_kv_from_string(segment: str) -> Dict[str, object]:
    """Parse key=value pairs from a string; values may be quoted. Coerce INT_FIELDS."""
    out: Dict[str, object] = {}
    for m in KV_PAIR_RE.finditer(segment):
        key = m.group("key")
        if m.group("qval") is not None:
            raw_val = m.group("qval")
        else:
            raw_val = m.group("uval") or ""
        val: object = raw_val
        if key in INT_FIELDS:
            iv = _coerce_int(raw_val)
            val = iv if iv is not None else raw_val
        out[key] = val
    return out


def _parse_incontrol_message(msg: str) -> Dict[str, object]:
    """Parse InControl MSG: id= event= prefix plus key=value from all bracket blocks. Flatten; last write wins."""
    # Prefix (before first '['): id=600004 event=conn_open_natsat
    prefix, _, rest = msg.partition("[")
    all_kv = _parse_kv_from_string(prefix.strip())
    # All inner bracket contents (including nested)
    for part in _extract_bracket_inner_parts("[" + rest):
        for key, val in _parse_kv_from_string(part).items():
            all_kv[key] = val
    return all_kv


def _normalize_incontrol_kv(kv: Dict[str, object]) -> None:
    """Normalize enum-like values to lowercase (e.g. conn=Open -> open). Mutates kv in place."""
    for key in ("conn", "action", "event"):
        v = kv.get(key)
        if isinstance(v, str) and v:
            kv[key] = v.strip().lower()
    # Map srcuser -> srcusername for schema
    if "srcuser" in kv and "srcusername" not in kv:
        kv["srcusername"] = kv["srcuser"]


def _parse_record_incontrol(raw: str, config: AppConfig) -> Optional[ParsedRecord]:
    """Parse InControl RFC5424 export line. Returns ParsedRecord or None if not this format."""
    m = INCONTROL_RFC5424_RE.match(raw)
    if not m:
        return None
    try:
        ts_str = m.group("timestamp")
        host = (m.group("host") or "").strip() or "unknown"
        app_name = (m.group("app") or "").strip()
        msg = m.group("msg") or ""
        dt = _parse_iso_timestamp(ts_str)
        kv = _parse_incontrol_message(msg)
        _normalize_incontrol_kv(kv)
        # Ensure id is string for filtering (e.g. 600004)
        if "id" in kv and kv["id"] is not None:
            kv["id"] = str(kv["id"])
        return ParsedRecord(ts_utc=dt, device=host, kv=kv, extra={"log_type": app_name})
    except Exception as exc:  # noqa: BLE001
        logger.exception("InControl parse failed")
        return ParsedRecord(
            ts_utc=datetime.now(timezone.utc),
            device="unknown",
            kv={},
            extra={},
            parse_status="error",
            parse_error=str(exc),
        )


class RecordReconstructor:
    """Accumulate wrapped syslog lines into full records."""

    def __init__(self) -> None:
        self._current: Optional[str] = None

    def _is_record_start(self, line: str) -> bool:
        return (
            SYSLOG_PREFIX_RE.match(line) is not None
            or SYSLOG_PREFIX_ALT_RE.match(line) is not None
            or SYSLOG_PREFIX_RFC5424_RE.match(line) is not None
            or INCONTROL_RFC5424_RE.match(line) is not None
        )

    def feed_line(self, line: str) -> List[str]:
        records: List[str] = []
        if self._is_record_start(line):
            # Start of a new record.
            if self._current is not None:
                records.append(self._current)
            self._current = line.strip()
        else:
            # Continuation.
            if self._current is None:
                # Ignore orphaned continuation lines, but keep them in logs.
                logger.debug("Ignoring continuation without prefix: %s", line.rstrip())
            else:
                self._current += " " + line.strip()
        return records

    def flush(self) -> List[str]:
        if self._current is None:
            return []
        out = [self._current]
        self._current = None
        return out


def _parse_syslog_header(
    record: str,
    config: AppConfig,
) -> Tuple[datetime, str, str]:
    """Parse syslog header, infer year, return (ts_utc, device, rest_after_header).

    Tries RFC 5424 first, then bracket format, then BSD format.
    """
    # 1) RFC 5424: "1 ISO-TIMESTAMP HOSTNAME EFW - - - EVENTTYPE: kv..."
    m_rfc = SYSLOG_PREFIX_RFC5424_RE.match(record)
    if m_rfc:
        ts_str = m_rfc.group("timestamp")
        host = (m_rfc.group("host") or "").strip() or "unknown"
        dt = _parse_iso_timestamp(ts_str)
        rest = record[m_rfc.end() :]
        return dt, host, rest

    # 2) Bracket format: [YYYY-MM-DD HH:MM:SS] EFW: EVENTTYPE:
    m_alt = SYSLOG_PREFIX_ALT_RE.match(record)
    if m_alt:
        year = int(m_alt.group("year"))
        month = int(m_alt.group("month"))
        day = int(m_alt.group("day"))
        time_part = m_alt.group("time")
        dt_str = f"{year:04d}-{month:02d}-{day:02d} {time_part}"
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        rest = record[m_alt.end() :]
        return dt, "unknown", rest

    # 3) BSD format: "Feb 10 17:37:13 hostname ... EFW: EVENTTYPE:"
    m = SYSLOG_PREFIX_RE.match(record)
    if not m:
        # Fallback: treat as now and unknown device.
        now = datetime.now(timezone.utc)
        return now, "unknown", record

    month_name = m.group("month")
    day = int(m.group("day"))
    time_part = m.group("time")
    host = (m.group("host") or "").strip()
    if not host:
        host = "unknown"

    year = datetime.utcnow().year  # CURRENT year mode
    month = MONTHS.get(month_name, 1)
    dt_str = f"{year:04d}-{month:02d}-{day:02d} {time_part}"
    dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

    rest = record[m.end() :]
    return dt, host, rest


def _coerce_int(value: str) -> Optional[int]:
    """Parse leading digits as int, ignore trailing junk."""
    m = re.match(r"(\d+)", value)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _parse_kv(rest: str) -> Tuple[Dict[str, object], Dict[str, object]]:
    """Parse key=value pairs from the full rest-of-line string.

    Values may be quoted (``key="value with spaces"``) or unquoted (``key=value``).
    The regex is applied directly to the full string so that quoted values
    containing spaces are captured correctly.
    """
    kv: Dict[str, object] = {}
    extra: Dict[str, object] = {}

    for m in KV_PAIR_RE.finditer(rest):
        key = m.group("key")
        if m.group("qval") is not None:
            raw_val = m.group("qval")
        else:
            raw_val = m.group("uval") or ""

        val: object = raw_val
        if key in INT_FIELDS:
            iv = _coerce_int(raw_val)
            val = iv

        kv[key] = val

    return kv, extra


def parse_record(raw: str, config: AppConfig) -> ParsedRecord:
    # InControl export (RFC5424 + structured data) takes precedence
    incontrol = _parse_record_incontrol(raw, config)
    if incontrol is not None:
        return incontrol
    try:
        ts_utc, device, rest = _parse_syslog_header(raw, config)
        kv, extra = _parse_kv(rest)
        return ParsedRecord(ts_utc=ts_utc, device=device, kv=kv, extra=extra)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to parse record")
        now = datetime.now(timezone.utc)
        return ParsedRecord(
            ts_utc=now,
            device="unknown",
            kv={},
            extra={},
            parse_status="error",
            parse_error=str(exc),
        )


def _extract_str(kv: Dict[str, object], key: str) -> Optional[str]:
    v = kv.get(key)
    if v is None:
        return None
    return str(v)


def _extract_str_any(kv: Dict[str, object], *keys: str) -> Optional[str]:
    """Return first non-empty string value for any of the given keys (e.g. device_ip4 or deviceip4)."""
    for key in keys:
        v = _extract_str(kv, key)
        if v and v.strip():
            return v
    return None


def _extract_int(kv: Dict[str, object], key: str) -> Optional[int]:
    v = kv.get(key)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v))
    except ValueError:
        return None


def _extract_int_any(kv: Dict[str, object], *keys: str) -> Optional[int]:
    """Return first non-None int for any of the given keys."""
    for key in keys:
        v = _extract_int(kv, key)
        if v is not None:
            return v
    return None


def normalize_to_models(parsed: ParsedRecord, raw_text: str) -> Tuple[RawLog, Optional[Event]]:
    raw = RawLog(
        ts_utc=parsed.ts_utc,
        device=parsed.device,
        raw_record=raw_text,
        parse_status=parsed.parse_status,
        parse_error=parsed.parse_error,
    )

    if parsed.parse_status != "ok":
        return raw, None

    kv = parsed.kv
    extra = dict(parsed.extra)

    event_type = _extract_str(kv, "event")

    # Base connection mapping
    e = Event(
        ts_utc=parsed.ts_utc,
        device=parsed.device,
        event_type=event_type,
        action=_extract_str(kv, "action"),
        rule=_extract_str(kv, "rule"),
        satsrcrule=_extract_str(kv, "satsrcrule"),
        satdestrule=_extract_str(kv, "satdestrule"),
        srcusername=_extract_str_any(kv, "srcusername", "srcuser"),
        destusername=_extract_str(kv, "destusername"),
        proto=_extract_str(kv, "connipproto"),
        recv_if=_extract_str(kv, "connrecvif"),
        recv_zone=_extract_str(kv, "connrecvzone"),
        src_ip=_extract_str(kv, "connsrcip"),
        src_port=_extract_int(kv, "connsrcport"),
        src_mac=normalize_mac(_extract_str(kv, "connsrcmac")),
        src_device=_extract_str(kv, "connsrcdevice"),
        dest_if=_extract_str(kv, "conndestif"),
        dest_zone=_extract_str(kv, "conndestzone"),
        dest_ip=_extract_str(kv, "conndestip"),
        dest_port=_extract_int(kv, "conndestport"),
        dest_mac=normalize_mac(_extract_str(kv, "conndestmac")),
        dest_device=_extract_str(kv, "conndestdevice"),
        xlat_src_ip=_extract_str(kv, "connnewsrcip"),
        xlat_src_port=_extract_int(kv, "connnewsrcport"),
        xlat_dest_ip=_extract_str(kv, "connnewdestip"),
        xlat_dest_port=_extract_int(kv, "connnewdestport"),
        bytes_orig=_extract_int(kv, "origsent"),
        bytes_term=_extract_int(kv, "termsent"),
        duration_s=_extract_int(kv, "conntime"),
        app_name=_extract_str(kv, "app_name"),
        app_risk=_extract_str(kv, "app_risk"),
        app_family=_extract_str(kv, "app_family"),
        iprep_ip=_extract_str(kv, "ip"),
        iprep_score=_extract_int(kv, "score"),
        iprep_categories=_extract_str(kv, "categories"),
        iprep_src=_extract_str(kv, "iprep_src"),
        iprep_dest=_extract_str(kv, "iprep_dest"),
        iprep_src_score=_extract_int(kv, "iprep_src_score"),
        iprep_dest_score=_extract_int(kv, "iprep_dest_score"),
        recv_side=None,
        dest_side=None,
        direction_bucket=None,
        extra_json=extra,
    )

    # Move unknown keys into extra_json if not already mapped.
    mapped_keys = {
        "event",
        "action",
        "rule",
        "satsrcrule",
        "satdestrule",
        "srcusername",
        "destusername",
        "connipproto",
        "connrecvif",
        "connrecvzone",
        "connsrcip",
        "connsrcport",
        "connsrcmac",
        "connsrcdevice",
        "conndestif",
        "conndestzone",
        "conndestip",
        "conndestport",
        "conndestmac",
        "conndestdevice",
        "connnewsrcip",
        "connnewsrcport",
        "connnewdestip",
        "connnewdestport",
        "origsent",
        "termsent",
        "conntime",
        "app_name",
        "app_risk",
        "app_family",
        "ip",
        "score",
        "categories",
        "iprep_src",
        "iprep_dest",
        "iprep_src_score",
        "iprep_dest_score",
    }
    for k, v in kv.items():
        if k not in mapped_keys:
            e.extra_json.setdefault("unmapped", {})[k] = v

    return raw, e


# Accepted id prefixes: CONN (0060, 60), DEVICE (0890, 89). InControl may send 600004, 890001.
_ACCEPTED_ID_PREFIXES = ("0060", "60", "0890", "89")


def _upsert_device_identification(
    db: Session,
    parsed: ParsedRecord,
) -> Optional[DeviceIdentification]:
    """Upsert a DeviceIdentification row from a DEVICE log record. Returns the row (existing or new)."""
    kv = parsed.kv
    raw_mac = _extract_str(kv, "srcmac")
    mac = normalize_mac(raw_mac)
    if not mac:
        return None

    from sqlalchemy import select as sa_select  # local import to keep top-level light
    existing: Optional[DeviceIdentification] = db.execute(
        sa_select(DeviceIdentification).where(
            DeviceIdentification.firewall_device == parsed.device,
            DeviceIdentification.srcmac == mac,
        )
    ).scalar_one_or_none()

    def _val(*keys: str) -> Optional[str]:
        return _extract_str_any(kv, *keys)

    # Accept both underscore keys (device_ip4, device_vendor, ...) and no-underscore (deviceip4, devicevendor, ...)
    new_fields = {
        "hostname": _val("hostname"),
        "if_name": _val("if"),
        "zone": _val("zone"),
        "device_ip4": _val("device_ip4", "deviceip4"),
        "device_ip6": _val("device_ip6", "deviceip6"),
        "device_vendor": _val("device_vendor", "devicevendor"),
        "device_type": _val("device_type", "devicetype"),
        "device_type_name": _val("device_type_name", "devicetypename"),
        "device_type_group_name": _val("device_type_group_name", "devicetypegroupname"),
        "device_os_name": _val("device_os_name", "deviceosname"),
        "device_brand": _val("device_brand", "devicebrand"),
        "device_model": _val("device_model", "devicemodel"),
        "device_rank": _extract_int_any(kv, "device_rank", "devicerank"),
    }

    if existing:
        # Update only non-empty fields (don't overwrite populated values with empty)
        for attr, new_val in new_fields.items():
            if new_val is not None:
                setattr(existing, attr, new_val)
        existing.last_seen = parsed.ts_utc
        # Store raw kv in json for audit
        existing.raw_event_json = {k: v for k, v in kv.items()}
        db.flush()
        return existing
    di = DeviceIdentification(
        firewall_device=parsed.device,
        srcmac=mac,
        first_seen=parsed.ts_utc,
        last_seen=parsed.ts_utc,
        raw_event_json={k: v for k, v in kv.items()},
        **{k: v for k, v in new_fields.items() if v is not None},
    )
    db.add(di)
    db.flush()
    return di


def _sync_endpoints_from_device_identification(
    db: Session,
    di: DeviceIdentification,
) -> None:
    """Update all endpoints where (device, ip, mac) matches (firewall_device, device_ip4, srcmac)."""
    if not di.device_ip4 or not di.srcmac:
        return
    from sqlalchemy import update
    endpoint_attrs = {
        "hostname": di.hostname,
        "device_ip4": di.device_ip4,
        "device_ip6": di.device_ip6,
        "device_vendor": di.device_vendor,
        "device_type": di.device_type,
        "device_type_name": di.device_type_name,
        "device_type_group_name": di.device_type_group_name,
        "device_os_name": di.device_os_name,
        "device_brand": di.device_brand,
        "device_model": di.device_model,
        "device_rank": di.device_rank,
    }
    # Only set non-None so we don't overwrite with null
    payload = {k: v for k, v in endpoint_attrs.items() if v is not None}
    if not payload:
        return
    stmt = (
        update(Endpoint)
        .where(
            Endpoint.device == di.firewall_device,
            Endpoint.ip == di.device_ip4,
            Endpoint.mac == di.srcmac,
        )
        .values(**payload)
    )
    db.execute(stmt)


class UploadCollector:
    """Collects per-upload stats (devices, raw_logs, events, time range, parse counts) for the upload API response."""

    def __init__(self) -> None:
        self.device_counts: Counter[str] = Counter()
        self.raw_logs_inserted = 0
        self.events_inserted = 0
        self.parse_ok = 0
        self.parse_err = 0
        self.filtered_id = 0
        self._time_min: Optional[datetime] = None
        self._time_max: Optional[datetime] = None

    def record_raw(self, device: str, ts_utc: datetime) -> None:
        self.device_counts[device] += 1
        self.raw_logs_inserted += 1
        if ts_utc.tzinfo is None:
            ts_utc = ts_utc.replace(tzinfo=timezone.utc)
        if self._time_min is None or ts_utc < self._time_min:
            self._time_min = ts_utc
        if self._time_max is None or ts_utc > self._time_max:
            self._time_max = ts_utc

    def record_event(self, device: str, ts_utc: datetime) -> None:
        self.events_inserted += 1
        if ts_utc.tzinfo is None:
            ts_utc = ts_utc.replace(tzinfo=timezone.utc)
        if self._time_min is None or ts_utc < self._time_min:
            self._time_min = ts_utc
        if self._time_max is None or ts_utc > self._time_max:
            self._time_max = ts_utc

    def primary_device(self, user_provided: Optional[str] = None) -> str:
        if user_provided and user_provided.strip():
            return user_provided.strip()
        if not self.device_counts:
            return "unknown"
        return self.device_counts.most_common(1)[0][0]

    def time_min_iso(self) -> Optional[str]:
        return self._time_min.isoformat().replace("+00:00", "Z") if self._time_min else None

    def time_max_iso(self) -> Optional[str]:
        return self._time_max.isoformat().replace("+00:00", "Z") if self._time_max else None


def _raw_log_to_dict(m: RawLog) -> dict:
    """Convert RawLog ORM to dict for bulk insert (omit id)."""
    return {
        "ts_utc": m.ts_utc,
        "device": m.device,
        "raw_record": m.raw_record,
        "parse_status": m.parse_status,
        "parse_error": m.parse_error,
    }


def _event_to_dict(e: Event) -> dict:
    """Convert Event ORM to dict for bulk insert (omit id)."""
    return {c.key: getattr(e, c.key) for c in Event.__table__.c if c.key != "id"}


@dataclass
class SyslogIngestor:
    """Shared ingest pipeline for UDP and file uploads."""

    sessionmaker: sessionmaker
    config: AppConfig
    reconstructor: RecordReconstructor = field(default_factory=RecordReconstructor)
    upload_collector: Optional[UploadCollector] = field(default=None, repr=False)
    # Batch mode (set by job processor): use one session and writer, flush every N rows
    upload_session: Optional[Session] = field(default=None, repr=False)
    upload_writer: Optional[EventWriter] = field(default=None, repr=False)
    upload_raw_batch: Optional[List[dict]] = field(default=None, repr=False)
    upload_event_batch: Optional[List[dict]] = field(default=None, repr=False)
    upload_batch_size: int = 5000
    upload_job_id: Optional[str] = field(default=None, repr=False)
    upload_get_lines_processed: Optional[Any] = field(default=None, repr=False)  # callable returning int (lines_processed)

    async def handle_line(self, line: str) -> None:
        records = self.reconstructor.feed_line(line)
        if not records:
            return
        await self._process_records(records)

    async def flush(self) -> None:
        records = self.reconstructor.flush()
        if records:
            await self._process_records(records)
        if self.upload_writer is not None and self.upload_raw_batch is not None:
            self._flush_upload_batch()

    def _flush_upload_batch(self) -> None:
        """Flush accumulated raw/event batches to DB via writer; update job row on same session to avoid SQLite lock."""
        if not self.upload_session or not self.upload_writer:
            return
        raw_batch = self.upload_raw_batch or []
        event_batch = self.upload_event_batch or []
        if not raw_batch and not event_batch:
            return
        try:
            self.upload_writer.insert_raw_logs(self.upload_session, raw_batch)
            self.upload_writer.insert_events(self.upload_session, event_batch)
            # Update job row on same session so we don't open a second writer (SQLite: one writer at a time)
            if self.upload_job_id and self.upload_collector is not None and self.upload_get_lines_processed is not None:
                j = self.upload_session.get(IngestJob, self.upload_job_id)
                if j:
                    j.lines_processed = self.upload_get_lines_processed()
                    j.parse_ok = self.upload_collector.parse_ok
                    j.parse_err = self.upload_collector.parse_err
                    j.filtered_id = self.upload_collector.filtered_id
                    j.raw_logs_inserted = self.upload_collector.raw_logs_inserted
                    j.events_inserted = self.upload_collector.events_inserted
                    j.time_min = self.upload_collector.time_min_iso()
                    j.time_max = self.upload_collector.time_max_iso()
                    j.updated_at = datetime.now(timezone.utc)
            self.upload_writer.commit_batch(self.upload_session)
            if self.upload_raw_batch is not None:
                self.upload_raw_batch.clear()
            if self.upload_event_batch is not None:
                self.upload_event_batch.clear()
            ingest_stats.touch()
        except Exception as exc:  # noqa: BLE001
            ingest_stats.batch_errors += 1
            ingest_stats.touch()
            logger.exception("Failed to persist batch, rolling back: %s", exc)
            self.upload_session.rollback()

    async def _process_records(self, records: Iterable[str]) -> None:
        batch_mode = self.upload_writer is not None and self.upload_session is not None
        db: Session = self.upload_session if batch_mode else self.sessionmaker()
        try:
            for raw_text in records:
                ingest_stats.records_processed += 1
                parsed = parse_record(raw_text, self.config)
                rec_id = str(parsed.kv.get("id") or "")

                # Filter: only keep CONN (0060) and DEVICE (0890)
                if rec_id and not any(rec_id.startswith(p) for p in _ACCEPTED_ID_PREFIXES):
                    ingest_stats.records_filtered_id += 1
                    if self.upload_collector is not None:
                        self.upload_collector.filtered_id += 1
                    continue

                if parsed.parse_status == "ok":
                    ingest_stats.records_parse_ok += 1
                    if self.upload_collector is not None:
                        self.upload_collector.parse_ok += 1
                else:
                    ingest_stats.records_parse_error += 1
                    if self.upload_collector is not None:
                        self.upload_collector.parse_err += 1

                # Always store raw log (batch dict or add to session)
                raw_model = RawLog(
                    ts_utc=parsed.ts_utc,
                    device=parsed.device,
                    raw_record=raw_text,
                    parse_status=parsed.parse_status,
                    parse_error=parsed.parse_error,
                )
                if batch_mode and self.upload_raw_batch is not None:
                    self.upload_raw_batch.append(_raw_log_to_dict(raw_model))
                    if len(self.upload_raw_batch) >= self.upload_batch_size:
                        self._flush_upload_batch()
                else:
                    db.add(raw_model)
                ingest_stats.raw_logs_saved += 1
                if self.upload_collector is not None:
                    self.upload_collector.record_raw(parsed.device, parsed.ts_utc)
                if not batch_mode and parsed.device and parsed.ts_utc:
                    device_key = get_canonical_device_key(db, parsed.device)
                    upsert_firewall_syslog(db, device_key, parsed.ts_utc)

                if parsed.parse_status != "ok":
                    continue

                # Route by record type (0890/89 = DEVICE, 0060/60 = CONN)
                if rec_id.startswith("0890") or rec_id.startswith("89"):
                    # DEVICE identification log: upsert device_identifications and sync to matching endpoints
                    logger.info(
                        "DEVICE log: device=%s mac=%s ip=%s vendor=%s type=%s hostname=%s",
                        parsed.device,
                        normalize_mac(_extract_str(parsed.kv, "srcmac")),
                        _extract_str_any(parsed.kv, "device_ip4", "deviceip4"),
                        _extract_str_any(parsed.kv, "device_vendor", "devicevendor"),
                        _extract_str_any(parsed.kv, "device_type_name", "devicetypename"),
                        _extract_str(parsed.kv, "hostname"),
                    )
                    di = _upsert_device_identification(db, parsed)
                    if di is not None:
                        _sync_endpoints_from_device_identification(db, di)
                        logger.debug("DEVICE upserted: id=%s mac=%s vendor=%s", di.id, di.srcmac, di.device_vendor)
                    else:
                        logger.warning("DEVICE log had no usable srcmac, skipped")
                elif rec_id.startswith("0060") or rec_id.startswith("60"):
                    # CONN log → Event model
                    _, event_model = normalize_to_models(parsed, raw_text)
                    if event_model is not None:
                        apply_direction_classification(
                            db=db,
                            event=event_model,
                            precedence=self.config.classification_precedence,
                        )
                        update_flows_for_event(db, event_model, self.config)
                        if batch_mode and self.upload_event_batch is not None:
                            self.upload_event_batch.append(_event_to_dict(event_model))
                        else:
                            db.add(event_model)
                        ingest_stats.events_saved += 1
                        if self.upload_collector is not None:
                            self.upload_collector.record_event(parsed.device, parsed.ts_utc)

            if not batch_mode:
                db.commit()
                ingest_stats.touch()
        except Exception as exc:  # noqa: BLE001
            ingest_stats.batch_errors += 1
            ingest_stats.touch()
            logger.exception("Failed to persist records, rolling back: %s", exc)
            db.rollback()
        finally:
            if not batch_mode:
                db.close()

