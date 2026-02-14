"""Tests for InControl RFC5424 + structured-data syslog ingest."""

from __future__ import annotations

import pytest

from app.config import AppConfig
from app.ingest.reconstruct import (
    INCONTROL_RFC5424_RE,
    RecordReconstructor,
    _extract_bracket_inner_parts,
    _parse_incontrol_message,
    _parse_record_incontrol,
    parse_record,
)


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


# Sample CONN line (InControl export format) with structured data
SAMPLE_CONN_LINE = (
    "<1>1 2026-02-09T07:32:47Z 15c8cb06-465b-48b2-b7f7-b6c206e749dc CONN : id=600004 event=conn_open_natsat "
    '[message=Connection opened connrecvzone="" conndestzone="" ]'
    "[conn [conn connsrcip=10.48.11.55 conndestip=20.242.39.171 connipproto=TCP conndestport=443 "
    "connrecvif=lan conndestif=wan connnewsrcip=62.111.230.212 ]]"
)

# Minimal ALG line (should not break ingest)
SAMPLE_ALG_LINE = (
    "<1>1 2026-02-09T07:32:48Z 15c8cb06-465b-48b2-b7f7-b6c206e749dc ALG : id=200001 event=alg_session_open "
    "[conn [conn connsrcip=10.0.0.1 conndestip=10.0.0.2 ]]"
)


def test_incontrol_rfc5424_re_matches_conn_line():
    assert INCONTROL_RFC5424_RE.match(SAMPLE_CONN_LINE) is not None
    m = INCONTROL_RFC5424_RE.match(SAMPLE_CONN_LINE)
    assert m.group("timestamp") == "2026-02-09T07:32:47Z"
    assert m.group("host") == "15c8cb06-465b-48b2-b7f7-b6c206e749dc"
    assert m.group("app") == "CONN"
    assert "id=600004" in m.group("msg")
    assert "[conn " in m.group("msg")


def test_incontrol_rfc5424_re_matches_alg_line():
    assert INCONTROL_RFC5424_RE.match(SAMPLE_ALG_LINE) is not None
    m = INCONTROL_RFC5424_RE.match(SAMPLE_ALG_LINE)
    assert m.group("app") == "ALG"
    assert "id=200001" in m.group("msg")


def test_incontrol_rfc5424_re_rejects_classic_bsd():
    classic = "<134>Feb 10 17:37:13 myfw EFW: CONN: id=00600004 event=conn_open"
    assert INCONTROL_RFC5424_RE.match(classic) is None


def test_extract_bracket_inner_parts():
    s = "a [b [c x=1 ] d=2 ] e"
    parts = _extract_bracket_inner_parts(s)
    assert "b [c x=1 ] d=2 " in parts
    assert "c x=1 " in parts


def test_parse_incontrol_message_prefix_and_blocks():
    msg = "id=600004 event=conn_open_natsat [conn [conn connsrcip=10.48.11.55 conndestip=20.242.39.171 ]]"
    kv = _parse_incontrol_message(msg)
    assert kv.get("id") == "600004" or kv.get("id") == 600004
    assert kv.get("event") == "conn_open_natsat"
    assert kv.get("connsrcip") == "10.48.11.55"
    assert kv.get("conndestip") == "20.242.39.171"


def test_parse_record_incontrol_conn_line(config: AppConfig):
    parsed = _parse_record_incontrol(SAMPLE_CONN_LINE, config)
    assert parsed is not None
    assert parsed.device == "15c8cb06-465b-48b2-b7f7-b6c206e749dc"
    assert parsed.extra.get("log_type") == "CONN"
    assert parsed.parse_status == "ok"
    assert str(parsed.kv.get("id")) == "600004"
    assert parsed.kv.get("event") == "conn_open_natsat"
    assert parsed.kv.get("connsrcip") == "10.48.11.55"
    assert parsed.kv.get("conndestip") == "20.242.39.171"
    assert parsed.kv.get("connipproto") == "TCP"
    assert parsed.kv.get("conndestport") == 443
    assert parsed.kv.get("connrecvif") == "lan"
    assert parsed.kv.get("conndestif") == "wan"
    assert parsed.kv.get("connnewsrcip") == "62.111.230.212"


def test_parse_record_incontrol_returns_none_for_classic(config: AppConfig):
    classic = "<134>Feb 10 17:37:13 myfw EFW: CONN: id=00600004 event=conn_open connsrcip=1.2.3.4"
    parsed = _parse_record_incontrol(classic, config)
    assert parsed is None


def test_parse_record_uses_incontrol_for_export_line(config: AppConfig):
    """parse_record() should return InControl result when line matches InControl format."""
    parsed = parse_record(SAMPLE_CONN_LINE, config)
    assert parsed.device == "15c8cb06-465b-48b2-b7f7-b6c206e749dc"
    assert parsed.extra.get("log_type") == "CONN"
    assert str(parsed.kv.get("id")) == "600004"
    assert parsed.kv.get("event") == "conn_open_natsat"
    assert parsed.kv.get("connsrcip") == "10.48.11.55"
    assert parsed.kv.get("conndestip") == "20.242.39.171"
    assert parsed.kv.get("connipproto") == "TCP"
    assert parsed.kv.get("conndestport") == 443
    assert parsed.kv.get("connrecvif") == "lan"
    assert parsed.kv.get("conndestif") == "wan"
    assert parsed.kv.get("connnewsrcip") == "62.111.230.212"


def test_parse_record_alg_line_does_not_break(config: AppConfig):
    """ALG lines parse without error; id may be filtered later but line is accepted."""
    parsed = parse_record(SAMPLE_ALG_LINE, config)
    assert parsed is not None
    assert parsed.parse_status == "ok"
    assert parsed.device == "15c8cb06-465b-48b2-b7f7-b6c206e749dc"
    assert parsed.extra.get("log_type") == "ALG"
    assert parsed.kv.get("event") == "alg_session_open"


def test_reconstructor_treats_incontrol_as_record_start():
    rec = RecordReconstructor()
    assert rec._is_record_start(SAMPLE_CONN_LINE) is True
    assert rec._is_record_start(SAMPLE_ALG_LINE) is True
    records = rec.feed_line(SAMPLE_CONN_LINE)
    assert records == []
    records = rec.feed_line("continuation text")
    assert records == []  # continuation appended
    records = rec.feed_line(SAMPLE_ALG_LINE)
    assert len(records) == 1
    assert "600004" in records[0]
    assert "200001" in rec._current
