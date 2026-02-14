"""Helpers for reading/writing app_settings table."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AppSetting

# ── Default settings ──
DEFAULTS: dict[str, Any] = {
    "log_retention": {
        "enabled": True,
        "keep_days": 3,
    },
    "local_networks": {
        "enabled": True,
        "cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    },
}


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    """Return the value for *key*, falling back to DEFAULTS then *default*."""
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalar_one_or_none()
    if row is not None:
        return row.value_json
    if key in DEFAULTS:
        return DEFAULTS[key]
    return default


def set_setting(db: Session, key: str, value: Any) -> None:
    """Upsert a setting."""
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if row is not None:
        row.value_json = value
        row.updated_at = now
    else:
        db.add(AppSetting(key=key, value_json=value, updated_at=now))
    db.flush()


def get_all_settings(db: Session) -> dict[str, Any]:
    """Return all settings with defaults applied for missing keys."""
    stored: dict[str, Any] = {}
    for row in db.execute(select(AppSetting)).scalars().all():
        stored[row.key] = row.value_json
    merged = dict(DEFAULTS)
    merged.update(stored)
    return merged
