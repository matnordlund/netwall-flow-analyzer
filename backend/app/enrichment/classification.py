from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..config import ClassificationPrecedence
from ..storage.models import Classification, UnclassifiedEndpoint, ClassificationSide

logger = logging.getLogger("netwall.classification")


def _lookup_classification(
    db: Session,
    device: str,
    kind: str,
    name: Optional[str],
) -> Optional[str]:
    if not name:
        return None
    stmt = (
        select(Classification.side)
        .where(
            Classification.device == device,
            Classification.kind == kind,
            Classification.name == name,
        )
        .order_by(Classification.priority.desc())
    )
    side = db.execute(stmt).scalar_one_or_none()
    return side


def _record_unclassified(
    db: Session,
    device: str,
    kind: str,
    name: Optional[str],
    inc: int = 1,
) -> None:
    """Record an unclassified (device, kind, name). Idempotent upsert: insert or increment count on conflict."""
    if not name:
        return

    table = UnclassifiedEndpoint.__table__
    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        stmt = pg_insert(table).values(
            device=device,
            kind=kind,
            name=name,
            count=inc,
        ).on_conflict_do_update(
            index_elements=["device", "kind", "name"],
            set_={"count": table.c.count + inc},
        )
    else:
        stmt = sqlite_insert(table).values(
            device=device,
            kind=kind,
            name=name,
            count=inc,
        ).on_conflict_do_update(
            index_elements=["device", "kind", "name"],
            set_={"count": table.c.count + inc},
        )
    db.execute(stmt)


def derive_side_for_endpoint(
    db: Session,
    device: str,
    zone: Optional[str],
    iface: Optional[str],
    precedence: ClassificationPrecedence,
) -> str:
    """Return inside|outside|remote|unknown and update unclassified_endpoints if needed."""
    kinds = []
    if precedence == ClassificationPrecedence.ZONE_FIRST:
        kinds = [("zone", zone), ("interface", iface)]
    else:
        kinds = [("interface", iface), ("zone", zone)]

    for kind, name in kinds:
        side = _lookup_classification(db, device=device, kind=kind, name=name)
        if side and side != ClassificationSide.UNKNOWN:
            return side

    # No known classification; record as unclassified.
    for kind, name in kinds:
        _record_unclassified(db, device=device, kind=kind, name=name)

    return ClassificationSide.UNKNOWN


def apply_direction_classification(
    db: Session,
    event,
    precedence: ClassificationPrecedence,
) -> None:
    """Populate recv_side, dest_side, direction_bucket on an Event instance."""
    recv_side = derive_side_for_endpoint(
        db=db,
        device=event.device,
        zone=event.recv_zone,
        iface=event.recv_if,
        precedence=precedence,
    )
    dest_side = derive_side_for_endpoint(
        db=db,
        device=event.device,
        zone=event.dest_zone,
        iface=event.dest_if,
        precedence=precedence,
    )

    event.recv_side = recv_side
    event.dest_side = dest_side

    if recv_side != ClassificationSide.UNKNOWN and dest_side != ClassificationSide.UNKNOWN:
        event.direction_bucket = f"{recv_side}_to_{dest_side}"
    else:
        event.direction_bucket = "unknown"

