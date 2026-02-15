from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import ClassificationPrecedence
from ..storage.models import Classification, UnclassifiedEndpoint, ClassificationSide
from ..storage.retry import execute_with_retry

logger = logging.getLogger("netwall.classification")


def flush_unclassified_counter(
    db: Session,
    counter: dict[tuple[str, str, Optional[str]], int],
) -> None:
    """Flush aggregated (device, kind, name) -> count into unclassified_endpoints. One upsert per key, sorted order; retry on lock."""
    if not counter:
        return
    table = UnclassifiedEndpoint.__table__
    dialect = db.get_bind().dialect.name
    for (device, kind, name) in sorted(counter.keys()):
        inc = counter[(device, kind, name)]
        if not name:
            continue
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
        try:
            ok, _ = execute_with_retry(db, lambda _s=stmt: db.execute(_s), log=logger)
            if not ok:
                logger.warning(
                    "unclassified_endpoints batch upsert failed after retries; skipping (device=%s kind=%s name=%s)",
                    device,
                    kind,
                    name,
                )
        except IntegrityError as e:
            logger.warning(
                "unclassified_endpoints upsert skipped (constraint); continuing: %s",
                e,
                exc_info=False,
            )


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
    """Record an unclassified (device, kind, name). Idempotent upsert with retry; best-effort, never fails ingest."""
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

    try:
        ok, _ = execute_with_retry(db, lambda: db.execute(stmt), log=logger)
        if not ok:
            logger.warning(
                "unclassified_endpoints upsert failed after retries; continuing (device=%s kind=%s name=%s)",
                device,
                kind,
                name,
            )
    except IntegrityError as e:
        logger.warning(
            "unclassified_endpoints upsert skipped (constraint); continuing: %s",
            e,
            exc_info=False,
        )


def derive_side_for_endpoint(
    db: Session,
    device: str,
    zone: Optional[str],
    iface: Optional[str],
    precedence: ClassificationPrecedence,
    unclassified_counter: Optional[Dict[Tuple[str, str, Optional[str]], int]] = None,
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

    # No known classification; record as unclassified (or accumulate for batch flush).
    for kind, name in kinds:
        if unclassified_counter is not None:
            key = (device, kind, name)
            unclassified_counter[key] = unclassified_counter.get(key, 0) + 1
        else:
            _record_unclassified(db, device=device, kind=kind, name=name)

    return ClassificationSide.UNKNOWN


def apply_direction_classification(
    db: Session,
    event,
    precedence: ClassificationPrecedence,
    unclassified_counter: Optional[Dict[Tuple[str, str, Optional[str]], int]] = None,
) -> None:
    """Populate recv_side, dest_side, direction_bucket on an Event instance."""
    recv_side = derive_side_for_endpoint(
        db=db,
        device=event.device,
        zone=event.recv_zone,
        iface=event.recv_if,
        precedence=precedence,
        unclassified_counter=unclassified_counter,
    )
    dest_side = derive_side_for_endpoint(
        db=db,
        device=event.device,
        zone=event.dest_zone,
        iface=event.dest_if,
        precedence=precedence,
        unclassified_counter=unclassified_counter,
    )

    event.recv_side = recv_side
    event.dest_side = dest_side

    if recv_side != ClassificationSide.UNKNOWN and dest_side != ClassificationSide.UNKNOWN:
        event.direction_bucket = f"{recv_side}_to_{dest_side}"
    else:
        event.direction_bucket = "unknown"

