"""Retry helper for transient DB locking errors (deadlock, SQLite locked). No new dependencies."""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, TypeVar

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

logger = logging.getLogger("netwall.storage.retry")

T = TypeVar("T")


def _is_transient_locking_error(exc: BaseException) -> bool:
    """True if the exception is a transient locking/deadlock error we can retry."""
    if isinstance(exc, OperationalError):
        orig = getattr(exc, "orig", None)
        if orig is not None and type(orig).__name__ == "DeadlockDetected":
            return True
    # SQLite: database is locked, etc.
    msg = str(exc).lower()
    if "database is locked" in msg or "locked" in msg or "busy" in msg:
        return True
    return False


def execute_with_retry(
    session: Session,
    fn: Callable[[], T],
    *,
    max_attempts: int = 6,
    base_sleep: float = 0.02,
    log: logging.Logger | None = None,
) -> tuple[bool, T | None]:
    """Run fn() (e.g. session.execute(...)); on transient locking errors, rollback and retry with backoff.

    Returns (True, result) on success, (False, None) if all retries failed. Never raises for transient
    errors; callers can treat (False, None) as best-effort failure and continue.
    """
    log = log or logger
    for attempt in range(max_attempts):
        try:
            result = fn()
            return (True, result)
        except Exception as e:
            if not _is_transient_locking_error(e):
                raise
            if attempt == max_attempts - 1:
                log.warning(
                    "Transient DB error after %s attempts; giving up: %s",
                    max_attempts,
                    e,
                    exc_info=False,
                )
                return (False, None)
            try:
                session.rollback()
            except Exception:  # noqa: S110
                pass
            sleep_time = base_sleep * (2**attempt) + random.random() * base_sleep
            log.debug(
                "Retrying after transient error (attempt %s/%s): %s; sleep %.3fs",
                attempt + 1,
                max_attempts,
                e,
                sleep_time,
            )
            time.sleep(sleep_time)
    return (False, None)
