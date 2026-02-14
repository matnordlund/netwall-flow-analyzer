from __future__ import annotations

from typing import Tuple

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def init_engine_and_sessionmaker(database_url: str) -> Tuple[object, sessionmaker]:
    """Initialise SQLAlchemy engine and sessionmaker."""
    engine = create_engine(database_url, future=True)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return engine, SessionLocal

