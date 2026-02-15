from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ClassificationPrecedence(str, Enum):
    ZONE_FIRST = "zone_first"
    INTERFACE_FIRST = "interface_first"


class YearMode(str, Enum):
    CURRENT = "current"
    # Future: INFER = "infer"


@dataclass
class AppConfig:
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    database_url: str = "postgresql+psycopg://localhost/netwall"
    serve_frontend: bool = False
    frontend_dir: str = "./frontend/dist"
    log_level: str = "info"
    year_mode: YearMode = YearMode.CURRENT
    classification_precedence: ClassificationPrecedence = ClassificationPrecedence.ZONE_FIRST


def parse_args(argv: Optional[list[str]] = None) -> AppConfig:
    """Parse CLI arguments into AppConfig.

    Exposed via `python -m app` and `netwall-flow-analyzer`.
    """
    import argparse

    parser = argparse.ArgumentParser(description="NetWall CONN Flow Analyzer backend")
    parser.add_argument("--web-host", default="0.0.0.0")
    parser.add_argument("--web-port", type=int, default=8080)
    parser.add_argument("--syslog-host", default="0.0.0.0")
    parser.add_argument("--syslog-port", type=int, default=5514)
    parser.add_argument(
        "--database-url",
        default="postgresql+psycopg://localhost/netwall",
        help="SQLAlchemy database URL (PostgreSQL recommended)",
    )
    parser.add_argument(
        "--serve-frontend",
        action="store_true",
        help="Serve built frontend assets from backend",
    )
    parser.add_argument(
        "--frontend-dir",
        default="./frontend/dist",
        help="Path to built frontend assets (index.html, assets/...)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
    )
    parser.add_argument(
        "--year-mode",
        default=YearMode.CURRENT.value,
        choices=[YearMode.CURRENT.value],
        help="How to infer year for syslog timestamps",
    )
    parser.add_argument(
        "--classification-precedence",
        default=ClassificationPrecedence.ZONE_FIRST.value,
        choices=[
            ClassificationPrecedence.ZONE_FIRST.value,
            ClassificationPrecedence.INTERFACE_FIRST.value,
        ],
        help="Whether zone or interface wins when deriving recv/dest side",
    )

    args = parser.parse_args(argv)

    return AppConfig(
        web_host=args.web_host,
        web_port=args.web_port,
        syslog_host=args.syslog_host,
        syslog_port=args.syslog_port,
        database_url=args.database_url,
        serve_frontend=bool(args.serve_frontend),
        frontend_dir=args.frontend_dir,
        log_level=args.log_level,
        year_mode=YearMode(args.year_mode),
        classification_precedence=ClassificationPrecedence(args.classification_precedence),
    )

