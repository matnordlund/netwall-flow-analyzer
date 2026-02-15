from __future__ import annotations

import asyncio
import logging
import signal
from typing import Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import AppConfig, parse_args
from .api import routes_firewalls, routes_graph, routes_ingest, routes_inventory, routes_maintenance, routes_rules, routes_settings, routes_zones
from .api.routes_ingest import mark_stale_ingest_jobs_error
from .ingest.syslog_udp import run_syslog_udp_server
from .ingest.reconstruct import SyslogIngestor
from .storage.db import init_engine_and_sessionmaker
from .storage import models
from .storage.flow_index import ensure_flows_unique_index, ensure_ingest_job_error_columns

logger = logging.getLogger("netwall")


def create_app(config: AppConfig) -> FastAPI:
    app = FastAPI(title="NetWall CONN Flow Analyzer")

    # Basic CORS for dev; can tighten later.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routers.
    app.include_router(routes_ingest.router, prefix="/api")
    app.include_router(routes_graph.router, prefix="/api")
    app.include_router(routes_rules.router, prefix="/api")
    app.include_router(routes_zones.router, prefix="/api")
    app.include_router(routes_firewalls.router, prefix="/api")
    app.include_router(routes_maintenance.router, prefix="/api")
    app.include_router(routes_inventory.router, prefix="/api")
    app.include_router(routes_settings.router, prefix="/api")

    if config.serve_frontend:
        app.mount(
            "/",
            StaticFiles(directory=config.frontend_dir, html=True),
            name="frontend",
        )

    return app


async def _run_uvicorn(app: FastAPI, config: AppConfig, shutdown_event: asyncio.Event) -> None:
    """Run Uvicorn server until shutdown_event is set."""
    config_kwargs = {
        "host": config.web_host,
        "port": config.web_port,
        "log_level": config.log_level,
        "loop": "asyncio",
        "factory": False,
    }
    server = uvicorn.Server(uvicorn.Config(app, **config_kwargs))

    async def serve() -> None:
        logger.info("Starting HTTP server on %s:%s", config.web_host, config.web_port)
        await server.serve()

    server_task = asyncio.create_task(serve(), name="uvicorn-server")

    await shutdown_event.wait()
    logger.info("Shutdown event received, stopping HTTP server...")
    server.should_exit = True
    await server_task


async def _run_syslog(config: AppConfig, shutdown_event: asyncio.Event, ingestor: SyslogIngestor) -> None:
    logger.info("Starting UDP syslog receiver on %s:%s", config.syslog_host, config.syslog_port)

    async def handler(line: str) -> None:
        await ingestor.handle_line(line)

    await run_syslog_udp_server(
        host=config.syslog_host,
        port=config.syslog_port,
        shutdown_event=shutdown_event,
        handler=handler,
    )


async def _run_scheduled_cleanup(
    shutdown_event: asyncio.Event,
    session_factory,
    engine,
    interval_seconds: int = 3600,
) -> None:
    """Run log cleanup every interval_seconds (default 1 hour)."""
    from .api.routes_settings import run_cleanup

    # Wait a bit on startup before first run
    try:
        await asyncio.wait_for(shutdown_event.wait(), timeout=60)
        return  # Shutdown during initial wait
    except asyncio.TimeoutError:
        pass

    while not shutdown_event.is_set():
        try:
            summary = run_cleanup(session_factory, engine)
            logger.info("Scheduled cleanup: %s", summary)
        except Exception as exc:
            logger.exception("Scheduled cleanup failed: %s", exc)
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=interval_seconds)
            return
        except asyncio.TimeoutError:
            pass


async def main_async(config: AppConfig) -> None:
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Initialise DB engine and create tables for MVP (can switch to Alembic migrations later).
    engine, SessionLocal = init_engine_and_sessionmaker(config.database_url)
    models.Base.metadata.create_all(bind=engine)
    # Ensure flows table has unique index for upsert (existing DBs may lack it; SQLite only).
    ensure_flows_unique_index(engine)
    ensure_ingest_job_error_columns(engine)

    # Create app instance.
    app = create_app(config)
    app.state.db_engine = engine
    app.state.db_sessionmaker = SessionLocal
    app.state.app_config = config

    # Shared ingestor for UDP + file upload.
    ingestor = SyslogIngestor(sessionmaker=SessionLocal, config=config)
    app.state.syslog_ingestor = ingestor

    # Mark any ingest jobs left in uploading/processing (e.g. from before a restart) as error.
    n = mark_stale_ingest_jobs_error(SessionLocal)
    if n:
        logger.info("Marked %d stale ingest job(s) as error on startup", n)

    shutdown_event = asyncio.Event()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_event.set)

    # Run HTTP server, syslog receiver, and scheduled cleanup concurrently.
    await asyncio.gather(
        _run_uvicorn(app, config, shutdown_event),
        _run_syslog(config, shutdown_event, ingestor),
        _run_scheduled_cleanup(shutdown_event, SessionLocal, engine, interval_seconds=3600),
    )


def cli(argv: Optional[list[str]] = None) -> None:
    """Console entrypoint defined in pyproject."""
    config = parse_args(argv)
    asyncio.run(main_async(config))


def main() -> None:
    """Entrypoint for `python -m app`."""
    cli()


if __name__ == "__main__":
    main()

