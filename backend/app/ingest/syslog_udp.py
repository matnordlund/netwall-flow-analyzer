from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

from .stats import ingest_stats, SAMPLE_RAW_LINE_MAX

logger = logging.getLogger("netwall.syslog")


SyslogHandler = Callable[[str], Awaitable[None]]


async def default_syslog_handler(line: str) -> None:
    """Placeholder handler; will be wired to reconstructor + parser."""
    logger.debug("Received syslog line: %s", line.rstrip())


async def run_syslog_udp_server(
    host: str,
    port: int,
    shutdown_event: asyncio.Event,
    handler: SyslogHandler = default_syslog_handler,
) -> None:
    """Run a simple UDP server that splits datagrams into lines and feeds them to handler."""

    loop = asyncio.get_running_loop()

    class SyslogProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
            ingest_stats.udp_packets += 1
            ingest_stats.udp_bytes += len(data)
            text = data.decode(errors="replace")
            for line in text.splitlines():
                if not line.strip():
                    continue
                ingest_stats.lines_received += 1
                ingest_stats.sample_raw_line = (
                    line[:SAMPLE_RAW_LINE_MAX] + ("..." if len(line) > SAMPLE_RAW_LINE_MAX else "")
                )
                asyncio.create_task(handler(line))
            ingest_stats.touch()

        def error_received(self, exc: Exception) -> None:  # type: ignore[override]
            logger.error("Syslog UDP error: %s", exc)

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(),
        local_addr=(host, port),
    )

    try:
        await shutdown_event.wait()
    finally:
        transport.close()

