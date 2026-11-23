import asyncio
import logging

from app.pipeline import SIEMPipeline

logger = logging.getLogger("siem.syslog_server")


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, pipeline: SIEMPipeline) -> None:
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        peer_ip = addr[0] if addr else None
        try:
            text = data.decode("utf-8", errors="replace").strip()
            if text:
                self.pipeline.ingest_raw_syslog(text, peer_ip=peer_ip)
        except Exception:
            logger.exception("Error procesando datagrama Syslog UDP")


class SyslogCollectorServer:
    """Servidor Syslog RFC 5424 asíncrono (UDP + TCP con soporte RFC 6587)."""

    def __init__(
        self,
        pipeline: SIEMPipeline,
        *,
        host: str,
        port: int,
        max_message_bytes: int = 65536,
    ) -> None:
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.max_message_bytes = max_message_bytes
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self.udp_port: int | None = None
        self.tcp_port: int | None = None

    @property
    def udp_active(self) -> bool:
        return self._udp_transport is not None and not self._udp_transport.is_closing()

    @property
    def tcp_active(self) -> bool:
        return self._tcp_server is not None and self._tcp_server.is_serving()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogUDPProtocol(self.pipeline),
            local_addr=(self.host, self.port),
        )
        self._udp_transport = transport
        udp_sock = transport.get_extra_info("socket")
        self.udp_port = int(udp_sock.getsockname()[1]) if udp_sock else self.port

        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            host=self.host,
            port=self.port,
            limit=self.max_message_bytes,
        )
        sockets = self._tcp_server.sockets or []
        self.tcp_port = int(sockets[0].getsockname()[1]) if sockets else self.port
        logger.info(
            "Colector Syslog RFC 5424 activo en %s (UDP:%s, TCP:%s)",
            self.host,
            self.udp_port,
            self.tcp_port,
        )

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if isinstance(peer, tuple) and peer else None
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                # Soporte opcional para framing octet-counting RFC 6587 ("<len> <syslog>")
                if text[0].isdigit() and " <" in text[:16]:
                    prefix, remainder = text.split(" ", 1)
                    if prefix.isdigit() and remainder.startswith("<"):
                        text = remainder
                self.pipeline.ingest_raw_syslog(text, peer_ip=peer_ip)
        except Exception:
            logger.exception("Error procesando conexión Syslog TCP")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                logger.debug("Cierre de socket TCP Syslog finalizado con OSError esperado")
