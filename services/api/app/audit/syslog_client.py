from collections.abc import Callable
from datetime import datetime, timezone
import logging
import os
import socket

from fastapi import Request

logger = logging.getLogger("api.audit.syslog")

SYSLOG_FACILITY_AUTHPRIV = 10
SYSLOG_SEVERITY_CRIT = 2
SYSLOG_SEVERITY_ERR = 3
SYSLOG_SEVERITY_WARNING = 4
SYSLOG_SEVERITY_NOTICE = 5
SYSLOG_SEVERITY_INFO = 6

# Enterprise ID reservado para documentación/proyectos RFC 5424 (32473)
AUDIT_SD_ID = "audit@32473"


def _sanitize_header_token(value: str, *, max_len: int, fallback: str = "-") -> str:
    cleaned = "".join(
        ch for ch in value.strip() if 33 <= ord(ch) <= 126 and ch not in ("\r", "\n")
    )
    if not cleaned:
        return fallback
    return cleaned[:max_len]


def _escape_sd_value(value: str) -> str:
    cleaned = value.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    return cleaned.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sanitize_msg_text(value: str) -> str:
    cleaned = value.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    return "".join(ch if ord(ch) >= 32 else " " for ch in cleaned).strip()


def format_rfc5424_message(
    *,
    msg_id: str,
    message: str,
    severity: int = SYSLOG_SEVERITY_INFO,
    facility: int = SYSLOG_FACILITY_AUTHPRIV,
    app_name: str = "hospital-privacy-api",
    hostname: str | None = None,
    proc_id: str | None = None,
    structured_params: dict[str, object] | None = None,
    timestamp: datetime | None = None,
) -> str:
    """Formatea un evento de auditoría cumpliendo estrictamente Syslog RFC 5424."""
    bounded_facility = max(0, min(23, int(facility)))
    bounded_severity = max(0, min(7, int(severity)))
    pri = bounded_facility * 8 + bounded_severity

    ts = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ts_str = ts.isoformat().replace("+00:00", "Z")
    host = _sanitize_header_token(hostname or socket.gethostname(), max_len=255)
    app = _sanitize_header_token(app_name, max_len=48, fallback="hospital-api")
    pid = _sanitize_header_token(proc_id or str(os.getpid()), max_len=128)
    mid = _sanitize_header_token(msg_id, max_len=32, fallback="AUDIT_EVENT")

    sd_part = "-"
    if structured_params:
        encoded_pairs: list[str] = []
        for raw_key, raw_val in structured_params.items():
            if raw_val is None:
                continue
            key = _sanitize_header_token(str(raw_key), max_len=32, fallback="")
            if not key or "=" in key or "]" in key or '"' in key:
                continue
            val = _escape_sd_value(str(raw_val))
            encoded_pairs.append(f'{key}="{val}"')
        if encoded_pairs:
            sd_part = f"[{AUDIT_SD_ID} {' '.join(encoded_pairs)}]"

    msg_part = _sanitize_msg_text(message)
    return f"<{pri}>1 {ts_str} {host} {app} {pid} {mid} {sd_part} {msg_part}"


def extract_client_ip(request: Request | None) -> str:
    """Extrae IP del cliente priorizando cabeceras Cloudflare/Proxy sin confiar ciegamente."""
    if request is None:
        return "unknown"
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()[:64]
    xff = request.headers.get("x-forwarded-for")
    if xff and xff.strip():
        return xff.split(",")[0].strip()[:64]
    if request.client and request.client.host:
        return str(request.client.host)[:64]
    return "unknown"


def extract_request_id(request: Request | None) -> str | None:
    if request is None:
        return None
    state_id = getattr(request.state, "request_id", None)
    if state_id:
        return str(state_id)
    header_id = request.headers.get("x-request-id")
    return header_id.strip()[:64] if header_id else None


class SyslogAuditClient:
    """
    Emisor Syslog RFC 5424 hacia el colector SIEM (`siem-collector:5514`).
    Operación resiliente (best-effort): nunca bloquea ni interrumpe la API si
    el colector está temporalmente inaccesible.
    """

    def __init__(
        self,
        *,
        host: str = "siem-collector",
        port: int = 5514,
        protocol: str = "udp",
        enabled: bool = True,
        app_name: str = "hospital-privacy-api",
        timeout_seconds: float = 0.5,
        sink: Callable[[str], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.enabled = enabled
        self.app_name = app_name
        self.timeout_seconds = timeout_seconds
        self._sink = sink

    def emit_event(
        self,
        *,
        msg_id: str,
        message: str,
        severity: int = SYSLOG_SEVERITY_INFO,
        actor: str | None = None,
        role: str | None = None,
        action: str | None = None,
        outcome: str = "success",
        purpose: str | None = None,
        resource: str | None = None,
        records_count: int | None = None,
        request: Request | None = None,
        source_ip: str | None = None,
        request_id: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> str:
        params: dict[str, object] = {
            "actor": actor,
            "role": role,
            "action": action,
            "outcome": outcome,
            "purpose": purpose,
            "resource": resource,
            "source_ip": source_ip or extract_client_ip(request),
            "request_id": request_id or extract_request_id(request),
        }
        if records_count is not None:
            params["records_count"] = records_count
        if extra:
            params.update(extra)

        frame = format_rfc5424_message(
            msg_id=msg_id,
            message=message,
            severity=severity,
            app_name=self.app_name,
            structured_params=params,
        )
        if not self.enabled:
            return frame

        if self._sink is not None:
            self._sink(frame)
            return frame

        self._send_network(frame)
        return frame

    def _send_network(self, frame: str) -> None:
        payload = frame.encode("utf-8")
        try:
            if self.protocol == "tcp":
                with socket.create_connection(
                    (self.host, self.port),
                    timeout=self.timeout_seconds,
                ) as sock:
                    sock.sendall(payload + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout_seconds)
                    sock.sendto(payload, (self.host, self.port))
        except OSError as exc:
            logger.debug("No se pudo enviar evento Syslog al SIEM (%s:%s): %s", self.host, self.port, exc)
