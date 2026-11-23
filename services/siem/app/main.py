from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import SIEMSettings, load_siem_settings
from app.dashboard import SOC_DASHBOARD_HTML
from app.models import (
    AlertAckRequest,
    AlertSeverity,
    CorrelationRuleInfo,
    SIEMAlertResponse,
    SIEMEventResponse,
    SIEMStatsResponse,
    SyslogIngestRequest,
    SyslogIngestResponse,
)
from app.pipeline import SIEMPipeline
from app.storage import SIEMStorage
from app.syslog_server import SyslogCollectorServer


class SIEMSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Cabeceras defensivas Zero Trust para la consola y API del SIEM."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        if request.url.path == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "frame-ancestors 'none'; base-uri 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
            )
        return response


def create_siem_app(settings: SIEMSettings | None = None) -> FastAPI:
    active_settings = settings or load_siem_settings()
    storage = SIEMStorage(db_path=active_settings.db_path)
    pipeline = SIEMPipeline(settings=active_settings, storage=storage)
    syslog_server = SyslogCollectorServer(
        pipeline=pipeline,
        host=active_settings.syslog_host,
        port=active_settings.syslog_port,
        max_message_bytes=active_settings.max_message_bytes,
    )

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        if active_settings.enable_syslog_listener:
            await syslog_server.start()
        try:
            yield
        finally:
            await syslog_server.stop()
            storage.close()

    application = FastAPI(
        title="Hospital-SIEM-Collector",
        version="1.0.0",
        description=(
            "Colector Syslog RFC 5424, pipeline de sanitización regex en ingesta (MC-03) "
            "y motor de correlación temporal SOC (MC-04)"
        ),
        lifespan=lifespan,
    )
    application.add_middleware(SIEMSecurityHeadersMiddleware)
    application.state.siem_settings = active_settings
    application.state.siem_storage = storage
    application.state.siem_pipeline = pipeline
    application.state.syslog_server = syslog_server

    @application.get("/health", tags=["siem"])
    def health_check() -> dict[str, object]:
        stats = storage.get_stats()
        return {
            "status": "ok",
            "service": active_settings.service_name,
            "syslog_port": str(syslog_server.udp_port or active_settings.syslog_port),
            "syslog_udp_active": syslog_server.udp_active,
            "syslog_tcp_active": syslog_server.tcp_active,
            "events_count": stats.total_events,
            "alerts_count": stats.total_alerts,
            "open_alerts": stats.open_alerts,
        }

    @application.get("/", response_class=HTMLResponse, tags=["siem-ui"])
    def soc_dashboard() -> HTMLResponse:
        return HTMLResponse(content=SOC_DASHBOARD_HTML)

    @application.post(
        "/api/v1/ingest/syslog",
        response_model=SyslogIngestResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["ingesta-mc02-mc03"],
        summary="Ingerir una trama Syslog RFC 5424 por HTTP, sanitizar PII/secretos y evaluar correlación",
    )
    def ingest_syslog_http(
        payload: SyslogIngestRequest,
        request: Request,
    ) -> SyslogIngestResponse:
        client_ip = payload.source_ip or (request.client.host if request.client else None)
        return pipeline.ingest_raw_syslog(payload.raw_message, peer_ip=client_ip)

    @application.get(
        "/api/v1/events",
        response_model=list[SIEMEventResponse],
        tags=["auditoria-mc02-mc03"],
        summary="Consultar eventos Syslog RFC 5424 persistidos (ya sanitizados en ingesta)",
    )
    def list_events(
        limit: int = Query(default=100, ge=1, le=500),
        msg_id: str | None = Query(default=None, max_length=32),
        actor: str | None = Query(default=None, max_length=64),
        source_ip: str | None = Query(default=None, max_length=64),
        max_severity: int | None = Query(default=None, ge=0, le=7),
        sanitized_only: bool = Query(default=False),
    ) -> list[SIEMEventResponse]:
        return storage.list_events(
            limit=limit,
            msg_id=msg_id,
            actor=actor,
            source_ip=source_ip,
            max_severity=max_severity,
            sanitized_only=sanitized_only,
        )

    @application.get(
        "/api/v1/alerts",
        response_model=list[SIEMAlertResponse],
        tags=["correlacion-mc04"],
        summary="Listar alertas disparadas por las reglas de correlación temporal SOC",
    )
    def list_alerts(
        limit: int = Query(default=100, ge=1, le=500),
        rule_id: str | None = Query(default=None, max_length=32),
        severity: AlertSeverity | None = Query(default=None),
        acknowledged: bool | None = Query(default=None),
    ) -> list[SIEMAlertResponse]:
        return storage.list_alerts(
            limit=limit,
            rule_id=rule_id,
            severity=severity,
            acknowledged=acknowledged,
        )

    @application.post(
        "/api/v1/alerts/{alert_id}/ack",
        response_model=SIEMAlertResponse,
        tags=["correlacion-mc04"],
        summary="Marcar una alerta SOC como reconocida por un analista",
    )
    def acknowledge_alert(alert_id: int, payload: AlertAckRequest) -> SIEMAlertResponse:
        updated = storage.acknowledge_alert(
            alert_id=alert_id,
            acknowledged_by=payload.acknowledged_by,
        )
        if updated is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alerta SIEM no encontrada.",
            )
        return updated

    @application.get(
        "/api/v1/rules",
        response_model=list[CorrelationRuleInfo],
        tags=["correlacion-mc04"],
        summary="Consultar catálogo de reglas activas de correlación temporal",
    )
    def list_rules() -> list[CorrelationRuleInfo]:
        return pipeline.correlator.describe_rules()

    @application.get(
        "/api/v1/stats",
        response_model=SIEMStatsResponse,
        tags=["siem"],
        summary="Métricas globales del colector SIEM (ingesta, sanitización y alertas)",
    )
    def get_stats() -> SIEMStatsResponse:
        return storage.get_stats()

    return application


app = create_siem_app()
