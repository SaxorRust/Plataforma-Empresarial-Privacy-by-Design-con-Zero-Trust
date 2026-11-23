"""
Suite de pruebas automatizadas para Módulo C — Auditoría SIEM y SOC (MC-02, MC-03, MC-04):
- MC-02: Centralización Syslog RFC 5424 (emisor API, parser, transporte real UDP/TCP y HTTP).
- MC-03: Sanitización Regex en ingesta ANTES de persistir (tarjetas Luhn, CURP, contraseñas, JWT, NSS).
- MC-04: Reglas de correlación temporal (fuerza bruta, consultas masivas CRÍTICA y denegaciones OPA).
- Integración end-to-end API Hospitalaria -> UDP RFC 5424 -> Colector SIEM -> Alertas SOC.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import sqlite3
import time

from conftest import load_service_app
from fastapi.testclient import TestClient


def _build_siem_test_app(
    tmp_path: Path,
    *,
    enable_listener: bool = False,
    syslog_port: int = 0,
    brute_force_threshold: int = 5,
    brute_force_window_seconds: int = 60,
    mass_query_threshold: int = 10,
    mass_records_threshold: int = 25,
    mass_query_window_seconds: int = 60,
    policy_denial_threshold: int = 5,
    alert_cooldown_seconds: int = 30,
):
    load_service_app("siem")
    from app.config import SIEMSettings
    from app.main import create_siem_app

    db_file = tmp_path / "siem_test.db"
    settings = SIEMSettings(
        service_name="siem-collector",
        syslog_host="127.0.0.1",
        syslog_port=syslog_port,
        enable_syslog_listener=enable_listener,
        db_path=str(db_file),
        max_message_bytes=65536,
        brute_force_threshold=brute_force_threshold,
        brute_force_window_seconds=brute_force_window_seconds,
        mass_query_threshold=mass_query_threshold,
        mass_records_threshold=mass_records_threshold,
        mass_query_window_seconds=mass_query_window_seconds,
        policy_denial_threshold=policy_denial_threshold,
        policy_denial_window_seconds=120,
        alert_cooldown_seconds=alert_cooldown_seconds,
    )
    return create_siem_app(settings), db_file


def _rfc5424_line(
    *,
    msg_id: str,
    message: str,
    pri: int = 86,
    timestamp: datetime | None = None,
    actor: str = "dr_garcia",
    role: str = "medico",
    action: str = "read_record",
    outcome: str = "success",
    source_ip: str = "198.51.100.10",
    records_count: int = 1,
    extra_sd: str = "",
) -> str:
    ts = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ts_iso = ts.isoformat().replace("+00:00", "Z")
    sd_fields = (
        f'actor="{actor}" role="{role}" action="{action}" outcome="{outcome}" '
        f'source_ip="{source_ip}" records_count="{records_count}"'
    )
    if extra_sd:
        sd_fields = f"{sd_fields} {extra_sd}"
    return f"<{pri}>1 {ts_iso} hospital-node hospital-privacy-api 4201 {msg_id} [audit@32473 {sd_fields}] {message}"


def _wait_until(predicate, *, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_mc02_rfc5424_parser_log_forging_defense_and_udp_tcp_transport(tmp_path):
    """MC-02: Verifica parseo RFC 5424, defensa CWE-117 y recepción real por UDP y TCP."""
    siem_app, _ = _build_siem_test_app(tmp_path, enable_listener=True, syslog_port=0)

    with TestClient(siem_app) as client:
        health = client.get("/health").json()
        assert health["status"] == "ok"
        assert health["syslog_udp_active"] is True
        assert health["syslog_tcp_active"] is True

        udp_port = siem_app.state.syslog_server.udp_port
        tcp_port = siem_app.state.syslog_server.tcp_port
        assert udp_port is not None and udp_port > 0
        assert tcp_port is not None and tcp_port > 0

        # 1. Envío real por UDP con intento de Log Forging (\r\n inyectado)
        udp_frame = _rfc5424_line(
            msg_id="CLINICAL_RECORD_READ",
            message="Consulta expediente\r\n<134>1 2026-11-23T00:00:00Z fake app 1 FAKE - inyectado",
            actor="dr_udp",
            source_ip="198.51.100.21",
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.sendto(udp_frame.encode("utf-8"), ("127.0.0.1", udp_port))

        # 2. Envío real por TCP usando framing octet-counting (RFC 6587)
        tcp_frame = _rfc5424_line(
            msg_id="AUTH_LOGIN_SUCCESS",
            message="Inicio de sesión verificado vía TCP Syslog",
            actor="dr_tcp",
            source_ip="198.51.100.22",
        )
        octet_framed = f"{len(tcp_frame.encode('utf-8'))} {tcp_frame}\n"
        with socket.create_connection(("127.0.0.1", tcp_port), timeout=2.0) as tcp_sock:
            tcp_sock.sendall(octet_framed.encode("utf-8"))

        assert _wait_until(lambda: len(client.get("/api/v1/events").json()) >= 2)
        events = client.get("/api/v1/events").json()
        by_actor = {ev["actor"]: ev for ev in events}

        assert "dr_udp" in by_actor
        assert by_actor["dr_udp"]["rfc5424_valid"] is True
        assert by_actor["dr_udp"]["msg_id"] == "CLINICAL_RECORD_READ"
        assert "\r" not in by_actor["dr_udp"]["message"]
        assert "\n" not in by_actor["dr_udp"]["message"]

        assert "dr_tcp" in by_actor
        assert by_actor["dr_tcp"]["rfc5424_valid"] is True
        assert by_actor["dr_tcp"]["msg_id"] == "AUTH_LOGIN_SUCCESS"

        # 3. Dashboard HTML SOC operativo y con cabeceras Zero Trust
        dash = client.get("/")
        assert dash.status_code == 200
        assert "Consola SIEM" in dash.text
        assert dash.headers.get("x-content-type-options") == "nosniff"
        assert dash.headers.get("x-frame-options") == "DENY"


def test_mc03_ingestion_regex_sanitization_before_persistence(tmp_path):
    """MC-03: Ofusca tarjetas (Luhn), CURP, contraseñas, NSS y JWT ANTES de persistir en SQLite."""
    siem_app, db_file = _build_siem_test_app(tmp_path, enable_listener=False)

    sensitive_card = "4111-1111-1111-1111"
    sensitive_curp = "PERJ920514HPLRNS08"
    sensitive_pwd = "SuperClaveHospital2026!"
    sensitive_nss = "45901234567"
    sensitive_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEiLCJyb2xlIjoibWVkaWNvIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    frame = _rfc5424_line(
        msg_id="AUDIT_LEAK_SIMULATION",
        actor="dr_auditoria",
        extra_sd=f'password="{sensitive_pwd}" curp="{sensitive_curp}"',
        message=(
            f"Pago tarjeta={sensitive_card} paciente curp={sensitive_curp} "
            f'nss={sensitive_nss} "password": "{sensitive_pwd}" '
            f"Authorization: Bearer {sensitive_jwt}"
        ),
    )

    with TestClient(siem_app) as client:
        resp = client.post("/api/v1/ingest/syslog", json={"raw_message": frame})
        assert resp.status_code == 201
        event = resp.json()["event"]

        assert event["sanitized"] is True
        assert event["redaction_count"] >= 5
        assert "credit_card" in event["redacted_categories"]
        assert "curp" in event["redacted_categories"]
        assert "password" in event["redacted_categories"]
        assert "nss" in event["redacted_categories"]
        assert "jwt" in event["redacted_categories"]

        # Verificar que la respuesta API solo expone valores enmascarados (***)
        assert "***" in event["message"]
        assert event["structured_data"]["audit@32473"]["password"] == "***"
        assert event["structured_data"]["audit@32473"]["curp"] == "***"

        for leaked in (sensitive_card, sensitive_curp, sensitive_pwd, sensitive_nss, sensitive_jwt):
            assert leaked not in event["message"]
            assert leaked not in event["raw_sanitized"]

        # Verificación directa en el archivo SQLite en disco: CERO valores crudos persistidos
        conn = sqlite3.connect(db_file)
        try:
            row = conn.execute(
                "SELECT message, raw_sanitized, structured_data_json FROM siem_events WHERE id = ?",
                (event["id"],),
            ).fetchone()
            assert row is not None
            persisted_blob = " ".join(row)
            for leaked in (sensitive_card, sensitive_curp, sensitive_pwd, sensitive_nss, sensitive_jwt):
                assert leaked not in persisted_blob
            assert "***" in persisted_blob
        finally:
            conn.close()

        # Confirmar estadísticas de sanitización
        stats = client.get("/api/v1/stats").json()
        assert stats["sanitized_events"] == 1
        assert stats["total_redactions"] >= 5
        assert stats["redactions_by_category"]["credit_card"] == 1
        assert stats["redactions_by_category"]["curp"] == 1


def test_mc04_temporal_correlation_brute_force_and_mass_queries(tmp_path):
    """MC-04: Dispara RULE-001 (fuerza bruta), RULE-002 (CRÍTICA consultas masivas) y RULE-003 (OPA)."""
    siem_app, _ = _build_siem_test_app(
        tmp_path,
        enable_listener=False,
        brute_force_threshold=5,
        brute_force_window_seconds=60,
        mass_query_threshold=10,
        mass_records_threshold=25,
        mass_query_window_seconds=60,
        policy_denial_threshold=4,
        alert_cooldown_seconds=30,
    )

    base_ts = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)

    with TestClient(siem_app) as client:
        # Verificar catálogo de reglas activas (>= 2 reglas requeridas)
        rules = client.get("/api/v1/rules").json()
        rule_ids = {r["rule_id"] for r in rules}
        assert {"RULE-001", "RULE-002", "RULE-003"}.issubset(rule_ids)

        # ----------------------------------------------------------------------
        # Caso 1: Eventos antiguos fuera de ventana NO deben disparar fuerza bruta
        # ----------------------------------------------------------------------
        old_ts = base_ts - timedelta(minutes=10)
        for idx in range(4):
            r = client.post(
                "/api/v1/ingest/syslog",
                json={
                    "raw_message": _rfc5424_line(
                        msg_id="AUTH_LOGIN_FAILED",
                        message="Login fallido antiguo",
                        pri=84,
                        timestamp=old_ts + timedelta(seconds=idx),
                        actor="victima_1",
                        outcome="failure",
                        source_ip="203.0.113.55",
                    )
                },
            )
            assert r.status_code == 201
            assert r.json()["triggered_alerts"] == []

        # 4 intentos recientes -> debajo del umbral (5), aún NO dispara
        for idx in range(4):
            r = client.post(
                "/api/v1/ingest/syslog",
                json={
                    "raw_message": _rfc5424_line(
                        msg_id="AUTH_LOGIN_FAILED",
                        message=f"Intento fallido #{idx + 1}",
                        pri=84,
                        timestamp=base_ts + timedelta(seconds=idx * 5),
                        actor="victima_1",
                        outcome="failure",
                        source_ip="203.0.113.55",
                    )
                },
            )
            assert r.json()["triggered_alerts"] == []

        # 5to intento dentro de 60s -> DISPARA RULE-001 (BRUTE_FORCE_LOGIN)
        fifth = client.post(
            "/api/v1/ingest/syslog",
            json={
                "raw_message": _rfc5424_line(
                    msg_id="AUTH_LOGIN_FAILED",
                    message="Intento fallido #5",
                    pri=84,
                    timestamp=base_ts + timedelta(seconds=25),
                    actor="victima_1",
                    outcome="failure",
                    source_ip="203.0.113.55",
                )
            },
        )
        bf_alerts = fifth.json()["triggered_alerts"]
        assert len(bf_alerts) == 1
        assert bf_alerts[0]["rule_id"] == "RULE-001"
        assert bf_alerts[0]["rule_name"] == "BRUTE_FORCE_LOGIN"
        assert bf_alerts[0]["severity"] == "HIGH"
        assert bf_alerts[0]["event_count"] == 5

        # ----------------------------------------------------------------------
        # Caso 2: Consultas masivas de expedientes en ventana corta -> ALERTA CRÍTICA (RULE-002)
        # ----------------------------------------------------------------------
        mass_alert = None
        for idx in range(10):
            r = client.post(
                "/api/v1/ingest/syslog",
                json={
                    "raw_message": _rfc5424_line(
                        msg_id="CLINICAL_RECORD_READ",
                        message=f"Lectura rápida expediente #{idx + 1}",
                        timestamp=base_ts + timedelta(seconds=idx * 2),
                        actor="dr_exfiltrador",
                        role="medico",
                        action="read_single_record",
                        source_ip="198.51.100.88",
                        records_count=1,
                    )
                },
            )
            assert r.status_code == 201
            if r.json()["triggered_alerts"]:
                mass_alert = r.json()["triggered_alerts"][0]

        assert mass_alert is not None
        assert mass_alert["rule_id"] == "RULE-002"
        assert mass_alert["rule_name"] == "MASS_RECORD_ACCESS"
        assert mass_alert["severity"] == "CRITICAL"
        assert mass_alert["actor"] == "dr_exfiltrador"

        # También dispara alerta CRÍTICA por volumen acumulado de expedientes (3 listados x 10 = 30 >= 25)
        vol_alert = None
        for idx in range(3):
            r = client.post(
                "/api/v1/ingest/syslog",
                json={
                    "raw_message": _rfc5424_line(
                        msg_id="CLINICAL_RECORD_LIST",
                        message="Listado masivo de expedientes",
                        timestamp=base_ts + timedelta(seconds=idx * 3),
                        actor="analista_masivo",
                        role="analista",
                        action="read_record",
                        source_ip="198.51.100.89",
                        records_count=10,
                    )
                },
            )
            if r.json()["triggered_alerts"]:
                vol_alert = r.json()["triggered_alerts"][0]

        assert vol_alert is not None
        assert vol_alert["rule_id"] == "RULE-002"
        assert vol_alert["severity"] == "CRITICAL"
        assert vol_alert["event_count"] >= 25

        # ----------------------------------------------------------------------
        # Caso 3: Intentos reiterados de Function Creep (OPA_POLICY_DENIED -> RULE-003)
        # ----------------------------------------------------------------------
        opa_alert = None
        for idx in range(4):
            r = client.post(
                "/api/v1/ingest/syslog",
                json={
                    "raw_message": _rfc5424_line(
                        msg_id="OPA_POLICY_DENIED",
                        message="Acceso fuera de propósito bloqueado por OPA",
                        pri=84,
                        timestamp=base_ts + timedelta(seconds=idx * 4),
                        actor="admin_curioso",
                        role="admin_sec",
                        action="read_record",
                        outcome="denied",
                        source_ip="198.51.100.90",
                    )
                },
            )
            if r.json()["triggered_alerts"]:
                opa_alert = r.json()["triggered_alerts"][0]

        assert opa_alert is not None
        assert opa_alert["rule_id"] == "RULE-003"
        assert opa_alert["rule_name"] == "REPEATED_POLICY_DENIAL"

        # Reconocimiento (ACK) de alerta crítica desde el SOC
        ack = client.post(
            f"/api/v1/alerts/{mass_alert['id']}/ack",
            json={"acknowledged_by": "samuel_soc"},
        )
        assert ack.status_code == 200
        assert ack.json()["acknowledged"] is True
        assert ack.json()["status"] == "ACKNOWLEDGED"
        assert ack.json()["acknowledged_by"] == "samuel_soc"

        critical_alerts = client.get("/api/v1/alerts?severity=CRITICAL").json()
        assert len(critical_alerts) == 2


def test_end_to_end_api_emits_rfc5424_over_udp_and_triggers_siem_alerts(tmp_path):
    """Integración real API -> Syslog UDP RFC 5424 -> Colector SIEM -> Alertas SOC."""
    siem_app, _ = _build_siem_test_app(
        tmp_path,
        enable_listener=True,
        syslog_port=0,
        brute_force_threshold=5,
        mass_query_threshold=6,
        policy_denial_threshold=3,
    )

    with TestClient(siem_app) as siem_client:
        udp_port = siem_app.state.syslog_server.udp_port
        assert udp_port is not None and udp_port > 0

        # Cargar la API hospitalaria apuntando su emisor Syslog al colector SIEM real en UDP
        from test_privacy_module_a import _build_module_a_client

        api_client, _, _, _, headers_for = _build_module_a_client()
        from app.audit.syslog_client import SyslogAuditClient
        from app.security.dependencies import get_audit_client, get_user_repository
        from test_auth_ma01 import InMemoryUserRepository

        user_repo = InMemoryUserRepository()
        api_client.app.dependency_overrides[get_user_repository] = lambda: user_repo
        api_client.app.dependency_overrides[get_audit_client] = lambda: SyslogAuditClient(
            host="127.0.0.1",
            port=udp_port,
            protocol="udp",
            enabled=True,
        )

        # 1. Simular 5 intentos de login fallidos en la API -> dispara RULE-001 en SIEM
        for _ in range(5):
            login_resp = api_client.post(
                "/auth/login",
                json={"username": "dr_inexistente", "password": "WrongPassword!2026"},
                headers={"CF-Connecting-IP": "198.51.100.77"},
            )
            assert login_resp.status_code == 401

        # 2. Simular ráfaga de 6 consultas de expedientes por el mismo médico -> dispara RULE-002 CRÍTICA
        medico_headers = headers_for("medico", "atencion_medica")
        medico_headers["CF-Connecting-IP"] = "198.51.100.78"
        for _ in range(6):
            rec_resp = api_client.get("/clinical/records", headers=medico_headers)
            assert rec_resp.status_code == 200

        # 3. Simular 3 intentos de Function Creep bloqueados por OPA -> dispara RULE-003
        bad_headers = headers_for("admin_sec", "atencion_medica")
        bad_headers["CF-Connecting-IP"] = "198.51.100.79"
        for _ in range(3):
            denied = api_client.get("/clinical/records", headers=bad_headers)
            assert denied.status_code == 403

        # Esperar llegada asíncrona de datagramas UDP al colector SIEM
        assert _wait_until(lambda: len(siem_client.get("/api/v1/alerts").json()) >= 3)

        events = siem_client.get("/api/v1/events?limit=100").json()
        assert len(events) >= 14
        assert all(ev["rfc5424_valid"] is True for ev in events)
        # Ninguna contraseña de prueba debe haberse filtrado en ningún evento
        assert all("WrongPassword!2026" not in ev["raw_sanitized"] for ev in events)

        alerts = siem_client.get("/api/v1/alerts").json()
        alerts_by_rule = {a["rule_id"]: a for a in alerts}
        assert "RULE-001" in alerts_by_rule
        assert alerts_by_rule["RULE-001"]["rule_name"] == "BRUTE_FORCE_LOGIN"
        assert "RULE-002" in alerts_by_rule
        assert alerts_by_rule["RULE-002"]["severity"] == "CRITICAL"
        assert "RULE-003" in alerts_by_rule
