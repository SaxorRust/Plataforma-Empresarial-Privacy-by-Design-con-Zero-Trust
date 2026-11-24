"""
Suite de Pruebas Automatizadas de Seguridad — OWASP Top 10 (A01–A10)
Verifica controles activos de seguridad y Privacy-by-Design sobre la API Hospitalaria,
la bóveda HashiCorp Vault, el motor ABAC/OPA, el ciclo de vida NIST SP 800-88 y la
configuración de infraestructura (`docker-compose.yml` y `requirements.txt`).
"""

import base64
import json
from pathlib import Path
import re

from fastapi.testclient import TestClient
import jwt
from test_lifecycle_module_b import _admit_patient, _build_module_b_app
from test_privacy_module_a import _build_module_a_client
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_owasp_a01_broken_access_control():
    """OWASP A01: Denegación por defecto, escalación de privilegios, Function Creep y Path Traversal."""
    client, _, _, _, headers_for = _build_module_a_client()

    # 1. Acceso sin autenticación a endpoints protegidos -> 401
    for path in (
        "/auth/me",
        "/auth/users",
        "/clinical/records",
        "/clinical/policy/status",
        "/vault/status",
        "/lifecycle/ttl/status",
        "/lifecycle/certificates",
    ):
        assert client.get(path).status_code == 401, f"Se esperaba 401 sin token en {path}"

    # 2. Escalación de privilegios en auto-registro público -> 403 (y rol eliminado super_admin -> 422)
    assert (
        client.post(
            "/auth/register",
            json={
                "username": "atacante_admin",
                "password": "Hospital!2026#ZeroTrust",
                "role": "admin_sec",
            },
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/auth/register",
            json={
                "username": "atacante_super",
                "password": "Hospital!2026#ZeroTrust",
                "role": "super_admin",
            },
        ).status_code
        == 422
    )

    # 3. Function Creep y separación de funciones -> 403
    assert client.get("/clinical/records", headers=headers_for("medico", None)).status_code == 403
    assert (
        client.get("/clinical/records", headers=headers_for("medico", "publicidad")).status_code
        == 403
    )
    assert (
        client.get(
            "/clinical/records", headers=headers_for("admin_sec", "atencion_medica")
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/vault/patients/pat_" + "a" * 32,
            headers=headers_for("admin_sec", "mantenimiento_ttl"),
        ).status_code
        == 403
    )

    # 4. Path traversal / inyección de ruta en token opaco de Vault -> 400 o 404
    medico_headers = headers_for("medico", "atencion_medica")
    for malicious_token in ("..%2F..%2Fsys%2Fmounts", "pat_invalid", "pat_../../../etc/passwd"):
        resp = client.get(f"/vault/patients/{malicious_token}", headers=medico_headers)
        assert resp.status_code in (400, 404), f"Token malicioso no bloqueado: {malicious_token}"


def test_owasp_a02_cryptographic_failures():
    """OWASP A02: Rechazo de JWT alg=none / firma inválida y ausencia de PII en claro en bóveda."""
    app, _, _, _, _, headers_for = _build_module_b_app()
    client = TestClient(app)

    # 1. Rechazo de JWT forjado con algoritmo 'none' (ataque clásico JWT)
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload_b64 = (
        base64.urlsafe_b64encode(b'{"sub":"00000000-0000-0000-0000-000000000001","role":"admin_sec"}')
        .decode()
        .rstrip("=")
    )
    forged_none_jwt = f"{header_b64}.{payload_b64}."
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {forged_none_jwt}"})
    assert resp.status_code == 401

    # 2. Rechazo de JWT firmado con clave distinta
    wrong_key_jwt = jwt.encode(
        {
            "sub": "00000000-0000-0000-0000-000000000001",
            "username": "attacker",
            "role": "admin_sec",
            "amr": ["pwd"],
            "jti": "forged-jti",
            "iss": "Hospital-Privacy-ZeroTrust",
        },
        "wrong_attacker_secret_key_32bytes!",
        algorithm="HS256",
    )
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {wrong_key_jwt}"}).status_code == 401

    # 3. Verificación de Argon2id con salt único + pepper
    from app.security.passwords import Argon2idPasswordService

    svc = Argon2idPasswordService(pepper="owasp_test_pepper_123456")
    h1 = svc.hash_password("Hospital!2026#Secure")
    h2 = svc.hash_password("Hospital!2026#Secure")
    assert h1.startswith("$argon2id$")
    assert h1 != h2  # Salt único obligatorio


def test_owasp_a03_injection_and_mass_assignment():
    """OWASP A03: Bloqueo de payloads SQLi, mass-assignment (`extra=forbid`) y fuga PII en texto libre."""
    client, _, _, _, headers_for = _build_module_a_client()
    medico_headers = headers_for("medico", "atencion_medica")
    auditor_headers = headers_for("auditor_arco", "ejercicio_arco")

    # 1. SQL Injection en registro de usuario (bloqueado por patrón estricto) -> 422
    sqli_register = client.post(
        "/auth/register",
        json={
            "username": "admin' OR '1'='1",
            "password": "Hospital!2026#ZeroTrust",
            "role": "medico",
        },
    )
    assert sqli_register.status_code == 422

    # 2. SQL Injection en código CIE-10 y mass-assignment de campo PII -> 422
    sqli_clinical = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": "pat_" + "a" * 32,
            "age_years": 40,
            "zip_prefix": "72000",
            "gender": "M",
            "diagnosis_cie10": "I10'; DROP TABLE clinical.medical_records;--",
            "diagnosis_summary": "Control clinico",
            "department": "cardiologia",
            "is_sanitized": True,  # Mass assignment no permitido
        },
        headers=medico_headers,
    )
    assert sqli_clinical.status_code == 422

    # 3. SQL Injection en folio ARCO -> 422
    sqli_arco = client.post(
        "/lifecycle/arco/erasure",
        json={
            "opaque_patient_token": "pat_" + "b" * 32,
            "method": "NIST_800_88_PURGE",
            "arco_request_folio": "ARCO-1; DELETE FROM compliance.sanitization_certificates;--",
        },
        headers=auditor_headers,
    )
    assert sqli_arco.status_code == 422


def test_owasp_a04_insecure_design_fail_closed():
    """OWASP A04: Fail-Closed en motor de políticas OPA y en exportación (k, l) no satisfacible."""
    # 1. OPA inaccesible -> 503 (nunca autoriza por defecto)
    down_client, _, _, _, down_headers = _build_module_a_client(opa_fail_mode="connect_error")
    assert (
        down_client.get(
            "/clinical/records", headers=down_headers("medico", "atencion_medica")
        ).status_code
        == 503
    )

    # 2. Exportación desidentificada con k imposible -> 422 (nunca exporta registros reidentificables)
    app, _, _, _, _, headers_for = _build_module_b_app()
    client = TestClient(app)
    resp = client.post(
        "/lifecycle/exports/anonymized",
        json={"k": 5, "l": 2},
        headers=headers_for("analista", "investigacion_estadistica"),
    )
    assert resp.status_code == 422


def test_owasp_a05_security_misconfiguration():
    """OWASP A05: Cabeceras HTTP de endurecimiento, CORS estricto y hardening de Docker Compose."""
    client, _, _, _, _ = _build_module_a_client()

    # 1. Cabeceras Zero Trust en respuestas HTTP
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "strict-transport-security" in resp.headers
    assert "content-security-policy" in resp.headers
    assert "no-store" in resp.headers.get("cache-control", "")

    # 2. CORS rechaza orígenes no confiables
    evil_cors = client.options(
        "/health",
        headers={
            "Origin": "https://evil-attacker.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert evil_cors.headers.get("access-control-allow-origin") != "https://evil-attacker.example"

    # 3. Hardening en docker-compose.yml (least privilege, read_only, redes internal)
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for svc_name, svc in compose["services"].items():
        sec_opts = svc.get("security_opt", [])
        assert "no-new-privileges:true" in sec_opts, f"{svc_name} sin no-new-privileges:true"
        for port_binding in svc.get("ports", []):
            assert str(port_binding).startswith("127.0.0.1:"), (
                f"{svc_name} expone puerto fuera de loopback: {port_binding}"
            )
    for internal_net in ("data_net", "vault_net", "policy_net", "audit_net"):
        assert compose["networks"][internal_net].get("internal") is True


def test_owasp_a06_pinned_components_supply_chain():
    """OWASP A06: Todas las dependencias Python deben estar fijadas con versión exacta (`==`)."""
    req_files = [
        ROOT / "services" / "api" / "requirements.txt",
        ROOT / "services" / "siem" / "requirements.txt",
    ]
    exact_pin_re = re.compile(r"^[A-Za-z0-9_.\-\[\]]+==[0-9A-Za-z._\-+]+$")
    for req_file in req_files:
        lines = [
            line.strip()
            for line in req_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert lines, f"{req_file} no puede estar vacío"
        for line in lines:
            assert exact_pin_re.match(line), (
                f"Dependencia sin versión exacta fijada en {req_file.name}: {line}"
            )


def test_owasp_a07_identification_and_authentication_failures():
    """OWASP A07: Política de contraseñas robustas y rechazo de credenciales débiles."""
    client, _, _, _, _ = _build_module_a_client()

    # Contraseña débil rechazada -> 422
    weak_resp = client.post(
        "/auth/register",
        json={"username": "weak_user_1", "password": "password123", "role": "medico"},
    )
    assert weak_resp.status_code == 422

    # Cabecera Authorization con esquema inválido -> 401
    bad_scheme = client.get("/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert bad_scheme.status_code == 401


def test_owasp_a08_software_and_data_integrity_failures():
    """OWASP A08: Detección de manipulación en certificados SHA-256."""
    from uuid import UUID

    app, _, _, cert_repo, _, headers_for = _build_module_b_app()
    client = TestClient(app)
    medico_headers = headers_for("medico", "atencion_medica")
    auditor_headers = headers_for("auditor_arco", "ejercicio_arco")

    tok, _ = _admit_patient(
        client,
        medico_headers,
        full_name="Integridad Prueba OWASP",
        curp="IPOW900101HPLRNS01",
        nss="91000000001",
        age_years=36,
        zip_prefix="72000",
        gender="M",
        diagnosis_cie10="I10",
    )
    erase = client.post(
        "/lifecycle/arco/erasure",
        json={
            "opaque_patient_token": tok,
            "method": "NIST_800_88_PURGE",
            "arco_request_folio": "ARCO-OWASP-A08",
        },
        headers=auditor_headers,
    )
    assert erase.status_code == 201
    cert_id = erase.json()["certificate_id"]

    # Íntegro antes de alteración
    assert (
        client.get(
            f"/lifecycle/certificates/{cert_id}/verify", headers=auditor_headers
        ).json()["valid"]
        is True
    )

    # Alteración de un solo atributo -> detección inmediata
    cert_repo.tamper_certificate_for_test(UUID(cert_id), "vault_purged", False)
    assert (
        client.get(
            f"/lifecycle/certificates/{cert_id}/verify", headers=auditor_headers
        ).json()["valid"]
        is False
    )


def test_owasp_a09_logging_monitoring_and_safe_errors():
    """OWASP A09: Respuestas de error no deben filtrar secretos internos ni stack traces."""
    client, _, _, _, headers_for = _build_module_a_client()
    resp = client.get(
        "/clinical/records",
        headers=headers_for("medico", "proposito_ilegal"),
    )
    assert resp.status_code == 403
    body_text = json.dumps(resp.json()).lower()
    for sensitive_leak in ("traceback", "secret_key", "pepper", "vault_token", "postgresql://"):
        assert sensitive_leak not in body_text


def test_owasp_a10_ssrf_and_uri_manipulation():
    """OWASP A10: Bloqueo de intentos de SSRF / manipulación de URI mediante tokens opacos."""
    client, _, _, _, headers_for = _build_module_a_client()
    medico_headers = headers_for("medico", "atencion_medica")

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "https://attacker.invalid/steal",
        "pat_00000000000000000000000000000000@evil.com",
        "pat_00000000000000000000000000000000?extra=1",
    ]
    for candidate in ssrf_payloads:
        resp = client.post(
            "/clinical/records",
            json={
                "opaque_patient_token": candidate,
                "age_years": 30,
                "zip_prefix": "72000",
                "gender": "M",
                "diagnosis_cie10": "I10",
                "diagnosis_summary": "Prueba SSRF",
                "department": "cardiologia",
            },
            headers=medico_headers,
        )
        assert resp.status_code == 422, f"Payload SSRF no bloqueado: {candidate}"
