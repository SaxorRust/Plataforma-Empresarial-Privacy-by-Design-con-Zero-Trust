from datetime import datetime, timezone
import json
from uuid import uuid4

from conftest import load_service_app
from fastapi.testclient import TestClient
import httpx
from test_vault_ma02 import FakeHashiCorpVaultTransport


class FakeOPATransport(httpx.BaseTransport):
    """
    Simulador HTTP fiel de Open Policy Agent (`infra/opa/policies/hospital_abac.rego`)
    para pruebas unitarias e integración aislada en CI sin requerir contenedor OPA.
    """

    def __init__(self, *, fail_mode: str | None = None) -> None:
        self.fail_mode = fail_mode

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.fail_mode == "connect_error":
            raise httpx.ConnectError("OPA unreachable (simulated)")
        if self.fail_mode == "server_error":
            return httpx.Response(500, json={"error": "internal opa error"})

        if request.method == "GET" and request.url.path == "/health":
            return httpx.Response(200, json={})

        if request.method == "POST" and request.url.path == "/v1/data/hospital/authz/decision":
            body = json.loads(request.content.decode("utf-8"))
            inp = body.get("input", {})
            return httpx.Response(200, json={"result": self._evaluate(inp)})

        return httpx.Response(404, json={"error": "not found"})

    @staticmethod
    def _evaluate(inp: dict) -> dict:
        role = str(inp.get("role", ""))
        purpose = str(inp.get("purpose", ""))
        action = str(inp.get("action", ""))
        resource_purpose = inp.get("resource_purpose")
        is_sanitized = bool(inp.get("is_sanitized", False))
        resource_owner_match = bool(inp.get("resource_owner_match", False))

        valid_role_purpose = (
            (
                role == "medico"
                and purpose == "atencion_medica"
                and action
                in {
                    "create_record",
                    "read_record",
                    "read_single_record",
                    "update_record",
                    "detokenize_pii",
                }
            )
            or (
                role == "enfermeria"
                and purpose == "atencion_medica"
                and action in {"read_record", "read_single_record"}
            )
            or (
                role == "analista"
                and purpose == "investigacion_estadistica"
                and action in {"read_record", "export_anonymized"}
            )
            or (
                role == "auditor_arco"
                and purpose == "ejercicio_arco"
                and action in {"read_record", "read_single_record", "read_audit", "erase_nist_800_88"}
            )
            or (
                role == "paciente"
                and purpose == "acceso_titular"
                and action in {"read_record", "read_single_record"}
                and resource_owner_match
            )
        )

        resource_purpose_compatible = (
            not resource_purpose
            or resource_purpose == purpose
            or (
                role == "analista"
                and purpose == "investigacion_estadistica"
                and resource_purpose in {"atencion_medica", "investigacion_estadistica"}
            )
            or (role == "auditor_arco" and purpose == "ejercicio_arco")
            or (
                role == "paciente"
                and purpose == "acceso_titular"
                and resource_purpose in {"atencion_medica", "investigacion_estadistica"}
            )
        )

        record_state_allowed = (not is_sanitized) or (
            role == "auditor_arco" and purpose == "ejercicio_arco"
        )
        allow = valid_role_purpose and resource_purpose_compatible and record_state_allowed

        allowed_fields: list[str] = []
        if allow and role == "medico" and purpose == "atencion_medica":
            allowed_fields = [
                "record_id",
                "opaque_patient_token",
                "age_years",
                "zip_prefix",
                "gender",
                "diagnosis_cie10",
                "diagnosis_summary",
                "department",
                "purpose_scope",
                "ttl_expires_at",
                "created_at",
            ]
        elif allow and role == "enfermeria" and purpose == "atencion_medica":
            allowed_fields = [
                "record_id",
                "opaque_patient_token",
                "department",
                "diagnosis_summary",
            ]
        elif allow and role == "analista" and purpose == "investigacion_estadistica":
            allowed_fields = [
                "age_range",
                "zip_generalized",
                "gender",
                "diagnosis_cie10",
                "department",
            ]
        elif allow and role == "auditor_arco" and purpose == "ejercicio_arco":
            allowed_fields = [
                "record_id",
                "opaque_patient_token",
                "purpose_scope",
                "is_sanitized",
                "ttl_expires_at",
                "created_at",
            ]
        elif allow and role == "paciente" and purpose == "acceso_titular":
            allowed_fields = [
                "record_id",
                "department",
                "diagnosis_summary",
                "purpose_scope",
                "ttl_expires_at",
                "created_at",
            ]

        generalize_fields = allow and role == "analista" and purpose == "investigacion_estadistica"
        mask_token = allow and role == "enfermeria" and purpose == "atencion_medica"

        if allow:
            reason = "Autorizado conforme a propósito declarado y política de minimización"
        elif not purpose:
            reason = (
                "Acceso denegado: propósito declarado ausente "
                "(X-Purpose obligatorio — prevención de function creep)"
            )
        elif is_sanitized and role != "auditor_arco":
            reason = (
                "Acceso denegado: registro sanitizado conforme a NIST SP 800-88 "
                "(solo visible para auditoría ARCO)"
            )
        elif role == "analista" and action == "read_single_record":
            reason = (
                "Acceso denegado: consulta individual prohibida para analista "
                "(prevención de singularización)"
            )
        elif role == "admin_sec":
            reason = (
                "Acceso denegado: separación de funciones Zero Trust "
                "(admin_sec no tiene acceso a diagnósticos clínicos)"
            )
        elif valid_role_purpose and not resource_purpose_compatible:
            reason = (
                "Acceso denegado: finalidad incompatible con el alcance de recolección "
                "del registro (prevención de function creep)"
            )
        else:
            reason = (
                "Acceso denegado: rol, acción o propósito declarado inválido "
                "(prevención de function creep)"
            )

        return {
            "allow": allow,
            "allowed_fields": allowed_fields,
            "generalize_fields": generalize_fields,
            "mask_token": mask_token,
            "reason": reason,
            "policy_version": "1.1.0",
        }


def _build_module_a_client(
    *, opa_fail_mode: str | None = None, fail_db_on_create: bool = False
):
    app = load_service_app("api")

    from app.models.auth import UserRecord
    from app.policy.opa_client import OPAClient
    from app.repositories.auth_repo import DatabaseUnavailableError
    from app.repositories.clinical_repo import InMemoryClinicalRecordRepository
    from app.security import dependencies
    from app.security.jwt_auth import JWTService, TokenRevocationStore
    from app.vault.service import VaultPIIVaultService

    vault_transport = FakeHashiCorpVaultTransport(expected_token="test_vault_token")
    vault_service = VaultPIIVaultService(
        vault_addr="http://vault.test:8200",
        vault_token="test_vault_token",
        transport=vault_transport,
    )
    opa_transport = FakeOPATransport(fail_mode=opa_fail_mode)
    opa_client = OPAClient(
        opa_url="http://opa.test:8181/v1/data/hospital/authz/decision",
        transport=opa_transport,
    )

    class _FailingClinicalRepo(InMemoryClinicalRecordRepository):
        def create_record(self, **kwargs):
            raise DatabaseUnavailableError("PostgreSQL no disponible (simulado)")

    repo = _FailingClinicalRepo() if fail_db_on_create else InMemoryClinicalRecordRepository()
    jwt_service = JWTService(
        secret_key="test_secret_module_a_32_bytes_key!",
        algorithm="HS256",
        expire_minutes=30,
        issuer="Hospital-Privacy-ZeroTrust",
        revocation_store=TokenRevocationStore(),
    )

    app.dependency_overrides[dependencies.get_vault_service] = lambda: vault_service
    app.dependency_overrides[dependencies.get_opa_client] = lambda: opa_client
    app.dependency_overrides[dependencies.get_clinical_repository] = lambda: repo
    app.dependency_overrides[dependencies.get_jwt_service] = lambda: jwt_service

    def issue_headers(role: str, purpose: str | None = None) -> dict[str, str]:
        user = UserRecord(
            id=uuid4(),
            username=f"{role}_user",
            role=role,  # type: ignore[arg-type]
            password_hash="unused",
            webauthn_enabled=False,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        token, _, _ = jwt_service.create_access_token(user, amr=["pwd"])
        headers = {"Authorization": f"Bearer {token}"}
        if purpose is not None:
            headers["X-Purpose"] = purpose
        return headers

    return TestClient(app), vault_transport, repo, opa_transport, issue_headers


def test_ma02_segregated_admission_isolates_pii_and_links_by_opaque_token():
    client, vault_transport, clinical_repo, _, headers_for = _build_module_a_client()

    payload = {
        "patient_pii": {
            "full_name": "Elena Guadalupe Ramos Ortiz",
            "curp": "RAOE890412MPLRNT07",
            "nss": "33445566778",
            "contact_email": "elena.ramos@example.org",
            "contact_phone": "+522221112233",
        },
        "clinical_data": {
            "age_years": 37,
            "zip_prefix": "72000",
            "gender": "F",
            "diagnosis_cie10": "e11.9",
            "diagnosis_summary": "Control ambulatorio de diabetes mellitus tipo 2",
            "department": "Endocrinologia",
            "purpose_scope": "atencion_medica",
            "ttl_hours": 720,
        },
    }

    resp = client.post(
        "/clinical/records/segregated",
        json=payload,
        headers=headers_for("medico", "atencion_medica"),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    opaque_token = body["opaque_patient_token"]
    record_id = body["record"]["record_id"]
    assert opaque_token.startswith("pat_")
    assert body["record"]["diagnosis_cie10"] == "E11.9"
    assert body["record"]["department"] == "endocrinologia"

    # 1) Bóveda KV v2 solo contiene ciphertext Transit, nunca PII en claro
    kv_dump = json.dumps(vault_transport.kv_store)
    assert "Elena Guadalupe" not in kv_dump
    assert "RAOE890412MPLRNT07" not in kv_dump
    assert "33445566778" not in kv_dump
    assert "vault:v1:" in kv_dump

    # 2) Base clínica solo contiene token opaco y atributos clínicos, cero PII directa
    stored_records = clinical_repo.list_records()
    assert len(stored_records) == 1
    assert stored_records[0].opaque_patient_token == opaque_token
    clinical_dump = repr(stored_records[0])
    assert "Elena Guadalupe" not in clinical_dump
    assert "RAOE890412MPLRNT07" not in clinical_dump
    assert "33445566778" not in clinical_dump

    # 3) Detokenización desde expediente protegida por OPA (médico + atencion_medica)
    detok_ok = client.get(
        f"/clinical/records/{record_id}/patient-identity",
        headers=headers_for("medico", "atencion_medica"),
    )
    assert detok_ok.status_code == 200
    assert detok_ok.json()["curp"] == "RAOE890412MPLRNT07"
    assert detok_ok.json()["nss"] == "33445566778"

    # 4) Function Creep / roles no autorizados bloqueados en detokenización
    assert (
        client.get(
            f"/clinical/records/{record_id}/patient-identity",
            headers=headers_for("medico", "marketing"),
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/clinical/records/{record_id}/patient-identity",
            headers=headers_for("enfermeria", "atencion_medica"),
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/clinical/records/{record_id}/patient-identity",
            headers=headers_for("analista", "investigacion_estadistica"),
        ).status_code
        == 403
    )


def test_ma02_blocks_direct_pii_in_clinical_payloads_and_compensates_on_db_failure():
    client, vault_transport, _, _, headers_for = _build_module_a_client()
    medico_headers = headers_for("medico", "atencion_medica")

    # 1) Token opaco inexistente en Vault -> 404
    fake_token = "pat_" + "a" * 32
    missing_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": fake_token,
            "age_years": 45,
            "zip_prefix": "72000",
            "gender": "M",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Hipertension arterial controlada",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert missing_resp.status_code == 404

    # 2) Rechazo de campos PII directos adicionales (extra="forbid") -> 422
    extra_pii_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": fake_token,
            "full_name": "Paciente No Permitido Aqui",
            "age_years": 45,
            "zip_prefix": "72000",
            "gender": "M",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Hipertension arterial",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert extra_pii_resp.status_code == 422

    # 3) Rechazo de CURP o NSS embebidos en texto libre clínico -> 422
    curp_leak_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": fake_token,
            "age_years": 45,
            "zip_prefix": "72000",
            "gender": "M",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Paciente con CURP PEMJ900115HPLRNS01 en observacion",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert curp_leak_resp.status_code == 422
    assert "CURP" in curp_leak_resp.text

    nss_leak_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": fake_token,
            "age_years": 45,
            "zip_prefix": "72000",
            "gender": "M",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Registro IMSS 11223344556 pendiente",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert nss_leak_resp.status_code == 422
    assert "NSS" in nss_leak_resp.text

    # 4) Flujo en dos pasos: tokenizar en /vault y luego vincular en /clinical/records
    tok_resp = client.post(
        "/vault/patients/tokenize",
        json={
            "full_name": "Carlos Alberto Diaz Vega",
            "curp": "DIVC850610HPLRNS04",
            "nss": "55667788990",
        },
        headers=medico_headers,
    )
    assert tok_resp.status_code == 201
    valid_token = tok_resp.json()["opaque_patient_token"]

    linked_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": valid_token,
            "age_years": 41,
            "zip_prefix": "72100",
            "gender": "M",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Control de presion arterial semestral",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert linked_resp.status_code == 201
    assert linked_resp.json()["record"]["opaque_patient_token"] == valid_token

    # 5) Compensación Zero Trust: si PostgreSQL falla, se purga el token recién creado en Vault
    failing_client, failing_vault, _, _, failing_headers = _build_module_a_client(
        fail_db_on_create=True
    )
    fail_resp = failing_client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": "Luis Fernando Soto",
                "curp": "SOLF910203HPLRNS02",
                "nss": "22334455667",
            },
            "clinical_data": {
                "age_years": 35,
                "zip_prefix": "72000",
                "gender": "M",
                "diagnosis_cie10": "J06.9",
                "diagnosis_summary": "Infeccion respiratoria aguda leve",
                "department": "urgencias",
            },
        },
        headers=failing_headers("medico", "atencion_medica"),
    )
    assert fail_resp.status_code == 503
    assert len(failing_vault.kv_store) == 0


def test_ma03_function_creep_prevention_and_fail_closed_opa():
    client, _, clinical_repo, _, headers_for = _build_module_a_client()

    # Crear expediente válido
    create_resp = client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": "Sofia Morales Herrera",
                "curp": "MOHS940822MPLRNS09",
                "nss": "99887766554",
            },
            "clinical_data": {
                "age_years": 32,
                "zip_prefix": "72500",
                "gender": "F",
                "diagnosis_cie10": "J45.9",
                "diagnosis_summary": "Seguimiento de asma leve persistente",
                "department": "neumologia",
            },
        },
        headers=headers_for("medico", "atencion_medica"),
    )
    assert create_resp.status_code == 201
    record_id = create_resp.json()["record"]["record_id"]
    opaque_token = create_resp.json()["opaque_patient_token"]

    # 1) Ausencia de X-Purpose -> 403 Forbidden
    no_purpose = client.get("/clinical/records", headers=headers_for("medico", None))
    assert no_purpose.status_code == 403
    assert "X-Purpose" in no_purpose.json()["detail"]

    # 2) Propósito no autorizado (marketing) -> 403 Forbidden
    marketing = client.get("/clinical/records", headers=headers_for("medico", "marketing"))
    assert marketing.status_code == 403
    assert "function creep" in marketing.json()["detail"].lower()

    # 3) Uso cruzado de propósito entre roles -> 403 Forbidden
    assert (
        client.get(
            "/clinical/records", headers=headers_for("medico", "investigacion_estadistica")
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/clinical/records", headers=headers_for("analista", "atencion_medica")
        ).status_code
        == 403
    )

    # 4) Separación de funciones: admin_sec NO puede leer expedientes clínicos
    admin_read = client.get("/clinical/records", headers=headers_for("admin_sec", "atencion_medica"))
    assert admin_read.status_code == 403
    assert "separación de funciones" in admin_read.json()["detail"].lower()

    # 5) Enfermería no puede modificar expedientes
    nurse_patch = client.patch(
        f"/clinical/records/{record_id}",
        json={"diagnosis_summary": "Intento no autorizado"},
        headers=headers_for("enfermeria", "atencion_medica"),
    )
    assert nurse_patch.status_code == 403

    # 6) Analista bloqueado contra singularización (lookup por ID o filtrado por token opaco)
    analyst_single = client.get(
        f"/clinical/records/{record_id}",
        headers=headers_for("analista", "investigacion_estadistica"),
    )
    assert analyst_single.status_code == 403
    assert "singularización" in analyst_single.json()["detail"].lower()

    analyst_by_token = client.get(
        f"/clinical/records?opaque_patient_token={opaque_token}",
        headers=headers_for("analista", "investigacion_estadistica"),
    )
    assert analyst_by_token.status_code == 403

    # 7) Registro sanitizado (NIST SP 800-88): bloqueado para médico, auditable por auditor_arco
    from uuid import UUID

    clinical_repo.mark_sanitized_for_test(UUID(record_id))
    assert (
        client.get(
            f"/clinical/records/{record_id}",
            headers=headers_for("medico", "atencion_medica"),
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/clinical/records/{record_id}",
            json={"diagnosis_summary": "Intento sobre registro sanitizado"},
            headers=headers_for("medico", "atencion_medica"),
        ).status_code
        == 409
    )
    auditor_view = client.get(
        f"/clinical/records/{record_id}",
        headers=headers_for("auditor_arco", "ejercicio_arco"),
    )
    assert auditor_view.status_code == 200
    assert auditor_view.json()["record"]["is_sanitized"] is True

    # 8) Fail-Closed: si OPA no responde o devuelve 500 -> 503 Service Unavailable (nunca autoriza)
    down_client, _, _, _, down_headers = _build_module_a_client(opa_fail_mode="connect_error")
    assert (
        down_client.get(
            "/clinical/records", headers=down_headers("medico", "atencion_medica")
        ).status_code
        == 503
    )

    err_client, _, _, _, err_headers = _build_module_a_client(opa_fail_mode="server_error")
    assert (
        err_client.get(
            "/clinical/records", headers=err_headers("medico", "atencion_medica")
        ).status_code
        == 503
    )


def test_ma04_quantitative_and_qualitative_minimization_by_role():
    client, _, _, _, headers_for = _build_module_a_client()
    medico_headers = headers_for("medico", "atencion_medica")

    # Insertar 2 pacientes (edad 34 + edad 93 para validar tope Safe Harbor "90+")
    r1 = client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": "Paciente Uno Prueba",
                "curp": "PUPA920110HPLRNS01",
                "nss": "10101010101",
            },
            "clinical_data": {
                "age_years": 34,
                "zip_prefix": "72000",
                "gender": "M",
                "diagnosis_cie10": "E11.9",
                "diagnosis_summary": "Diabetes tipo 2 sin complicaciones",
                "department": "medicina_interna",
            },
        },
        headers=medico_headers,
    )
    assert r1.status_code == 201
    token_1 = r1.json()["opaque_patient_token"]

    r2 = client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": "Paciente Mayor Noventa",
                "curp": "PMNO330515MPLRNS02",
                "nss": "20202020202",
            },
            "clinical_data": {
                "age_years": 93,
                "zip_prefix": "06600",
                "gender": "F",
                "diagnosis_cie10": "I10",
                "diagnosis_summary": "Hipertension esencial geriatrica",
                "department": "geriatria",
            },
        },
        headers=medico_headers,
    )
    assert r2.status_code == 201

    # 1) Médico: vista clínica completa (sin PII directa)
    med_resp = client.get("/clinical/records", headers=medico_headers)
    assert med_resp.status_code == 200
    med_body = med_resp.json()
    assert med_body["count"] == 2
    assert med_body["policy"]["generalized"] is False
    assert med_body["policy"]["masked_token"] is False
    med_keys = set(med_body["records"][0].keys())
    assert {
        "record_id",
        "opaque_patient_token",
        "age_years",
        "zip_prefix",
        "gender",
        "diagnosis_cie10",
        "diagnosis_summary",
        "department",
    }.issubset(med_keys)

    # 2) Enfermería: minimización cuantitativa + token opaco enmascarado
    nurse_resp = client.get(
        "/clinical/records", headers=headers_for("enfermeria", "atencion_medica")
    )
    assert nurse_resp.status_code == 200
    nurse_body = nurse_resp.json()
    assert nurse_body["policy"]["masked_token"] is True
    for rec in nurse_body["records"]:
        assert set(rec.keys()) == {
            "record_id",
            "opaque_patient_token",
            "department",
            "diagnosis_summary",
        }
        assert "..." in rec["opaque_patient_token"]
        assert rec["opaque_patient_token"] != token_1
        assert "diagnosis_cie10" not in rec
        assert "age_years" not in rec
        assert "zip_prefix" not in rec

    # 3) Analista: minimización cuantitativa (sin IDs/tokens/texto libre) + cualitativa (rangos/CP)
    analyst_resp = client.get(
        "/clinical/records",
        headers=headers_for("analista", "investigacion_estadistica"),
    )
    assert analyst_resp.status_code == 200
    analyst_body = analyst_resp.json()
    assert analyst_body["policy"]["generalized"] is True
    age_ranges = set()
    zips = set()
    for rec in analyst_body["records"]:
        assert set(rec.keys()) == {
            "age_range",
            "zip_generalized",
            "gender",
            "diagnosis_cie10",
            "department",
        }
        assert "record_id" not in rec
        assert "opaque_patient_token" not in rec
        assert "diagnosis_summary" not in rec
        assert "age_years" not in rec
        assert "zip_prefix" not in rec
        age_ranges.add(rec["age_range"])
        zips.add(rec["zip_generalized"])
    assert age_ranges == {"30-39", "90+"}
    assert zips == {"72***", "06***"}

    # 4) Auditor ARCO: únicamente metadatos de ciclo de vida, cero diagnósticos
    auditor_resp = client.get(
        "/clinical/records",
        headers=headers_for("auditor_arco", "ejercicio_arco"),
    )
    assert auditor_resp.status_code == 200
    for rec in auditor_resp.json()["records"]:
        assert set(rec.keys()) == {
            "record_id",
            "opaque_patient_token",
            "purpose_scope",
            "is_sanitized",
            "ttl_expires_at",
            "created_at",
        }
        assert "diagnosis_cie10" not in rec
        assert "diagnosis_summary" not in rec


def test_ma03_policy_status_and_evaluate_audit_endpoints():
    client, _, _, _, headers_for = _build_module_a_client()

    # Solo admin_sec y auditor_arco pueden consultar estado/simulación OPA
    assert (
        client.get("/clinical/policy/status", headers=headers_for("medico")).status_code == 403
    )

    status_resp = client.get(
        "/clinical/policy/status", headers=headers_for("auditor_arco")
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["reachable"] is True
    assert status_resp.json()["policy_loaded"] is True

    eval_resp = client.post(
        "/clinical/policy/evaluate",
        json={
            "role": "analista",
            "purpose": "marketing",
            "action": "read_record",
        },
        headers=headers_for("admin_sec"),
    )
    assert eval_resp.status_code == 200
    assert eval_resp.json()["allow"] is False
    assert eval_resp.json()["allowed_fields"] == []


def test_ma03_medico_update_record_happy_path_and_pii_guard():
    client, _, _, _, headers_for = _build_module_a_client()
    medico_headers = headers_for("medico", "atencion_medica")

    created = client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": "Jorge Luis Perez Ramirez",
                "curp": "PERJ880715HPLRNS05",
                "nss": "77889900112",
            },
            "clinical_data": {
                "age_years": 38,
                "zip_prefix": "72200",
                "gender": "M",
                "diagnosis_cie10": "J06.9",
                "diagnosis_summary": "Valoracion inicial respiratoria",
                "department": "urgencias",
            },
        },
        headers=medico_headers,
    )
    assert created.status_code == 201
    record_id = created.json()["record"]["record_id"]

    # Actualización válida por médico
    updated = client.patch(
        f"/clinical/records/{record_id}",
        json={
            "diagnosis_cie10": "j18.9",
            "diagnosis_summary": "Evolucion favorable tras tratamiento antibiotico",
            "department": "Neumologia",
        },
        headers=medico_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["record"]["diagnosis_cie10"] == "J18.9"
    assert updated.json()["record"]["department"] == "neumologia"

    # Actualización con PII embebida en texto libre bloqueada -> 422
    pii_patch = client.patch(
        f"/clinical/records/{record_id}",
        json={"diagnosis_summary": "Contacto correo paciente@hospital.org"},
        headers=medico_headers,
    )
    assert pii_patch.status_code == 422

