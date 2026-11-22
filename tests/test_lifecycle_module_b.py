from collections import defaultdict
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import time
from uuid import UUID, uuid4

from conftest import load_service_app
from fastapi.testclient import TestClient
from test_privacy_module_a import FakeOPATransport
from test_vault_ma02 import FakeHashiCorpVaultTransport


def _build_module_b_app(*, ttl_enabled: bool = False, ttl_interval_seconds: int = 5):
    app = load_service_app("api")

    from app.lifecycle.ttl_worker import TTLSweepService
    from app.models.auth import UserRecord
    from app.policy.opa_client import OPAClient
    from app.repositories.certificate_repo import InMemorySanitizationCertificateRepository
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
    opa_client = OPAClient(
        opa_url="http://opa.test:8181/v1/data/hospital/authz/decision",
        transport=FakeOPATransport(),
    )
    clinical_repo = InMemoryClinicalRecordRepository()
    cert_repo = InMemorySanitizationCertificateRepository()
    ttl_service = TTLSweepService(
        clinical_repo=clinical_repo,
        vault_service=vault_service,
        enabled=ttl_enabled,
        interval_seconds=ttl_interval_seconds,
    )
    jwt_service = JWTService(
        secret_key="test_secret_module_b_32_bytes_key!",
        algorithm="HS256",
        expire_minutes=30,
        issuer="Hospital-Privacy-ZeroTrust",
        revocation_store=TokenRevocationStore(),
    )

    app.dependency_overrides[dependencies.get_vault_service] = lambda: vault_service
    app.dependency_overrides[dependencies.get_opa_client] = lambda: opa_client
    app.dependency_overrides[dependencies.get_clinical_repository] = lambda: clinical_repo
    app.dependency_overrides[dependencies.get_certificate_repository] = lambda: cert_repo
    app.dependency_overrides[dependencies.get_ttl_sweep_service] = lambda: ttl_service
    app.dependency_overrides[dependencies.get_jwt_service] = lambda: jwt_service

    def headers_for(role: str, purpose: str | None = None) -> dict[str, str]:
        user = UserRecord(
            id=uuid4(),
            username=f"{role}_modb",
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

    return app, vault_service, clinical_repo, cert_repo, ttl_service, headers_for


def _admit_patient(
    client: TestClient,
    medico_headers: dict[str, str],
    *,
    full_name: str,
    curp: str,
    nss: str,
    age_years: int,
    zip_prefix: str,
    gender: str,
    diagnosis_cie10: str,
    department: str = "medicina_interna",
    ttl_expires_at: datetime | None = None,
) -> tuple[str, str]:
    clinical_data: dict = {
        "age_years": age_years,
        "zip_prefix": zip_prefix,
        "gender": gender,
        "diagnosis_cie10": diagnosis_cie10,
        "diagnosis_summary": f"Control clinico {diagnosis_cie10}",
        "department": department,
    }
    if ttl_expires_at is not None:
        clinical_data["ttl_expires_at"] = ttl_expires_at.isoformat()

    resp = client.post(
        "/clinical/records/segregated",
        json={
            "patient_pii": {
                "full_name": full_name,
                "curp": curp,
                "nss": nss,
            },
            "clinical_data": clinical_data,
        },
        headers=medico_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["opaque_patient_token"], body["record"]["record_id"]


def test_mb01_ttl_sweep_purges_expired_records_and_orphan_vault_tokens_only():
    app, vault_service, clinical_repo, _, _, headers_for = _build_module_b_app()
    client = TestClient(app)
    medico_headers = headers_for("medico", "atencion_medica")

    past = datetime.now(timezone.utc) - timedelta(hours=2)
    future = datetime.now(timezone.utc) + timedelta(hours=24)

    # Paciente A: 1 solo registro ya expirado -> se purga registro Y token en Vault
    tok_a, rec_a = _admit_patient(
        client,
        medico_headers,
        full_name="Paciente Expirado Uno",
        curp="PEUN900101HPLRNS01",
        nss="11111111111",
        age_years=36,
        zip_prefix="72000",
        gender="M",
        diagnosis_cie10="J06.9",
        ttl_expires_at=past,
    )

    # Paciente B: 1 registro expirado + 1 registro vigente -> se purga solo el expirado, Vault conserva token
    tok_b, rec_b_expired = _admit_patient(
        client,
        medico_headers,
        full_name="Paciente Mixto Dos",
        curp="PMDO880202MPLRNS02",
        nss="22222222222",
        age_years=38,
        zip_prefix="72100",
        gender="F",
        diagnosis_cie10="I10",
        ttl_expires_at=past,
    )
    rec_b_active_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": tok_b,
            "age_years": 38,
            "zip_prefix": "72100",
            "gender": "F",
            "diagnosis_cie10": "E11.9",
            "diagnosis_summary": "Seguimiento vigente",
            "department": "medicina_interna",
            "ttl_expires_at": future.isoformat(),
        },
        headers=medico_headers,
    )
    assert rec_b_active_resp.status_code == 201
    rec_b_active = rec_b_active_resp.json()["record"]["record_id"]

    # Paciente C: sin TTL -> permanece intacto
    tok_c, rec_c = _admit_patient(
        client,
        medico_headers,
        full_name="Paciente Permanente Tres",
        curp="PPTR750303HPLRNS03",
        nss="33333333333",
        age_years=51,
        zip_prefix="72200",
        gender="M",
        diagnosis_cie10="K21.9",
    )

    # OPA bloquea roles/propósitos inválidos
    assert (
        client.post("/lifecycle/ttl/sweep", headers=headers_for("medico", "atencion_medica")).status_code
        == 403
    )
    assert (
        client.post("/lifecycle/ttl/sweep", headers=headers_for("auditor_arco", "marketing")).status_code
        == 403
    )

    # Barrido autorizado por auditor_arco (ejercicio_arco)
    sweep_resp = client.post(
        "/lifecycle/ttl/sweep",
        headers=headers_for("auditor_arco", "ejercicio_arco"),
    )
    assert sweep_resp.status_code == 200, sweep_resp.text
    sweep = sweep_resp.json()
    assert sweep["purged_records_count"] == 2
    assert set(sweep["purged_record_ids"]) == {rec_a, rec_b_expired}
    assert sweep["purged_vault_tokens"] == [tok_a]
    assert sweep["skipped_vault_tokens_with_active_records"] == [tok_b]

    # Verificar estado en BD y Vault
    assert clinical_repo.get_record_by_id(UUID(rec_a)) is None
    assert clinical_repo.get_record_by_id(UUID(rec_b_expired)) is None
    assert clinical_repo.get_record_by_id(UUID(rec_b_active)) is not None
    assert clinical_repo.get_record_by_id(UUID(rec_c)) is not None

    assert vault_service.token_exists(tok_a) is False
    assert vault_service.token_exists(tok_b) is True
    assert vault_service.token_exists(tok_c) is True

    # admin_sec también puede ejecutar mantenimiento TTL sin ver diagnósticos
    admin_sweep = client.post(
        "/lifecycle/ttl/sweep",
        headers=headers_for("admin_sec", "mantenimiento_ttl"),
    )
    assert admin_sweep.status_code == 200
    assert admin_sweep.json()["purged_records_count"] == 0


def test_mb01_background_ttl_scheduler_runs_automatically_on_lifespan():
    app, vault_service, clinical_repo, _, _, headers_for = _build_module_b_app(
        ttl_enabled=True, ttl_interval_seconds=5
    )

    # Insertar registro vencido directamente antes de arrancar el lifespan
    from app.models.vault import PatientPIIRequest

    tok = vault_service.tokenize_patient(
        PatientPIIRequest(
            full_name="Paciente Scheduler Auto",
            curp="PSAU910505HPLRNS05",
            nss="55555555555",
        )
    ).opaque_patient_token
    expired_rec = clinical_repo.create_record(
        opaque_patient_token=tok,
        age_years=35,
        zip_prefix="72000",
        gender="M",
        diagnosis_cie10="J06.9",
        diagnosis_summary="Registro temporal vencido",
        department="urgencias",
        ttl_expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )

    with TestClient(app) as client:
        # Esperar brevemente a que corra el primer ciclo del scheduler automático
        deadline = time.time() + 3.0
        status_body = None
        while time.time() < deadline:
            resp = client.get(
                "/lifecycle/ttl/status",
                headers=headers_for("auditor_arco"),
            )
            assert resp.status_code == 200
            status_body = resp.json()
            if status_body["total_sweeps"] >= 1:
                break
            time.sleep(0.05)

        assert status_body is not None
        assert status_body["enabled"] is True
        assert status_body["scheduler_running"] is True
        assert status_body["total_sweeps"] >= 1
        assert status_body["total_records_purged"] == 1
        assert status_body["total_vault_tokens_purged"] == 1
        assert clinical_repo.get_record_by_id(expired_rec.record_id) is None
        assert vault_service.token_exists(tok) is False


def test_mb02_safe_harbor_k_anonymity_and_l_diversity_json_and_csv():
    app, _, _, _, _, headers_for = _build_module_b_app()
    client = TestClient(app)
    medico_headers = headers_for("medico", "atencion_medica")
    analista_headers = headers_for("analista", "investigacion_estadistica")

    # Sembrar 6 expedientes en 2 cohortes (30-39 y 90+) con al menos 2 diagnósticos distintos por cohorte
    cohort = [
        ("Paciente Uno A", "PUAA950101HPLRNS01", "10000000001", 31, "72000", "M", "E11.9"),
        ("Paciente Dos A", "PDAA920202HPLRNS02", "10000000002", 34, "72010", "M", "I10"),
        ("Paciente Tres A", "PTAA880303HPLRNS03", "10000000003", 38, "72020", "M", "J45.9"),
        ("Paciente Cuatro B", "PCBB340404MPLRNS04", "10000000004", 92, "06600", "F", "I10"),
        ("Paciente Cinco B", "PCBB310505MPLRNS05", "10000000005", 95, "06610", "F", "E11.9"),
        ("Paciente Seis B", "PSBB290606MPLRNS06", "10000000006", 97, "06620", "F", "K21.9"),
    ]
    tokens_created = []
    for name, curp, nss, age, zip_code, gender, cie10 in cohort:
        tok, _ = _admit_patient(
            client,
            medico_headers,
            full_name=name,
            curp=curp,
            nss=nss,
            age_years=age,
            zip_prefix=zip_code,
            gender=gender,
            diagnosis_cie10=cie10,
        )
        tokens_created.append(tok)

    # Control OPA: solo analista con investigacion_estadistica puede exportar
    assert (
        client.post(
            "/lifecycle/exports/anonymized",
            json={"k": 3, "l": 2},
            headers=medico_headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/lifecycle/exports/anonymized",
            json={"k": 3, "l": 2},
            headers=headers_for("analista", "atencion_medica"),
        ).status_code
        == 403
    )

    # Exportación JSON con k=3, l=2
    export_resp = client.post(
        "/lifecycle/exports/anonymized",
        json={"k": 3, "l": 2, "suppression_limit": 0.25},
        headers=analista_headers,
    )
    assert export_resp.status_code == 200, export_resp.text
    body = export_resp.json()
    metrics = body["metrics"]
    assert metrics["achieved_k"] >= 3
    assert metrics["achieved_l"] >= 2
    assert metrics["safe_harbor_verified"] is True
    assert metrics["removed_hipaa_identifiers_count"] == 18
    assert metrics["exported_records_count"] == 6
    assert metrics["suppressed_records_count"] == 0

    # Verificar ausencia total de PII directa y tokens opacos en el JSON exportado
    raw_dump = json.dumps(body)
    assert "pat_" not in raw_dump
    assert "PUAA950101HPLRNS01" not in raw_dump
    assert "Paciente Uno" not in raw_dump
    assert "72000" not in raw_dump
    assert "06600" not in raw_dump

    # Verificar matemáticamente cada clase de equivalencia (k >= 3, l >= 2) y tope Safe Harbor "90+"
    groups = defaultdict(list)
    age_ranges = set()
    for row in body["records"]:
        assert set(row.keys()) == {
            "age_range",
            "zip_generalized",
            "gender",
            "diagnosis_cie10",
            "department",
            "record_year",
        }
        age_ranges.add(row["age_range"])
        groups[(row["age_range"], row["zip_generalized"], row["gender"])].append(
            row["diagnosis_cie10"]
        )
    assert "90+" in age_ranges
    for diags in groups.values():
        assert len(diags) >= 3
        assert len(set(diags)) >= 2

    # Exportación CSV
    csv_resp = client.get(
        "/lifecycle/exports/anonymized.csv?k=3&l=2",
        headers=analista_headers,
    )
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert csv_resp.headers["x-safe-harbor-verified"] == "true"
    assert int(csv_resp.headers["x-anonymization-achieved-k"]) >= 3
    assert int(csv_resp.headers["x-anonymization-achieved-l"]) >= 2

    parsed_csv = list(csv.DictReader(io.StringIO(csv_resp.text)))
    assert len(parsed_csv) == 6
    assert "pat_" not in csv_resp.text

    # Fail-Closed: parámetros (k, l) imposibles -> 422 (nunca exporta dataset inseguro)
    impossible_k = client.post(
        "/lifecycle/exports/anonymized",
        json={"k": 10, "l": 2},
        headers=analista_headers,
    )
    assert impossible_k.status_code == 422

    impossible_l = client.post(
        "/lifecycle/exports/anonymized",
        json={"k": 2, "l": 10},
        headers=analista_headers,
    )
    assert impossible_l.status_code == 422


def test_mb03_and_mb04_arco_nist_purge_clear_memory_zeroing_json_pdf_and_sha256():
    app, vault_service, clinical_repo, cert_repo, _, headers_for = _build_module_b_app()
    client = TestClient(app)
    medico_headers = headers_for("medico", "atencion_medica")
    auditor_headers = headers_for("auditor_arco", "ejercicio_arco")

    # Unit test directo de limpieza de buffers en memoria (NIST SP 800-88)
    from app.lifecycle.nist_sanitization import secure_zero_buffer

    secret_buf = bytearray(b"SENSITIVE_DIAGNOSIS_DATA_CURP_SECRET")
    assert secure_zero_buffer(secret_buf, passes=3) == 1
    assert all(b == 0 for b in secret_buf)

    # Paciente 1 con 2 expedientes clínicos -> NIST_800_88_PURGE
    tok_1, rec_1a = _admit_patient(
        client,
        medico_headers,
        full_name="Maria Fernanda Castro Luna",
        curp="CALM910718MPLRNS08",
        nss="88776655443",
        age_years=35,
        zip_prefix="72000",
        gender="F",
        diagnosis_cie10="E11.9",
        department="endocrinologia",
    )
    rec_1b_resp = client.post(
        "/clinical/records",
        json={
            "opaque_patient_token": tok_1,
            "age_years": 35,
            "zip_prefix": "72000",
            "gender": "F",
            "diagnosis_cie10": "I10",
            "diagnosis_summary": "Evaluacion cardiologica complementaria",
            "department": "cardiologia",
        },
        headers=medico_headers,
    )
    assert rec_1b_resp.status_code == 201
    rec_1b = rec_1b_resp.json()["record"]["record_id"]

    # Médico no autorizado para ejecutar borrado ARCO -> 403
    assert (
        client.post(
            "/lifecycle/arco/erasure",
            json={
                "opaque_patient_token": tok_1,
                "method": "NIST_800_88_PURGE",
                "arco_request_folio": "ARCO-2026-UNAUTH",
            },
            headers=medico_headers,
        ).status_code
        == 403
    )

    # Ejecución ARCO + NIST SP 800-88 PURGE por auditor_arco
    erasure_resp = client.post(
        "/lifecycle/arco/erasure",
        json={
            "opaque_patient_token": tok_1,
            "method": "NIST_800_88_PURGE",
            "arco_request_folio": "ARCO-2026-0001",
            "reason": "Solicitud de cancelacion definitiva del titular (LFPDPPP)",
            "purge_vault": True,
        },
        headers=auditor_headers,
    )
    assert erasure_resp.status_code == 201, erasure_resp.text
    erasure = erasure_resp.json()
    cert_id = erasure["certificate_id"]
    sha256_hash = erasure["sha256_hash"]

    assert erasure["method"] == "NIST_800_88_PURGE"
    assert erasure["overwrite_passes"] == 3
    assert erasure["memory_buffers_zeroed"] == 2
    assert erasure["records_sanitized_count"] == 2
    assert set(erasure["sanitized_record_ids"]) == {rec_1a, rec_1b}
    assert erasure["vault_purged"] is True
    assert erasure["vault_verification"] == "CONFIRMED_NOT_FOUND"
    assert len(sha256_hash) == 64

    # Verificar borrado irreversible en BD y bóveda Vault
    for rid in (rec_1a, rec_1b):
        rec = clinical_repo.get_record_by_id(UUID(rid))
        assert rec is not None
        assert rec.is_sanitized is True
        assert rec.age_years == 0
        assert rec.zip_prefix == "00000"
        assert rec.diagnosis_cie10 == "PURGED"
        assert "NIST SP 800-88 PURGE" in rec.diagnosis_summary
        assert "E11.9" not in rec.diagnosis_summary
        assert "cardiologica" not in rec.diagnosis_summary

    assert vault_service.token_exists(tok_1) is False
    assert (
        client.get(f"/vault/patients/{tok_1}", headers=medico_headers).status_code == 404
    )

    # Re-ejecutar borrado sobre token ya sanitizado -> 409 Conflict
    dup_resp = client.post(
        "/lifecycle/arco/erasure",
        json={
            "opaque_patient_token": tok_1,
            "method": "NIST_800_88_PURGE",
            "arco_request_folio": "ARCO-2026-0001-DUP",
        },
        headers=auditor_headers,
    )
    assert dup_resp.status_code == 409

    # MB-04: Descarga JSON + verificación independiente SHA-256 + cero PII directa
    json_resp = client.get(f"/lifecycle/certificates/{cert_id}.json", headers=auditor_headers)
    assert json_resp.status_code == 200
    assert json_resp.headers["x-certificate-sha256"] == sha256_hash
    cert_doc = json_resp.json()
    canonical = json.dumps(
        cert_doc["certificate"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == sha256_hash
    assert "Maria Fernanda" not in json_resp.text
    assert "CALM910718MPLRNS08" not in json_resp.text
    assert "88776655443" not in json_resp.text

    # MB-04: Descarga PDF generado con ReportLab + cabecera SHA-256
    pdf_resp = client.get(f"/lifecycle/certificates/{cert_id}.pdf", headers=auditor_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.headers["x-certificate-sha256"] == sha256_hash
    assert pdf_resp.content.startswith(b"%PDF-")
    assert len(pdf_resp.content) > 1500

    # MB-04: Endpoint /verify positivo y detección de alteración (tampering)
    verify_ok = client.get(f"/lifecycle/certificates/{cert_id}/verify", headers=auditor_headers)
    assert verify_ok.status_code == 200
    assert verify_ok.json()["valid"] is True
    assert verify_ok.json()["stored_sha256"] == verify_ok.json()["recomputed_sha256"]

    cert_repo.tamper_certificate_for_test(UUID(cert_id), "records_sanitized_count", 999)
    verify_tampered = client.get(
        f"/lifecycle/certificates/{cert_id}/verify", headers=auditor_headers
    )
    assert verify_tampered.status_code == 200
    assert verify_tampered.json()["valid"] is False
    assert verify_tampered.json()["stored_sha256"] != verify_tampered.json()["recomputed_sha256"]

    # Listado de certificados
    list_resp = client.get("/lifecycle/certificates", headers=auditor_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["certificate_id"] == cert_id

    # Paciente 2: prueba de método NIST_800_88_CLEAR (2 pasadas)
    tok_2, rec_2 = _admit_patient(
        client,
        medico_headers,
        full_name="Roberto Gomez Silva",
        curp="GOSR850101HPLRNS01",
        nss="44556677889",
        age_years=41,
        zip_prefix="72300",
        gender="M",
        diagnosis_cie10="J06.9",
    )
    clear_resp = client.post(
        "/lifecycle/arco/erasure",
        json={
            "opaque_patient_token": tok_2,
            "method": "NIST_800_88_CLEAR",
            "arco_request_folio": "ARCO-2026-0002",
        },
        headers=auditor_headers,
    )
    assert clear_resp.status_code == 201
    assert clear_resp.json()["overwrite_passes"] == 2
    rec_2_after = clinical_repo.get_record_by_id(UUID(rec_2))
    assert rec_2_after is not None and rec_2_after.diagnosis_cie10 == "SANITIZED"
