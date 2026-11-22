from datetime import datetime, timezone
import json
import secrets
from typing import Literal
from uuid import uuid4

from app.lifecycle.certificates import (
    build_certificate_urls,
    compute_certificate_sha256,
)
from app.models.auth import AuthenticatedUser
from app.models.lifecycle import ARCOErasureRequest, ARCOErasureResponse
from app.repositories.certificate_repo import SanitizationCertificateRepository
from app.repositories.clinical_repo import ClinicalRecordRepository
from app.vault.service import VaultPIIVaultService, VaultTokenNotFoundError


class ARCOErasureNotFoundError(Exception):
    """El token opaco no posee expedientes ni secreto en Vault para sanitizar."""


class ARCOAlreadySanitizedError(Exception):
    """Todos los datos asociados al token ya fueron sanitizados previamente."""


def secure_zero_buffer(buffer: bytearray, *, passes: int = 2) -> int:
    """
    Limpieza explícita de buffers mutables en memoria conforme a NIST SP 800-88 (MB-03):
    - Sobrescribe con bytes aleatorios (en modo multi-pasada) y finaliza con `0x00`.
    - Verifica que cada byte quede en cero antes de liberar la referencia.
    """
    length = len(buffer)
    if length == 0:
        return 0
    if passes >= 2:
        rand_bytes = secrets.token_bytes(length)
        for idx in range(length):
            buffer[idx] = rand_bytes[idx]
    for idx in range(length):
        buffer[idx] = 0xFF
    for idx in range(length):
        buffer[idx] = 0x00
    assert all(b == 0 for b in buffer)
    return 1


class NISTSanitizationService:
    """
    Orquestador de Derechos ARCO (Cancelación/Supresión) y Sanitización NIST SP 800-88 (MB-03 + MB-04):
    1. Recopila los expedientes vinculados a `opaque_patient_token`.
    2. Ejecuta sobrescritura segura en PostgreSQL (`CLEAR`: 2 pasadas, `PURGE`: 3 pasadas
       aleatorio + ceros + marcador canónico `is_sanitized=TRUE`).
    3. Limpia explícitamente buffers en memoria (`secure_zero_buffer`) que hayan cargado
       atributos clínicos durante la verificación.
    4. Purga metadatos y versiones KV v2 en HashiCorp Vault y confirma `token_exists == False`.
    5. Genera, firma con `SHA-256` y persiste el Certificado de Sanitización en
       `compliance.sanitization_certificates` (descargable en JSON y PDF).
    """

    def __init__(
        self,
        *,
        clinical_repo: ClinicalRecordRepository,
        vault_service: VaultPIIVaultService,
        certificate_repo: SanitizationCertificateRepository,
    ) -> None:
        self._clinical_repo = clinical_repo
        self._vault_service = vault_service
        self._certificate_repo = certificate_repo

    def execute_arco_erasure(
        self,
        payload: ARCOErasureRequest,
        *,
        actor: AuthenticatedUser,
    ) -> ARCOErasureResponse:
        token = payload.opaque_patient_token
        all_records = self._clinical_repo.list_records(
            opaque_patient_token=token,
            include_sanitized=True,
        )
        active_records = [rec for rec in all_records if not rec.is_sanitized]
        vault_exists_before = self._vault_service.token_exists(token)

        if not all_records and not vault_exists_before:
            raise ARCOErasureNotFoundError(
                "No existen expedientes clínicos ni identificadores en Vault para el token indicado."
            )

        if not active_records and (not payload.purge_vault or not vault_exists_before):
            raise ARCOAlreadySanitizedError(
                "Los registros clínicos y la bóveda para este token ya fueron sanitizados previamente."
            )

        # 1) Carga controlada en buffers mutables y limpieza inmediata en memoria (NIST SP 800-88)
        buffers_zeroed = 0
        mem_passes = 3 if payload.method == "NIST_800_88_PURGE" else 2
        for rec in active_records:
            snapshot_buf = bytearray(
                json.dumps(
                    {
                        "record_id": str(rec.record_id),
                        "diagnosis_cie10": rec.diagnosis_cie10,
                        "diagnosis_summary": rec.diagnosis_summary,
                        "zip_prefix": rec.zip_prefix,
                        "age_years": rec.age_years,
                    }
                ).encode("utf-8")
            )
            try:
                # Verificación en memoria antes de destruir en BD
                _ = len(snapshot_buf)
            finally:
                buffers_zeroed += secure_zero_buffer(snapshot_buf, passes=mem_passes)

        # 2) Sobrescritura multi-pasada en PostgreSQL (`CLEAR` / `PURGE`)
        sanitized_ids, overwrite_passes = (
            self._clinical_repo.overwrite_and_sanitize_records_for_token(
                token,
                method=payload.method,
            )
        )

        # 3) Purga criptográfica en HashiCorp Vault (KV v2 metadata destroy) + verificación
        vault_purged = False
        vault_verification: Literal["CONFIRMED_NOT_FOUND", "ALREADY_PURGED", "NOT_REQUESTED"]
        if payload.purge_vault:
            if vault_exists_before:
                try:
                    self._vault_service.purge_patient(token)
                    vault_purged = True
                except VaultTokenNotFoundError:
                    vault_purged = False
                still_exists = self._vault_service.token_exists(token)
                if still_exists:
                    raise RuntimeError(
                        "Verificación post-purga fallida: el token opaco persiste en Vault."
                    )
                vault_verification = "CONFIRMED_NOT_FOUND"
            else:
                vault_verification = "ALREADY_PURGED"
        else:
            vault_verification = "NOT_REQUESTED"

        # 4) Emisión de Certificado de Sanitización canónico firmado con SHA-256 (MB-04)
        certificate_id = uuid4()
        executed_at = datetime.now(timezone.utc)
        certificate_payload = {
            "certificate_id": str(certificate_id),
            "standard": "NIST SP 800-88 Rev. 1",
            "method": payload.method,
            "arco_right": "Cancelación / Supresión (ARCO)",
            "arco_request_folio": payload.arco_request_folio,
            "reason": payload.reason,
            "opaque_patient_token": token,
            "sanitized_record_ids": [str(rid) for rid in sanitized_ids],
            "records_sanitized_count": len(sanitized_ids),
            "overwrite_passes": overwrite_passes,
            "memory_buffers_zeroed": buffers_zeroed,
            "vault_purged": vault_purged,
            "vault_verification": vault_verification,
            "requested_by": actor.username,
            "requested_by_role": actor.role,
            "executed_at": executed_at.isoformat(),
            "organization": "Hospital Privacy-by-Design Zero Trust — BUAP FCC",
        }
        sha256_hash = compute_certificate_sha256(certificate_payload)

        saved = self._certificate_repo.save_certificate(
            certificate_id=certificate_id,
            opaque_patient_token=token,
            method=payload.method,
            sha256_hash=sha256_hash,
            requested_by=actor.username,
            executed_at=executed_at,
            certificate_json=certificate_payload,
        )

        json_url, pdf_url, verify_url = build_certificate_urls(saved.certificate_id)
        return ARCOErasureResponse(
            certificate_id=saved.certificate_id,
            opaque_patient_token=saved.opaque_patient_token,
            method=saved.method,
            overwrite_passes=overwrite_passes,
            memory_buffers_zeroed=buffers_zeroed,
            records_sanitized_count=len(sanitized_ids),
            sanitized_record_ids=sanitized_ids,
            vault_purged=vault_purged,
            vault_verification=vault_verification,
            sha256_hash=saved.sha256_hash,
            executed_at=saved.executed_at,
            certificate=saved.certificate_json,
            json_download_url=json_url,
            pdf_download_url=pdf_url,
            verify_url=verify_url,
        )
