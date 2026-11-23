import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.audit.syslog_client import (
    SYSLOG_SEVERITY_NOTICE,
    SYSLOG_SEVERITY_WARNING,
    SyslogAuditClient,
)
from app.lifecycle.anonymization import (
    AnonymizationNotSatisfiableError,
    build_anonymized_export,
    render_anonymized_csv,
)
from app.lifecycle.certificates import (
    entity_to_summary,
    render_certificate_json_document,
    render_certificate_pdf,
    verify_certificate_integrity,
)
from app.lifecycle.nist_sanitization import (
    ARCOAlreadySanitizedError,
    ARCOErasureNotFoundError,
    NISTSanitizationService,
)
from app.lifecycle.ttl_worker import TTLSweepService
from app.models.auth import AuthenticatedUser
from app.models.lifecycle import (
    AnonymizedExportRequest,
    AnonymizedExportResponse,
    ARCOErasureRequest,
    ARCOErasureResponse,
    CertificateVerificationResponse,
    SanitizationCertificateSummary,
    TTLStatusResponse,
    TTLSweepResponse,
)
from app.models.vault import OPAQUE_TOKEN_REGEX
from app.policy.opa_client import OPAClient, OPAServiceError, OPAUnavailableError
from app.repositories.auth_repo import DatabaseUnavailableError
from app.repositories.certificate_repo import SanitizationCertificateRepository
from app.repositories.clinical_repo import ClinicalRecordRepository
from app.security.dependencies import (
    get_audit_client,
    get_certificate_repository,
    get_clinical_repository,
    get_current_user,
    get_declared_purpose,
    get_opa_client,
    get_ttl_sweep_service,
    get_vault_service,
    require_roles,
)
from app.vault.service import (
    InvalidOpaqueTokenError,
    VaultPIIVaultService,
    VaultServiceError,
    VaultTokenNotFoundError,
    VaultUnavailableError,
)

router = APIRouter(prefix="/lifecycle", tags=["ciclo-vida-modulo-b"])


def _handle_opa_error(exc: OPAServiceError) -> HTTPException:
    if isinstance(exc, OPAUnavailableError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


def _handle_vault_error(exc: VaultServiceError) -> HTTPException:
    if isinstance(exc, InvalidOpaqueTokenError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if isinstance(exc, VaultTokenNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, VaultUnavailableError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


def _authorize_with_opa(
    opa_client: OPAClient,
    *,
    actor: AuthenticatedUser,
    purpose: str,
    action: str,
    audit_client: SyslogAuditClient | None = None,
    request: Request | None = None,
) -> None:
    try:
        decision = opa_client.evaluate(
            role=actor.role,
            purpose=purpose,
            action=action,
        )
    except OPAServiceError as exc:
        raise _handle_opa_error(exc) from exc

    if not decision.allow:
        if audit_client is not None:
            audit_client.emit_event(
                msg_id="OPA_POLICY_DENIED",
                message=f"Denegación ABAC/OPA en ciclo de vida ({action}): {decision.reason}",
                severity=SYSLOG_SEVERITY_WARNING,
                actor=actor.username,
                role=actor.role,
                action=action,
                outcome="denied",
                purpose=purpose or "none",
                request=request,
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )


# ==============================================================================
# MB-01: Retención Temporal Automatizada (TTL)
# ==============================================================================
@router.get(
    "/ttl/status",
    response_model=TTLStatusResponse,
    summary="Consultar estado del planificador automático de retención TTL (MB-01)",
)
def get_ttl_status(
    _actor: AuthenticatedUser = Depends(require_roles("auditor_arco", "admin_sec")),
    ttl_service: TTLSweepService = Depends(get_ttl_sweep_service),
) -> TTLStatusResponse:
    return ttl_service.get_status()


@router.post(
    "/ttl/sweep",
    response_model=TTLSweepResponse,
    summary="Ejecutar barrido inmediato de registros y tokens con TTL expirado (MB-01)",
)
def trigger_ttl_sweep(
    request: Request,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    ttl_service: TTLSweepService = Depends(get_ttl_sweep_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> TTLSweepResponse:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="run_ttl_sweep",
        audit_client=audit_client,
        request=request,
    )
    try:
        result = ttl_service.run_sweep(triggered_by=f"{actor.role}:{actor.username}")
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    audit_client.emit_event(
        msg_id="LIFECYCLE_TTL_SWEEP",
        message=f"Barrido TTL completado (registros_purgados={result.purged_records_count})",
        severity=SYSLOG_SEVERITY_NOTICE,
        actor=actor.username,
        role=actor.role,
        action="run_ttl_sweep",
        outcome="success",
        purpose=purpose,
        records_count=result.purged_records_count,
        request=request,
    )
    return result


# ==============================================================================
# MB-02: Exportación Desidentificada (Safe Harbor + k-Anonimato + l-Diversidad)
# ==============================================================================
@router.post(
    "/exports/anonymized",
    response_model=AnonymizedExportResponse,
    summary="Exportar dataset estadístico Safe Harbor + k-anonimato + l-diversidad en JSON (MB-02)",
)
def export_anonymized_json(
    payload: AnonymizedExportRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> AnonymizedExportResponse:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="export_anonymized",
        audit_client=audit_client,
        request=request,
    )
    try:
        records = clinical_repo.list_records(
            department=payload.department,
            include_sanitized=False,
        )
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    try:
        result = build_anonymized_export(
            records,
            k=payload.k,
            l_diversity=payload.l_diversity,
            suppression_limit=payload.suppression_limit,
            purpose=purpose,
        )
    except AnonymizationNotSatisfiableError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    audit_client.emit_event(
        msg_id="LIFECYCLE_EXPORT",
        message=(
            f"Exportación Safe Harbor + (k={result.metrics.achieved_k},"
            f"l={result.metrics.achieved_l}) en JSON"
        ),
        actor=actor.username,
        role=actor.role,
        action="export_anonymized",
        outcome="success",
        purpose=purpose,
        records_count=result.metrics.exported_records_count,
        request=request,
    )
    return result


@router.get(
    "/exports/anonymized.csv",
    summary="Descargar dataset estadístico desidentificado (Safe Harbor + k,l) en CSV (MB-02)",
)
def export_anonymized_csv(
    request: Request,
    k: int = Query(default=2, ge=2, le=50),
    l_diversity: int = Query(default=2, ge=1, le=20, alias="l"),
    suppression_limit: float = Query(default=0.25, ge=0.0, le=0.5),
    department: str | None = Query(default=None, min_length=2, max_length=64),
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> Response:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="export_anonymized",
        audit_client=audit_client,
        request=request,
    )
    try:
        records = clinical_repo.list_records(
            department=department,
            include_sanitized=False,
        )
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    try:
        export_result = build_anonymized_export(
            records,
            k=k,
            l_diversity=l_diversity,
            suppression_limit=suppression_limit,
            purpose=purpose,
        )
    except AnonymizationNotSatisfiableError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    csv_body = render_anonymized_csv(export_result)
    audit_client.emit_event(
        msg_id="LIFECYCLE_EXPORT",
        message=(
            f"Exportación Safe Harbor + (k={export_result.metrics.achieved_k},"
            f"l={export_result.metrics.achieved_l}) en CSV"
        ),
        actor=actor.username,
        role=actor.role,
        action="export_anonymized",
        outcome="success",
        purpose=purpose,
        records_count=export_result.metrics.exported_records_count,
        request=request,
    )
    return Response(
        content=csv_body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="hospital_anonymized_safe_harbor.csv"',
            "X-Anonymization-Achieved-K": str(export_result.metrics.achieved_k),
            "X-Anonymization-Achieved-L": str(export_result.metrics.achieved_l),
            "X-Safe-Harbor-Verified": "true",
        },
    )


# ==============================================================================
# MB-03 & MB-04: Derechos ARCO + NIST SP 800-88 + Certificados JSON/PDF SHA-256
# ==============================================================================
@router.post(
    "/arco/erasure",
    response_model=ARCOErasureResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ejecutar Cancelación/Supresión ARCO con NIST SP 800-88 (Clear/Purge) y emitir certificado (MB-03/MB-04)",
)
def execute_arco_erasure(
    payload: ARCOErasureRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
    certificate_repo: SanitizationCertificateRepository = Depends(get_certificate_repository),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> ARCOErasureResponse:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="erase_nist_800_88",
        audit_client=audit_client,
        request=request,
    )

    service = NISTSanitizationService(
        clinical_repo=clinical_repo,
        vault_service=vault_service,
        certificate_repo=certificate_repo,
    )
    try:
        result = service.execute_arco_erasure(payload, actor=actor)
    except ARCOErasureNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ARCOAlreadySanitizedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    audit_client.emit_event(
        msg_id="LIFECYCLE_ARCO_ERASURE",
        message=f"Borrado certificado {payload.method} completado (cert={result.certificate_id})",
        severity=SYSLOG_SEVERITY_NOTICE,
        actor=actor.username,
        role=actor.role,
        action="erase_nist_800_88",
        outcome="success",
        purpose=purpose,
        resource=str(result.certificate_id),
        records_count=result.records_sanitized_count,
        request=request,
    )
    return result


@router.get(
    "/certificates",
    response_model=list[SanitizationCertificateSummary],
    summary="Listar certificados de sanitización NIST SP 800-88 emitidos (MB-04)",
)
def list_sanitization_certificates(
    opaque_patient_token: str | None = Query(default=None),
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    certificate_repo: SanitizationCertificateRepository = Depends(get_certificate_repository),
) -> list[SanitizationCertificateSummary]:
    _authorize_with_opa(opa_client, actor=actor, purpose=purpose, action="read_audit")
    if opaque_patient_token is not None:
        normalized = opaque_patient_token.strip()
        if not OPAQUE_TOKEN_REGEX.match(normalized):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token opaco inválido: debe cumplir el formato `pat_<32 caracteres hex>`.",
            )
        opaque_patient_token = normalized

    try:
        certs = certificate_repo.list_certificates(opaque_patient_token=opaque_patient_token)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return [entity_to_summary(item) for item in certs]


@router.get(
    "/certificates/{certificate_id}.json",
    summary="Descargar Certificado de Sanitización en formato JSON firmado con SHA-256 (MB-04)",
)
def download_certificate_json(
    certificate_id: UUID,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    certificate_repo: SanitizationCertificateRepository = Depends(get_certificate_repository),
) -> Response:
    _authorize_with_opa(opa_client, actor=actor, purpose=purpose, action="read_audit")
    try:
        entity = certificate_repo.get_certificate_by_id(certificate_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificado de sanitización no encontrado.",
        )

    document = render_certificate_json_document(entity)
    return Response(
        content=json.dumps(document, indent=2, ensure_ascii=False),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="sanitization-certificate-{certificate_id}.json"'
            ),
            "X-Certificate-SHA256": entity.sha256_hash,
        },
    )


@router.get(
    "/certificates/{certificate_id}.pdf",
    summary="Descargar Certificado de Sanitización en formato PDF con sello SHA-256 (MB-04)",
)
def download_certificate_pdf(
    certificate_id: UUID,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    certificate_repo: SanitizationCertificateRepository = Depends(get_certificate_repository),
) -> Response:
    _authorize_with_opa(opa_client, actor=actor, purpose=purpose, action="read_audit")
    try:
        entity = certificate_repo.get_certificate_by_id(certificate_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificado de sanitización no encontrado.",
        )

    pdf_bytes = render_certificate_pdf(entity)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="sanitization-certificate-{certificate_id}.pdf"'
            ),
            "X-Certificate-SHA256": entity.sha256_hash,
        },
    )


@router.get(
    "/certificates/{certificate_id}/verify",
    response_model=CertificateVerificationResponse,
    summary="Verificar integridad criptográfica SHA-256 de un Certificado de Sanitización (MB-04)",
)
def verify_certificate_sha256(
    certificate_id: UUID,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    certificate_repo: SanitizationCertificateRepository = Depends(get_certificate_repository),
) -> CertificateVerificationResponse:
    _authorize_with_opa(opa_client, actor=actor, purpose=purpose, action="read_audit")
    try:
        entity = certificate_repo.get_certificate_by_id(certificate_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificado de sanitización no encontrado.",
        )

    return verify_certificate_integrity(entity)
