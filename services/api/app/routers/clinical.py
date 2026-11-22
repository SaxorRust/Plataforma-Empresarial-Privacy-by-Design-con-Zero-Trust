from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.models.auth import AuthenticatedUser
from app.models.clinical import (
    MedicalRecordCreateRequest,
    MedicalRecordUpdateRequest,
    MinimizationMetadata,
    MinimizedRecordListResponse,
    MinimizedRecordResponse,
    OPADecision,
    OPAStatusResponse,
    PolicyEvaluateRequest,
    SegregatedCreateResponse,
    SegregatedPatientRecordCreateRequest,
)
from app.models.vault import OPAQUE_TOKEN_REGEX, DetokenizePatientResponse
from app.policy.minimization import apply_minimization
from app.policy.opa_client import OPAClient, OPAServiceError, OPAUnavailableError
from app.repositories.auth_repo import DatabaseUnavailableError
from app.repositories.clinical_repo import ClinicalRecordRepository
from app.security.dependencies import (
    get_clinical_repository,
    get_current_user,
    get_declared_purpose,
    get_opa_client,
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

router = APIRouter(prefix="/clinical", tags=["clinica-abac-ma02-ma03-ma04"])


def _handle_vault_error(exc: VaultServiceError) -> HTTPException:
    if isinstance(exc, InvalidOpaqueTokenError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if isinstance(exc, VaultTokenNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, VaultUnavailableError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


def _handle_opa_error(exc: OPAServiceError) -> HTTPException:
    if isinstance(exc, OPAUnavailableError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


def _authorize_with_opa(
    opa_client: OPAClient,
    *,
    actor: AuthenticatedUser,
    purpose: str,
    action: str,
    resource_purpose: str | None = None,
    is_sanitized: bool = False,
    resource_owner_match: bool = False,
) -> OPADecision:
    try:
        decision = opa_client.evaluate(
            role=actor.role,
            purpose=purpose,
            action=action,
            resource_purpose=resource_purpose,
            is_sanitized=is_sanitized,
            resource_owner_match=resource_owner_match,
        )
    except OPAServiceError as exc:
        raise _handle_opa_error(exc) from exc

    if not decision.allow:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )
    return decision


def _build_policy_metadata(
    *,
    actor: AuthenticatedUser,
    purpose: str,
    action: str,
    decision: OPADecision,
) -> MinimizationMetadata:
    return MinimizationMetadata(
        role=actor.role,
        purpose=purpose,
        action=action,
        allowed_fields=decision.allowed_fields,
        generalized=decision.generalize_fields,
        masked_token=decision.mask_token,
        policy_version=decision.policy_version,
    )


@router.post(
    "/records/segregated",
    response_model=SegregatedCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Alta segregada MA-02: aísla PII en Vault y persiste atributos clínicos en PostgreSQL",
)
def create_segregated_patient_record(
    payload: SegregatedPatientRecordCreateRequest,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> SegregatedCreateResponse:
    decision = _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="create_record",
        resource_purpose=payload.clinical_data.purpose_scope,
    )

    try:
        tokenized = vault_service.tokenize_patient(payload.patient_pii)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc

    try:
        record = clinical_repo.create_record(
            opaque_patient_token=tokenized.opaque_patient_token,
            age_years=payload.clinical_data.age_years,
            zip_prefix=payload.clinical_data.zip_prefix,
            gender=payload.clinical_data.gender,
            diagnosis_cie10=payload.clinical_data.diagnosis_cie10,
            diagnosis_summary=payload.clinical_data.diagnosis_summary,
            department=payload.clinical_data.department,
            purpose_scope=payload.clinical_data.purpose_scope,
            ttl_expires_at=payload.clinical_data.ttl_expires_at,
        )
    except DatabaseUnavailableError as exc:
        # Compensación Zero Trust: purgar token huérfano si falló PostgreSQL
        try:
            vault_service.purge_patient(tokenized.opaque_patient_token)
        except VaultServiceError:
            pass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return SegregatedCreateResponse(
        opaque_patient_token=tokenized.opaque_patient_token,
        vault_engine=tokenized.vault_engine,
        transit_key=tokenized.transit_key,
        key_version=tokenized.key_version,
        record=apply_minimization(record, decision),
        policy=_build_policy_metadata(
            actor=actor,
            purpose=purpose,
            action="create_record",
            decision=decision,
        ),
    )


@router.post(
    "/records",
    response_model=MinimizedRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear expediente clínico vinculado a un token opaco `pat_...` ya existente en Vault",
)
def create_clinical_record(
    payload: MedicalRecordCreateRequest,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> MinimizedRecordResponse:
    decision = _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="create_record",
        resource_purpose=payload.purpose_scope,
    )

    try:
        exists = vault_service.token_exists(payload.opaque_patient_token)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc

    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "El token opaco no existe o fue purgado en HashiCorp Vault; "
                "tokenice la PII previamente en `/vault/patients/tokenize`."
            ),
        )

    try:
        record = clinical_repo.create_record(
            opaque_patient_token=payload.opaque_patient_token,
            age_years=payload.age_years,
            zip_prefix=payload.zip_prefix,
            gender=payload.gender,
            diagnosis_cie10=payload.diagnosis_cie10,
            diagnosis_summary=payload.diagnosis_summary,
            department=payload.department,
            purpose_scope=payload.purpose_scope,
            ttl_expires_at=payload.ttl_expires_at,
        )
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return MinimizedRecordResponse(
        record=apply_minimization(record, decision),
        policy=_build_policy_metadata(
            actor=actor,
            purpose=purpose,
            action="create_record",
            decision=decision,
        ),
    )


@router.get(
    "/records",
    response_model=MinimizedRecordListResponse,
    summary="Consultar expedientes clínicos con validación ABAC/OPA (MA-03) y minimización por rol (MA-04)",
)
def list_clinical_records(
    department: str | None = Query(default=None, min_length=2, max_length=64),
    opaque_patient_token: str | None = Query(default=None),
    include_sanitized: bool = Query(default=False),
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> MinimizedRecordListResponse:
    decision = _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="read_record",
    )

    if opaque_patient_token is not None:
        if actor.role == "analista":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Acceso denegado: filtrado por token de paciente prohibido para analista "
                    "(prevención de singularización)."
                ),
            )
        if not OPAQUE_TOKEN_REGEX.match(opaque_patient_token.strip()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token opaco inválido: debe cumplir el formato `pat_<32 caracteres hex>`.",
            )
        opaque_patient_token = opaque_patient_token.strip()

    allow_sanitized_query = include_sanitized and actor.role == "auditor_arco"
    try:
        records = clinical_repo.list_records(
            department=department,
            opaque_patient_token=opaque_patient_token,
            include_sanitized=allow_sanitized_query,
        )
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    minimized_records: list[dict] = []
    decision_cache: dict[tuple[str, bool], OPADecision] = {}
    for rec in records:
        cache_key = (rec.purpose_scope, rec.is_sanitized)
        rec_decision = decision_cache.get(cache_key)
        if rec_decision is None:
            try:
                rec_decision = opa_client.evaluate(
                    role=actor.role,
                    purpose=purpose,
                    action="read_record",
                    resource_purpose=rec.purpose_scope,
                    is_sanitized=rec.is_sanitized,
                )
            except OPAServiceError as exc:
                raise _handle_opa_error(exc) from exc
            decision_cache[cache_key] = rec_decision
        if rec_decision.allow:
            minimized_records.append(apply_minimization(rec, rec_decision))

    return MinimizedRecordListResponse(
        count=len(minimized_records),
        records=minimized_records,
        policy=_build_policy_metadata(
            actor=actor,
            purpose=purpose,
            action="read_record",
            decision=decision,
        ),
    )


@router.get(
    "/records/{record_id}",
    response_model=MinimizedRecordResponse,
    summary="Consultar un expediente individual con prevención de singularización y minimización ABAC",
)
def get_clinical_record(
    record_id: UUID,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> MinimizedRecordResponse:
    # Verificación previa por acción: bloquea `analista` y propósitos inválidos antes de tocar BD
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="read_single_record",
    )

    try:
        record = clinical_repo.get_record_by_id(record_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Expediente clínico no encontrado.",
        )

    # Re-evaluación con atributos del recurso (finalidad original y estado de sanitización)
    decision = _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="read_single_record",
        resource_purpose=record.purpose_scope,
        is_sanitized=record.is_sanitized,
    )

    return MinimizedRecordResponse(
        record=apply_minimization(record, decision),
        policy=_build_policy_metadata(
            actor=actor,
            purpose=purpose,
            action="read_single_record",
            decision=decision,
        ),
    )


@router.patch(
    "/records/{record_id}",
    response_model=MinimizedRecordResponse,
    summary="Actualizar expediente clínico (solo médico con propósito `atencion_medica` vía OPA)",
)
def update_clinical_record(
    record_id: UUID,
    payload: MedicalRecordUpdateRequest,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> MinimizedRecordResponse:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="update_record",
    )

    try:
        existing = clinical_repo.get_record_by_id(record_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Expediente clínico no encontrado.",
        )
    if existing.is_sanitized:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No es posible modificar un registro sanitizado conforme a NIST SP 800-88.",
        )

    decision = _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="update_record",
        resource_purpose=existing.purpose_scope,
        is_sanitized=existing.is_sanitized,
    )

    try:
        updated = clinical_repo.update_record(
            record_id,
            diagnosis_cie10=payload.diagnosis_cie10,
            diagnosis_summary=payload.diagnosis_summary,
            department=payload.department,
            ttl_expires_at=payload.ttl_expires_at,
        )
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    assert updated is not None
    return MinimizedRecordResponse(
        record=apply_minimization(updated, decision),
        policy=_build_policy_metadata(
            actor=actor,
            purpose=purpose,
            action="update_record",
            decision=decision,
        ),
    )


@router.get(
    "/records/{record_id}/patient-identity",
    response_model=DetokenizePatientResponse,
    summary="Resolver PII directa en Vault desde un expediente clínico con doble control OPA + Vault",
)
def resolve_record_patient_identity(
    record_id: UUID,
    actor: AuthenticatedUser = Depends(get_current_user),
    purpose: str = Depends(get_declared_purpose),
    opa_client: OPAClient = Depends(get_opa_client),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
    clinical_repo: ClinicalRecordRepository = Depends(get_clinical_repository),
) -> DetokenizePatientResponse:
    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="detokenize_pii",
    )

    try:
        record = clinical_repo.get_record_by_id(record_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Expediente clínico no encontrado.",
        )

    _authorize_with_opa(
        opa_client,
        actor=actor,
        purpose=purpose,
        action="detokenize_pii",
        resource_purpose=record.purpose_scope,
        is_sanitized=record.is_sanitized,
    )

    try:
        return vault_service.detokenize_patient(record.opaque_patient_token)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc


@router.get(
    "/policy/status",
    response_model=OPAStatusResponse,
    summary="Verificar salud de Open Policy Agent y carga de la política `hospital.authz`",
)
def opa_policy_status(
    _actor: AuthenticatedUser = Depends(require_roles("admin_sec", "auditor_arco")),
    opa_client: OPAClient = Depends(get_opa_client),
) -> OPAStatusResponse:
    try:
        return opa_client.get_status()
    except OPAServiceError as exc:
        raise _handle_opa_error(exc) from exc


@router.post(
    "/policy/evaluate",
    response_model=OPADecision,
    summary="Simular y auditar una decisión ABAC/OPA (herramienta de verificación para auditoría)",
)
def evaluate_abac_policy(
    payload: PolicyEvaluateRequest,
    _actor: AuthenticatedUser = Depends(require_roles("admin_sec", "auditor_arco")),
    opa_client: OPAClient = Depends(get_opa_client),
) -> OPADecision:
    try:
        return opa_client.evaluate(
            role=payload.role,
            purpose=payload.purpose,
            action=payload.action,
            resource_purpose=payload.resource_purpose,
            is_sanitized=payload.is_sanitized,
            resource_owner_match=payload.resource_owner_match,
        )
    except OPAServiceError as exc:
        raise _handle_opa_error(exc) from exc
