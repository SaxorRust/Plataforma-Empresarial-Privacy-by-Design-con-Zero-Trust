from fastapi import APIRouter, Depends, HTTPException, status

from app.models.auth import AuthenticatedUser
from app.models.vault import (
    DetokenizePatientResponse,
    PatientPIIRequest,
    PurgePatientResponse,
    TokenizePatientResponse,
    VaultRotateKeyResponse,
    VaultStatusResponse,
)
from app.security.dependencies import get_vault_service, require_roles
from app.vault.service import (
    InvalidOpaqueTokenError,
    VaultPIIVaultService,
    VaultServiceError,
    VaultTokenNotFoundError,
    VaultUnavailableError,
)

router = APIRouter(prefix="/vault", tags=["boveda-pii-ma02"])


def _handle_vault_error(exc: VaultServiceError) -> HTTPException:
    if isinstance(exc, InvalidOpaqueTokenError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if isinstance(exc, VaultTokenNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, VaultUnavailableError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


@router.post(
    "/patients/tokenize",
    response_model=TokenizePatientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Aislar identificadores directos (Nombre, CURP, NSS) en Vault y emitir token `pat_...`",
)
def tokenize_patient_pii(
    payload: PatientPIIRequest,
    _actor: AuthenticatedUser = Depends(require_roles("medico", "enfermeria", "admin_sec")),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
) -> TokenizePatientResponse:
    try:
        return vault_service.tokenize_patient(payload)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc


@router.get(
    "/patients/{opaque_patient_token}",
    response_model=DetokenizePatientResponse,
    summary="Detokenizar identificadores directos desde HashiCorp Vault (solo roles autorizados)",
)
def detokenize_patient_pii(
    opaque_patient_token: str,
    _actor: AuthenticatedUser = Depends(require_roles("medico", "admin_sec")),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
) -> DetokenizePatientResponse:
    try:
        return vault_service.detokenize_patient(opaque_patient_token)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc


@router.delete(
    "/patients/{opaque_patient_token}",
    response_model=PurgePatientResponse,
    summary="Purgar permanentemente metadatos y versiones KV v2 de un token (soporte NIST SP 800-88)",
)
def purge_patient_pii(
    opaque_patient_token: str,
    _actor: AuthenticatedUser = Depends(require_roles("auditor_arco", "admin_sec")),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
) -> PurgePatientResponse:
    try:
        return vault_service.purge_patient(opaque_patient_token)
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc


@router.get(
    "/status",
    response_model=VaultStatusResponse,
    summary="Verificar estado de salud de HashiCorp Vault, Transit y KV v2",
)
def vault_status(
    _actor: AuthenticatedUser = Depends(require_roles("admin_sec", "auditor_arco")),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
) -> VaultStatusResponse:
    try:
        return vault_service.get_status()
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc


@router.post(
    "/keys/rotate",
    response_model=VaultRotateKeyResponse,
    summary="Rotar versión activa de la llave Transit AEAD en HashiCorp Vault",
)
def rotate_vault_transit_key(
    _actor: AuthenticatedUser = Depends(require_roles("admin_sec")),
    vault_service: VaultPIIVaultService = Depends(get_vault_service),
) -> VaultRotateKeyResponse:
    try:
        return vault_service.rotate_transit_key()
    except VaultServiceError as exc:
        raise _handle_vault_error(exc) from exc
