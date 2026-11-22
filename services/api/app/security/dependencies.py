from collections.abc import Callable
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.models.auth import AuthenticatedUser, UserRole
from app.policy.opa_client import OPAClient
from app.repositories.auth_repo import PostgresUserRepository, UserRepository
from app.repositories.clinical_repo import (
    ClinicalRecordRepository,
    PostgresClinicalRecordRepository,
)
from app.security.jwt_auth import JWTService, TokenAuthenticationError, TokenRevocationStore
from app.security.passwords import Argon2idPasswordService
from app.security.webauthn_service import WebAuthnChallengeStore, WebAuthnService
from app.vault.service import VaultPIIVaultService

bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def _password_service_singleton() -> Argon2idPasswordService:
    return Argon2idPasswordService(
        pepper=settings.argon2_pepper,
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
        hash_len=settings.argon2_hash_len,
        salt_len=settings.argon2_salt_len,
    )


@lru_cache(maxsize=1)
def _jwt_service_singleton() -> JWTService:
    return JWTService(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expire_minutes=settings.jwt_expire_minutes,
        issuer=settings.app_name,
        revocation_store=TokenRevocationStore(),
    )


@lru_cache(maxsize=1)
def _webauthn_service_singleton() -> WebAuthnService:
    return WebAuthnService(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        expected_origins=settings.get_webauthn_origins(),
        challenge_store=WebAuthnChallengeStore(
            ttl_seconds=settings.webauthn_challenge_ttl_seconds
        ),
    )


@lru_cache(maxsize=1)
def _user_repository_singleton() -> PostgresUserRepository:
    return PostgresUserRepository(dsn=settings.database_url)


@lru_cache(maxsize=1)
def _clinical_repository_singleton() -> PostgresClinicalRecordRepository:
    return PostgresClinicalRecordRepository(dsn=settings.database_url)


@lru_cache(maxsize=1)
def _vault_service_singleton() -> VaultPIIVaultService:
    return VaultPIIVaultService(
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_dev_root_token_id,
        transit_mount=settings.vault_transit_mount,
        transit_key=settings.vault_transit_key,
        kv_mount=settings.vault_kv_mount,
        kv_prefix=settings.vault_kv_prefix,
        timeout_seconds=settings.vault_timeout_seconds,
    )


@lru_cache(maxsize=1)
def _opa_client_singleton() -> OPAClient:
    return OPAClient(
        opa_url=settings.opa_url,
        timeout_seconds=settings.opa_timeout_seconds,
    )


def get_password_service() -> Argon2idPasswordService:
    return _password_service_singleton()


def get_jwt_service() -> JWTService:
    return _jwt_service_singleton()


def get_webauthn_service() -> WebAuthnService:
    return _webauthn_service_singleton()


def get_user_repository() -> UserRepository:
    return _user_repository_singleton()


def get_clinical_repository() -> ClinicalRecordRepository:
    return _clinical_repository_singleton()


def get_vault_service() -> VaultPIIVaultService:
    return _vault_service_singleton()


def get_opa_client() -> OPAClient:
    return _opa_client_singleton()


def get_declared_purpose(
    x_purpose: str | None = Header(default=None, alias="X-Purpose"),
) -> str:
    """Extrae el propósito declarado (`X-Purpose`) para evaluación obligatoria en OPA (MA-03)."""
    return x_purpose.strip() if x_purpose else ""


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Se requiere token Bearer JWT válido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return jwt_service.verify_access_token(credentials.credentials)
    except TokenAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_roles(*allowed_roles: UserRole) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    allowed_set = set(allowed_roles)

    def _dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if current_user.role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Acceso denegado (Zero Trust): el rol '{current_user.role}' "
                    "no está autorizado para esta operación."
                ),
            )
        return current_user

    return _dependency
