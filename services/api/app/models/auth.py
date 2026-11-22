from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

UserRole = Literal["medico", "enfermeria", "analista", "auditor_arco", "admin_sec", "paciente"]


@dataclass(frozen=True)
class UserRecord:
    id: UUID
    username: str
    role: UserRole
    password_hash: str
    webauthn_enabled: bool
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
class WebAuthnCredentialRecord:
    id: UUID
    user_id: UUID
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]
    created_at: datetime


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: UUID
    username: str
    role: UserRole
    amr: list[str]
    jti: str
    exp: datetime


class UserRegisterRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Nombre de usuario único (alfanumérico, '.', '_' o '-').",
    )
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="Contraseña robusta (mín. 12 caracteres, mayúscula, minúscula, dígito y símbolo).",
    )
    role: UserRole = Field(
        default="medico",
        description="Rol institucional asignado conforme al esquema ABAC.",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        has_upper = any(ch.isupper() for ch in value)
        has_lower = any(ch.islower() for ch in value)
        has_digit = any(ch.isdigit() for ch in value)
        has_symbol = any(not ch.isalnum() for ch in value)
        if not (has_upper and has_lower and has_digit and has_symbol):
            raise ValueError(
                "La contraseña debe incluir al menos una mayúscula, una minúscula, "
                "un dígito y un carácter especial."
            )
        return value


class UserPublicResponse(BaseModel):
    id: UUID
    username: str
    role: UserRole
    webauthn_enabled: bool
    is_active: bool
    created_at: datetime


class PasswordLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    amr: list[str]
    user: UserPublicResponse


class CurrentUserResponse(BaseModel):
    user_id: UUID
    username: str
    role: UserRole
    amr: list[str]
    jti: str
    expires_at: datetime
    webauthn_enabled: bool


class LogoutResponse(BaseModel):
    status: Literal["logged_out"] = "logged_out"
    jti: str


class WebAuthnOptionsResponse(BaseModel):
    options: dict[str, Any]
    rp_id: str
    expires_in: int


class WebAuthnRegisterCompleteRequest(BaseModel):
    credential: dict[str, Any] = Field(
        ...,
        description="Objeto PublicKeyCredential serializado desde navigator.credentials.create().",
    )


class WebAuthnCredentialResponse(BaseModel):
    id: UUID
    credential_id: str
    sign_count: int
    transports: list[str]
    created_at: datetime


class WebAuthnRegisterCompleteResponse(BaseModel):
    credential_id: str
    sign_count: int
    transports: list[str]
    webauthn_enabled: bool = True


class WebAuthnLoginBeginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)


class WebAuthnLoginCompleteRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    credential: dict[str, Any] = Field(
        ...,
        description="Objeto PublicKeyCredential serializado desde navigator.credentials.get().",
    )
