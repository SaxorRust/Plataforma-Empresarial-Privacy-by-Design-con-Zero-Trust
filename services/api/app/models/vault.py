from datetime import datetime
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

CURP_REGEX = re.compile(r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$")
NSS_REGEX = re.compile(r"^\d{11}$")
OPAQUE_TOKEN_REGEX = re.compile(r"^pat_[0-9a-f]{32}$")


class PatientPIIRequest(BaseModel):
    """
    Identificadores directos de un paciente destinados EXCLUSIVAMENTE
    a la bóveda aislada HashiCorp Vault (MA-02). Nunca deben persistirse
    en PostgreSQL junto a los diagnósticos clínicos.
    """

    full_name: str = Field(
        ...,
        min_length=3,
        max_length=150,
        description="Nombre completo del paciente.",
    )
    curp: str = Field(
        ...,
        min_length=18,
        max_length=18,
        description="CURP oficial de 18 caracteres.",
    )
    nss: str = Field(
        ...,
        min_length=11,
        max_length=11,
        description="Número de Seguridad Social (IMSS, 11 dígitos).",
    )
    contact_email: str | None = Field(
        default=None,
        max_length=120,
        description="Correo electrónico opcional aislado en bóveda.",
    )
    contact_phone: str | None = Field(
        default=None,
        max_length=24,
        description="Teléfono opcional aislado en bóveda.",
    )

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = " ".join(value.strip().split())
        if len(normalized) < 3:
            raise ValueError("El nombre completo debe tener al menos 3 caracteres válidos.")
        return normalized

    @field_validator("curp")
    @classmethod
    def validate_curp(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not CURP_REGEX.match(normalized):
            raise ValueError("Formato de CURP inválido (esperado 18 caracteres oficiales).")
        return normalized

    @field_validator("nss")
    @classmethod
    def validate_nss(cls, value: str) -> str:
        normalized = value.strip()
        if not NSS_REGEX.match(normalized):
            raise ValueError("Formato de NSS inválido (esperados 11 dígitos numéricos).")
        return normalized


class TokenizePatientResponse(BaseModel):
    opaque_patient_token: str = Field(..., pattern=r"^pat_[0-9a-f]{32}$")
    vault_engine: Literal["transit+kv-v2"] = "transit+kv-v2"
    transit_key: str
    key_version: int
    created_at: datetime


class DetokenizePatientResponse(BaseModel):
    opaque_patient_token: str = Field(..., pattern=r"^pat_[0-9a-f]{32}$")
    full_name: str
    curp: str
    nss: str
    contact_email: str | None = None
    contact_phone: str | None = None
    created_at: datetime


class PurgePatientResponse(BaseModel):
    opaque_patient_token: str = Field(..., pattern=r"^pat_[0-9a-f]{32}$")
    status: Literal["purged"] = "purged"
    method: Literal["VAULT_KV2_METADATA_DESTROY"] = "VAULT_KV2_METADATA_DESTROY"
    purged_at: datetime


class VaultStatusResponse(BaseModel):
    reachable: bool
    initialized: bool
    sealed: bool
    transit_mount: str
    transit_key: str
    latest_key_version: int
    kv_mount: str


class VaultRotateKeyResponse(BaseModel):
    transit_key: str
    latest_key_version: int
    rotated_at: datetime
